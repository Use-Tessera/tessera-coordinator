// Package api is the coordinator's HTTP interface for applications.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Use-Tessera/tessera-coordinator/internal/coordinator"
	"github.com/Use-Tessera/tessera-coordinator/internal/submit"
)

// Server serves one coordinator.
type Server struct {
	Coordinator *coordinator.Coordinator
	Submitter   *submit.Client // nil disables ?submit
	Token       string         // required bearer token; empty disables auth
	Log         *slog.Logger
	Metrics     Metrics
	Idempotency Idempotency // zero value: keys kept 24 h, at most 10,000
}

// Handler returns the routes.
//
//	GET  /healthz
//	GET  /metrics
//	GET  /v1/group
//	POST /v1/sign       {"envelope": "<base64 XDR>", "submit": false}
//	POST /v1/authorize  {"auth_entry": "<base64 XDR>", "latest_ledger": 0}
//
// Both POST routes honour an Idempotency-Key header.
func (s *Server) Handler() http.Handler {
	if s.Idempotency.TTL == 0 {
		s.Idempotency.TTL = 24 * time.Hour
	}
	if s.Idempotency.Max == 0 {
		s.Idempotency.Max = 10_000
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /v1/group", s.auth(s.group))
	mux.HandleFunc("POST /v1/sign", s.auth(s.Idempotency.wrap(s.sign)))
	mux.HandleFunc("POST /v1/authorize", s.auth(s.Idempotency.wrap(s.authorize)))
	mux.Handle("GET /metrics", &s.Metrics)
	routes := map[string]bool{"/healthz": true, "/metrics": true, "/v1/group": true, "/v1/sign": true, "/v1/authorize": true}
	return s.observe(mux, routes)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Token != "" {
			given, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(given), []byte(s.Token)) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or wrong bearer token"})
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) group(w http.ResponseWriter, _ *http.Request) {
	type member struct {
		URL          string `json:"url"`
		Identifier   string `json:"identifier"`
		PolicySHA256 string `json:"policy_sha256"`
	}
	co := s.Coordinator
	members := make([]member, 0, len(co.Members))
	for _, m := range co.Members {
		members = append(members, member{m.Client.URL, m.Info.Identifier, m.Info.PolicySHA256})
	}
	writeJSON(w, http.StatusOK, map[string]any{"account": co.Account, "threshold": co.Threshold, "network": co.Network, "signers": members})
}

func (s *Server) sign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Envelope string `json:"envelope"`
		Submit   bool   `json:"submit"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.Envelope == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"envelope\": \"<base64 XDR>\"}"})
		return
	}
	if req.Submit && s.Submitter == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "no rpc configured; submission is disabled"})
		return
	}
	res, err := s.Coordinator.Sign(r.Context(), req.Envelope)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := map[string]any{"session": res.Session, "hash": res.Hash, "envelope": res.Envelope, "signers": res.Signers}
	if req.Submit {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		outcome, err := s.Submitter.Submit(ctx, res.Envelope, res.Hash)
		if err != nil {
			out["submission_error"] = err.Error()
			writeJSON(w, http.StatusBadGateway, out)
			return
		}
		out["submission"] = outcome
	}
	writeJSON(w, http.StatusOK, out)
}

// authorize signs a Soroban authorization entry. With an RPC configured the
// coordinator reads the latest ledger itself and ignores latest_ledger, so a
// caller cannot understate it to stretch the signature's lifetime.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AuthEntry    string `json:"auth_entry"`
		LatestLedger uint32 `json:"latest_ledger"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.AuthEntry == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"auth_entry\": \"<base64 XDR>\"}"})
		return
	}
	latest := req.LatestLedger
	if s.Submitter != nil {
		seq, err := s.Submitter.LatestLedger(r.Context())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "reading the latest ledger: " + err.Error()})
			return
		}
		latest = seq
	}
	if latest == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "latest_ledger is required when no rpc is configured"})
		return
	}
	res, err := s.Coordinator.SignAuth(r.Context(), req.AuthEntry, latest)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": res.Session, "hash": res.Hash, "auth_entry": res.AuthEntry, "signers": res.Signers, "latest_ledger": latest})
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	var refused *coordinator.RefusedError
	switch {
	case errors.As(err, &refused):
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "policy refused the request", "refusals": refused.Refusals})
	case errors.Is(err, coordinator.ErrBadEnvelope), errors.Is(err, coordinator.ErrBadAuthEntry):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	case errors.Is(err, coordinator.ErrNotEnoughSigners):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
	default:
		s.Log.Error("signing failed", "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
