package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Use-Tessera/tessera-coordinator/internal/api"
	"github.com/Use-Tessera/tessera-coordinator/internal/coordinator"
	"github.com/Use-Tessera/tessera-coordinator/internal/submit"
	"github.com/Use-Tessera/tessera-coordinator/internal/testsigner"
)

const token = "app-token"

func server(t *testing.T, bs ...testsigner.Behaviour) (*httptest.Server, testsigner.Transcript) {
	t.Helper()
	tr := testsigner.Load(t, "../../testdata/transcript.json")
	co, err := coordinator.New(context.Background(), tr.Network, testsigner.Group(t, tr, bs...), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &api.Server{Coordinator: co, Token: token, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, tr
}

func call(t *testing.T, srv *httptest.Server, method, path, auth string, body any) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, srv.URL+path, r)
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestSignReturnsTheSignedEnvelope(t *testing.T) {
	srv, tr := server(t)
	code, out := call(t, srv, "POST", "/v1/sign", token, map[string]any{"envelope": tr.Envelope})
	if code != http.StatusOK || out["envelope"] != tr.Aggregate.Envelope || out["hash"] != tr.Aggregate.Hash {
		t.Fatalf("status %d: %v", code, out)
	}
	if signers := out["signers"].([]any); len(signers) != 2 {
		t.Fatalf("want 2 signers, got %v", signers)
	}
}

func TestRefusalsAre403WithReasons(t *testing.T) {
	srv, tr := server(t, testsigner.Behaviour{Refuse: []string{"spends 500 native, more than per_transaction 100"}})
	code, out := call(t, srv, "POST", "/v1/sign", token, map[string]any{"envelope": tr.Envelope})
	refusals, _ := out["refusals"].(map[string]any)
	if code != http.StatusForbidden || len(refusals) != 1 {
		t.Fatalf("status %d: %v", code, out)
	}
}

func TestRequestsAreValidated(t *testing.T) {
	srv, tr := server(t)
	for name, c := range map[string]struct {
		auth string
		body any
		want int
	}{
		"no token":       {"", map[string]any{"envelope": tr.Envelope}, http.StatusUnauthorized},
		"wrong token":    {"nope", map[string]any{"envelope": tr.Envelope}, http.StatusUnauthorized},
		"empty body":     {token, map[string]any{}, http.StatusBadRequest},
		"not xdr":        {token, map[string]any{"envelope": "AAAA"}, http.StatusBadRequest},
		"submit, no rpc": {token, map[string]any{"envelope": tr.Envelope, "submit": true}, http.StatusNotImplemented},
	} {
		if code, out := call(t, srv, "POST", "/v1/sign", c.auth, c.body); code != c.want {
			t.Errorf("%s: status %d, want %d (%v)", name, code, c.want, out)
		}
	}
}

func TestGroupDescribesTheSigners(t *testing.T) {
	srv, tr := server(t)
	code, out := call(t, srv, "GET", "/v1/group", token, nil)
	if code != http.StatusOK || out["account"] != tr.Account || out["threshold"].(float64) != 2 {
		t.Fatalf("status %d: %v", code, out)
	}
	if signers := out["signers"].([]any); len(signers) != 3 {
		t.Fatalf("want 3 signers, got %d", len(signers))
	}
	if code, _ := call(t, srv, "GET", "/healthz", "", nil); code != http.StatusOK {
		t.Fatal("health check must not need a token")
	}
}

func TestTooFewSignersIs503(t *testing.T) {
	srv, tr := server(t, testsigner.Behaviour{Offline: true})
	if code, out := call(t, srv, "POST", "/v1/sign", token, map[string]any{"envelope": tr.Envelope}); code != http.StatusServiceUnavailable {
		t.Fatalf("status %d: %v", code, out)
	}
}

func authServer(t *testing.T, rpcLedger uint32) (*httptest.Server, testsigner.Transcript) {
	t.Helper()
	tr := testsigner.Load(t, "../../testdata/transcript.json")
	co, err := coordinator.New(context.Background(), tr.Network, testsigner.AuthGroup(t, tr), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &api.Server{Coordinator: co, Token: token, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if rpcLedger > 0 {
		rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"sequence": rpcLedger}})
		}))
		t.Cleanup(rpc.Close)
		s.Submitter = submit.New(rpc.URL)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, tr
}

func TestAuthorizeSignsTheEntry(t *testing.T) {
	srv, tr := authServer(t, 0)
	code, out := call(t, srv, "POST", "/v1/authorize", token, map[string]any{"auth_entry": tr.Auth.Entry, "latest_ledger": tr.Auth.LatestLedger})
	if code != http.StatusOK || out["auth_entry"] != tr.Auth.Aggregate.AuthEntry || out["hash"] != tr.Auth.Aggregate.Hash {
		t.Fatalf("status %d: %v", code, out)
	}
}

func TestAuthorizeTrustsRPCOverTheCaller(t *testing.T) {
	// The caller understates the ledger; the coordinator asks RPC instead.
	srv, tr := authServer(t, 1_000)
	code, out := call(t, srv, "POST", "/v1/authorize", token, map[string]any{"auth_entry": tr.Auth.Entry, "latest_ledger": 5})
	if code != http.StatusOK || out["latest_ledger"].(float64) != 1_000 {
		t.Fatalf("status %d: %v", code, out)
	}
}

func TestAuthorizeValidatesRequests(t *testing.T) {
	srv, tr := authServer(t, 0)
	for name, c := range map[string]struct {
		body any
		want int
	}{
		"no entry":         {map[string]any{"latest_ledger": 1000}, http.StatusBadRequest},
		"no latest ledger": {map[string]any{"auth_entry": tr.Auth.Entry}, http.StatusBadRequest},
		"not xdr":          {map[string]any{"auth_entry": "AAAA", "latest_ledger": 1000}, http.StatusBadRequest},
	} {
		if code, out := call(t, srv, "POST", "/v1/authorize", token, c.body); code != c.want {
			t.Errorf("%s: status %d, want %d (%v)", name, code, c.want, out)
		}
	}
}
