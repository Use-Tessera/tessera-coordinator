// Package testsigner provides fake Tessera signers for tests. They replay a
// real 2-of-3 FROST run recorded by tessera-signer's own test suite, so code
// under test handles genuine commitments, shares and signatures.
package testsigner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Use-Tessera/tessera-coordinator/internal/signer"
)

// Transcript is testdata/transcript.json.
type Transcript struct {
	Network        string `json:"network"`
	Account        string `json:"account"`
	GroupPublicKey string `json:"group_public_key"`
	Threshold      int    `json:"threshold"`
	Envelope       string `json:"envelope"`
	Signers        []struct {
		Identifier   string `json:"identifier"`
		PolicySHA256 string `json:"policy_sha256"`
		Commitments  string `json:"commitments"`
		Share        string `json:"share"`
	} `json:"signers"`
	Aggregate signer.Aggregate `json:"aggregate"`
}

// Load reads a transcript file.
func Load(t testing.TB, path string) Transcript {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var tr Transcript
	if err := json.Unmarshal(b, &tr); err != nil {
		t.Fatal(err)
	}
	return tr
}

// Behaviour tweaks one fake signer.
type Behaviour struct {
	Offline bool     // round 1 fails
	Refuse  []string // round 2 refuses with these violations
	BadSig  bool     // aggregate returns a forged signature
	Account string   // /v1/info reports this account instead
}

// Signer starts a fake replaying signer i of the transcript.
func Signer(t testing.TB, tr Transcript, i int, b Behaviour) *signer.Client {
	t.Helper()
	s := tr.Signers[i]
	reply := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", func(w http.ResponseWriter, _ *http.Request) {
		account := tr.Account
		if b.Account != "" {
			account = b.Account
		}
		reply(w, 200, signer.Info{Protocol: signer.Protocol, Identifier: s.Identifier, Account: account, Threshold: tr.Threshold, Signers: len(tr.Signers), Network: tr.Network, PolicySHA256: s.PolicySHA256})
	})
	mux.HandleFunc("POST /v1/round1", func(w http.ResponseWriter, _ *http.Request) {
		if b.Offline || s.Commitments == "" {
			reply(w, 503, map[string]string{"error": "offline"})
			return
		}
		reply(w, 200, map[string]string{"identifier": s.Identifier, "commitments": s.Commitments})
	})
	mux.HandleFunc("POST /v1/round2", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Envelope    string            `json:"envelope"`
			Commitments map[string]string `json:"commitments"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if len(b.Refuse) > 0 {
			reply(w, 403, map[string]any{"error": "policy refused the transaction", "violations": b.Refuse})
			return
		}
		if req.Envelope != tr.Envelope || len(req.Commitments) != 2 {
			reply(w, 400, map[string]string{"error": "unexpected request"})
			return
		}
		reply(w, 200, map[string]string{"identifier": s.Identifier, "share": s.Share})
	})
	mux.HandleFunc("POST /v1/aggregate", func(w http.ResponseWriter, _ *http.Request) {
		agg := tr.Aggregate
		if b.BadSig {
			agg.Signature = strings.Repeat("ab", 64)
		}
		reply(w, 200, agg)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return signer.New(srv.URL, "")
}

// Group starts one fake per transcript signer; behaviours apply by position.
// The transcript's second signer has no commitments, so it is offline by
// default and the first and third sign.
func Group(t testing.TB, tr Transcript, bs ...Behaviour) []*signer.Client {
	t.Helper()
	var out []*signer.Client
	for i := range tr.Signers {
		var b Behaviour
		if i < len(bs) {
			b = bs[i]
		}
		out = append(out, Signer(t, tr, i, b))
	}
	return out
}
