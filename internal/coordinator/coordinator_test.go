package coordinator_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Use-Tessera/tessera-coordinator/internal/audit"
	"github.com/Use-Tessera/tessera-coordinator/internal/coordinator"
	"github.com/Use-Tessera/tessera-coordinator/internal/signer"
)

// transcript is a real 2-of-3 run recorded by tessera-signer's test suite.
type transcript struct {
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

func load(t *testing.T) transcript {
	t.Helper()
	b, err := os.ReadFile("../../testdata/transcript.json")
	if err != nil {
		t.Fatal(err)
	}
	var tr transcript
	if err := json.Unmarshal(b, &tr); err != nil {
		t.Fatal(err)
	}
	return tr
}

// behaviour tweaks one fake signer.
type behaviour struct {
	offline bool
	refuse  []string
	badSig  bool
	account string
}

// fakeSigner replays signer i of the transcript.
func fakeSigner(t *testing.T, tr transcript, i int, b behaviour) *signer.Client {
	t.Helper()
	s := tr.Signers[i]
	reply := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", func(w http.ResponseWriter, r *http.Request) {
		account := tr.Account
		if b.account != "" {
			account = b.account
		}
		reply(w, 200, signer.Info{Protocol: signer.Protocol, Identifier: s.Identifier, Account: account, Threshold: tr.Threshold, Signers: len(tr.Signers), Network: tr.Network, PolicySHA256: s.PolicySHA256})
	})
	mux.HandleFunc("POST /v1/round1", func(w http.ResponseWriter, r *http.Request) {
		if b.offline || s.Commitments == "" {
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
		if len(b.refuse) > 0 {
			reply(w, 403, map[string]any{"error": "policy refused the transaction", "violations": b.refuse})
			return
		}
		if req.Envelope != tr.Envelope || len(req.Commitments) != 2 {
			reply(w, 400, map[string]string{"error": "unexpected request"})
			return
		}
		reply(w, 200, map[string]string{"identifier": s.Identifier, "share": s.Share})
	})
	mux.HandleFunc("POST /v1/aggregate", func(w http.ResponseWriter, r *http.Request) {
		agg := tr.Aggregate
		if b.badSig {
			agg.Signature = strings.Repeat("ab", 64)
		}
		reply(w, 200, agg)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return signer.New(srv.URL, "")
}

func group(t *testing.T, tr transcript, bs ...behaviour) []*signer.Client {
	t.Helper()
	var out []*signer.Client
	for i := range tr.Signers {
		var b behaviour
		if i < len(bs) {
			b = bs[i]
		}
		out = append(out, fakeSigner(t, tr, i, b))
	}
	return out
}

func newCoordinator(t *testing.T, tr transcript, clients []*signer.Client) (*coordinator.Coordinator, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	co, err := coordinator.New(context.Background(), tr.Network, clients, log)
	if err != nil {
		t.Fatal(err)
	}
	return co, path
}

func TestSignsWithTheSignersThatAnswer(t *testing.T) {
	tr := load(t)
	co, path := newCoordinator(t, tr, group(t, tr))
	if co.Account != tr.Account || co.Threshold != 2 {
		t.Fatalf("group not learned: %s %d", co.Account, co.Threshold)
	}
	res, err := co.Sign(context.Background(), tr.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if res.Hash != tr.Aggregate.Hash || res.Envelope != tr.Aggregate.Envelope {
		t.Fatal("result does not match the recorded aggregate")
	}
	if len(res.Signers) != 2 || res.Signers[0] != tr.Signers[0].Identifier || res.Signers[1] != tr.Signers[2].Identifier {
		t.Fatalf("expected signers 1 and 3 (2 is offline), got %v", res.Signers)
	}
	recs, err := audit.Read(path)
	if err != nil || len(recs) != 1 || recs[0].Outcome != "signed" {
		t.Fatalf("audit: %v %+v", err, recs)
	}
}

func TestAForgedAggregateIsCaught(t *testing.T) {
	tr := load(t)
	co, path := newCoordinator(t, tr, group(t, tr, behaviour{badSig: true}))
	if _, err := co.Sign(context.Background(), tr.Envelope); !errors.Is(err, coordinator.ErrInvalidAggregate) {
		t.Fatalf("want ErrInvalidAggregate, got %v", err)
	}
	recs, _ := audit.Read(path)
	if len(recs) != 1 || recs[0].Outcome != "failed" {
		t.Fatalf("failure not audited: %+v", recs)
	}
}

func TestRefusalsCarryEachSignersReasons(t *testing.T) {
	tr := load(t)
	co, path := newCoordinator(t, tr, group(t, tr, behaviour{}, behaviour{}, behaviour{refuse: []string{"spends 500 native, more than per_transaction 100"}}))
	_, err := co.Sign(context.Background(), tr.Envelope)
	var refused *coordinator.RefusedError
	if !errors.As(err, &refused) || len(refused.Refusals[tr.Signers[2].Identifier]) != 1 {
		t.Fatalf("want a RefusedError naming signer 3, got %v", err)
	}
	recs, _ := audit.Read(path)
	if recs[0].Outcome != "refused" || len(recs[0].Refusals) != 1 {
		t.Fatalf("refusal not audited: %+v", recs)
	}
}

func TestTooFewSignersOnline(t *testing.T) {
	tr := load(t)
	co, _ := newCoordinator(t, tr, group(t, tr, behaviour{offline: true}))
	if _, err := co.Sign(context.Background(), tr.Envelope); !errors.Is(err, coordinator.ErrNotEnoughSigners) {
		t.Fatalf("want ErrNotEnoughSigners, got %v", err)
	}
}

func TestSignersMustAgreeOnTheGroup(t *testing.T) {
	tr := load(t)
	clients := group(t, tr, behaviour{}, behaviour{account: "GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR"})
	if _, err := coordinator.New(context.Background(), tr.Network, clients, nil); !errors.Is(err, coordinator.ErrInconsistentGroup) {
		t.Fatalf("want ErrInconsistentGroup, got %v", err)
	}
	if _, err := coordinator.New(context.Background(), "Public Global Stellar Network ; September 2015", group(t, tr), nil); !errors.Is(err, coordinator.ErrInconsistentGroup) {
		t.Fatalf("network mismatch: want ErrInconsistentGroup, got %v", err)
	}
}

func TestRejectsGarbageEnvelopes(t *testing.T) {
	tr := load(t)
	co, _ := newCoordinator(t, tr, group(t, tr))
	if _, err := co.Sign(context.Background(), "not-xdr"); !errors.Is(err, coordinator.ErrBadEnvelope) {
		t.Fatalf("want ErrBadEnvelope, got %v", err)
	}
}
