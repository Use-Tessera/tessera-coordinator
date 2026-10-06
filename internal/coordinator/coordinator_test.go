package coordinator_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Use-Tessera/tessera-coordinator/internal/audit"
	"github.com/Use-Tessera/tessera-coordinator/internal/coordinator"
	"github.com/Use-Tessera/tessera-coordinator/internal/signer"
	"github.com/Use-Tessera/tessera-coordinator/internal/testsigner"
)

type transcript = testsigner.Transcript
type behaviour = testsigner.Behaviour

func load(t *testing.T) transcript { return testsigner.Load(t, "../../testdata/transcript.json") }

func group(t *testing.T, tr transcript, bs ...behaviour) []*signer.Client {
	return testsigner.Group(t, tr, bs...)
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
	co, path := newCoordinator(t, tr, group(t, tr, behaviour{BadSig: true}))
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
	co, path := newCoordinator(t, tr, group(t, tr, behaviour{}, behaviour{}, behaviour{Refuse: []string{"spends 500 native, more than per_transaction 100"}}))
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
	co, _ := newCoordinator(t, tr, group(t, tr, behaviour{Offline: true}))
	if _, err := co.Sign(context.Background(), tr.Envelope); !errors.Is(err, coordinator.ErrNotEnoughSigners) {
		t.Fatalf("want ErrNotEnoughSigners, got %v", err)
	}
}

func TestSignersMustAgreeOnTheGroup(t *testing.T) {
	tr := load(t)
	clients := group(t, tr, behaviour{}, behaviour{Account: "GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR"})
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
