package coordinator_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/Use-Tessera/tessera-coordinator/internal/audit"
	"github.com/Use-Tessera/tessera-coordinator/internal/coordinator"
	"github.com/Use-Tessera/tessera-coordinator/internal/testsigner"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func TestSignsAnAuthorizationEntry(t *testing.T) {
	tr := load(t)
	co, path := newCoordinator(t, tr, testsigner.AuthGroup(t, tr))
	res, err := co.SignAuth(context.Background(), tr.Auth.Entry, tr.Auth.LatestLedger)
	if err != nil {
		t.Fatal(err)
	}
	if res.AuthEntry != tr.Auth.Aggregate.AuthEntry || res.Hash != tr.Auth.Aggregate.Hash || len(res.Signers) != 2 {
		t.Fatalf("%+v", res)
	}

	// Check the result the way the Soroban host does, without the coordinator.
	var e xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(res.AuthEntry, &e); err != nil {
		t.Fatal(err)
	}
	creds := e.Credentials.MustAddress()
	pre, _ := xdr.HashIdPreimage{
		Type: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization,
		SorobanAuthorization: &xdr.HashIdPreimageSorobanAuthorization{
			NetworkId: network.ID(tr.Network), Nonce: creds.Nonce,
			SignatureExpirationLedger: creds.SignatureExpirationLedger, Invocation: e.RootInvocation,
		},
	}.MarshalBinary()
	payload := sha256.Sum256(pre)
	entry := (*(*creds.Signature.MustVec())[0].MustMap())
	key, sig := entry[0].Val.MustBytes(), entry[1].Val.MustBytes()
	if hex.EncodeToString(key) != tr.GroupPublicKey || !ed25519.Verify(ed25519.PublicKey(key), payload[:], sig) {
		t.Fatal("signature does not verify against the group key")
	}

	recs, err := audit.Read(path)
	if err != nil || len(recs) != 1 || recs[0].Kind != "authorization" || recs[0].TxHash != res.Hash {
		t.Fatalf("audit: %+v %v", recs, err)
	}
}

func TestAuthorizationRefusalsAreReported(t *testing.T) {
	tr := load(t)
	co, _ := newCoordinator(t, tr, testsigner.AuthGroup(t, tr, behaviour{Refuse: []string{"call 0: transfer of 5 native, more than per_transaction 1"}}))
	var refused *coordinator.RefusedError
	if _, err := co.SignAuth(context.Background(), tr.Auth.Entry, tr.Auth.LatestLedger); !errors.As(err, &refused) || len(refused.Refusals) != 1 {
		t.Fatalf("want a refusal, got %v", err)
	}
}

func TestBadAuthorizationAggregatesAreCaught(t *testing.T) {
	tr := load(t)
	for name, b := range map[string]behaviour{
		"forged signature": {BadSig: true},
		"altered entry":    {Tamper: true},
	} {
		co, _ := newCoordinator(t, tr, testsigner.AuthGroup(t, tr, b))
		if _, err := co.SignAuth(context.Background(), tr.Auth.Entry, tr.Auth.LatestLedger); !errors.Is(err, coordinator.ErrInvalidAggregate) {
			t.Errorf("%s: want ErrInvalidAggregate, got %v", name, err)
		}
	}
}

func TestOnlyTheGroupsAddressEntriesAreSigned(t *testing.T) {
	tr := load(t)
	co, _ := newCoordinator(t, tr, testsigner.AuthGroup(t, tr))
	var e xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(tr.Auth.Entry, &e); err != nil {
		t.Fatal(err)
	}
	other := e
	creds := *e.Credentials.Address
	creds.Address.AccountId = xdr.MustAddressPtr("GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR")
	other.Credentials = xdr.SorobanCredentials{Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddress, Address: &creds}
	source := e
	source.Credentials = xdr.SorobanCredentials{Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount}

	for name, entry := range map[string]any{"other account": other, "source account": source, "not xdr": "AAAA"} {
		b64, ok := entry.(string)
		if !ok {
			b64, _ = xdr.MarshalBase64(entry)
		}
		if _, err := co.SignAuth(context.Background(), b64, tr.Auth.LatestLedger); !errors.Is(err, coordinator.ErrBadAuthEntry) {
			t.Errorf("%s: want ErrBadAuthEntry, got %v", name, err)
		}
	}
}
