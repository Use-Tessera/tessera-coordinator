package coordinator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Use-Tessera/tessera-coordinator/internal/signer"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// ErrBadAuthEntry means the authorization entry cannot be signed by the group.
var ErrBadAuthEntry = errors.New("invalid authorization entry")

// AuthResult of a successful authorization-entry signing session.
type AuthResult struct {
	Session   string   `json:"session"`
	Hash      string   `json:"hash"`
	AuthEntry string   `json:"auth_entry"`
	Signers   []string `json:"signers"`
}

// SignAuth signs a SorobanAuthorizationEntry with address credentials, as
// returned by simulateTransaction, so the group can authorize a contract call
// inside a transaction someone else submits. latestLedger is the network's
// current ledger; signers use it to bound the signature's lifetime.
func (co *Coordinator) SignAuth(ctx context.Context, entry string, latestLedger uint32) (*AuthResult, error) {
	var e xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(entry, &e); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadAuthEntry, err)
	}
	hash, err := co.authPayload(e)
	if err != nil {
		return nil, err
	}
	session := newSession()
	ctx, cancel := context.WithTimeout(ctx, co.Timeout)
	defer cancel()

	signed, ids, err := co.run(ctx, session, job{
		round2: func(ctx context.Context, c *signer.Client, commitments map[string]string) (string, error) {
			return c.Round2Auth(ctx, session, entry, latestLedger, commitments)
		},
		aggregate: func(ctx context.Context, c *signer.Client, commitments, shares map[string]string) (string, error) {
			agg, err := c.AggregateAuth(ctx, entry, commitments, shares)
			if err != nil {
				return "", err
			}
			return agg.AuthEntry, co.checkAuth(agg, e, hash)
		},
	})
	var res *AuthResult
	if err == nil {
		res = &AuthResult{Session: session, Hash: hex.EncodeToString(hash[:]), AuthEntry: signed, Signers: ids}
	}
	co.record(session, "authorization", hash, ids, err)
	return res, err
}

// authPayload is the hash Soroban checks the account's signature against.
func (co *Coordinator) authPayload(e xdr.SorobanAuthorizationEntry) ([32]byte, error) {
	creds, ok := e.Credentials.GetAddress()
	if !ok {
		return [32]byte{}, fmt.Errorf("%w: only address credentials carry a signature", ErrBadAuthEntry)
	}
	if creds.Address.Type != xdr.ScAddressTypeScAddressTypeAccount || creds.Address.AccountId.Address() != co.Account {
		return [32]byte{}, fmt.Errorf("%w: entry does not authorize the group account %s", ErrBadAuthEntry, co.Account)
	}
	preimage := xdr.HashIdPreimage{
		Type: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization,
		SorobanAuthorization: &xdr.HashIdPreimageSorobanAuthorization{
			NetworkId:                 network.ID(co.Network),
			Nonce:                     creds.Nonce,
			SignatureExpirationLedger: creds.SignatureExpirationLedger,
			Invocation:                e.RootInvocation,
		},
	}
	b, err := preimage.MarshalBinary()
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %w", ErrBadAuthEntry, err)
	}
	return sha256.Sum256(b), nil
}

// checkAuth verifies the aggregate independently of the signers: the entry
// must be the one requested, with only its signature filled in, and that
// signature must be the group's over the payload.
func (co *Coordinator) checkAuth(agg *signer.AuthAggregate, requested xdr.SorobanAuthorizationEntry, want [32]byte) error {
	sig, err := hex.DecodeString(agg.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || agg.Hash != hex.EncodeToString(want[:]) {
		return ErrInvalidAggregate
	}
	if !ed25519.Verify(co.GroupKey, want[:], sig) {
		return ErrInvalidAggregate
	}
	var got xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(agg.AuthEntry, &got); err != nil {
		return ErrInvalidAggregate
	}
	creds, ok := got.Credentials.GetAddress()
	if !ok {
		return ErrInvalidAggregate
	}
	pk, s, ok := signaturePair(creds.Signature)
	if !ok || !bytes.Equal(pk, co.GroupKey) || !bytes.Equal(s, sig) {
		return ErrInvalidAggregate
	}
	// Apart from the signature, the entry must be byte-for-byte the request.
	wantCreds, _ := requested.Credentials.GetAddress()
	got.Credentials.Address.Signature = wantCreds.Signature
	a, err1 := got.MarshalBinary()
	b, err2 := requested.MarshalBinary()
	if err1 != nil || err2 != nil || !bytes.Equal(a, b) {
		return ErrInvalidAggregate
	}
	return nil
}

// signaturePair reads the [{public_key, signature}] value Stellar accounts expect.
func signaturePair(v xdr.ScVal) (publicKey, signature []byte, ok bool) {
	list, ok := v.GetVec()
	if !ok || list == nil || len(*list) != 1 {
		return nil, nil, false
	}
	m, ok := (*list)[0].GetMap()
	if !ok || m == nil || len(*m) != 2 {
		return nil, nil, false
	}
	field := func(i int, name string) []byte {
		k, ok := (*m)[i].Key.GetSym()
		if !ok || string(k) != name {
			return nil
		}
		b, ok := (*m)[i].Val.GetBytes()
		if !ok {
			return nil
		}
		return b
	}
	publicKey, signature = field(0, "public_key"), field(1, "signature")
	return publicKey, signature, publicKey != nil && signature != nil
}
