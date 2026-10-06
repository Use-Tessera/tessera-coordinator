// Package coordinator runs FROST signing sessions across Tessera signers.
//
// The coordinator holds no key material. It relays commitments and shares,
// and it independently verifies the final Ed25519 signature before releasing
// it, so a faulty or malicious signer cannot slip a bad signature through.
package coordinator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Use-Tessera/tessera-coordinator/internal/audit"
	"github.com/Use-Tessera/tessera-coordinator/internal/signer"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Errors callers map to responses.
var (
	ErrBadEnvelope       = errors.New("invalid transaction envelope")
	ErrNotEnoughSigners  = errors.New("not enough signers responded")
	ErrInvalidAggregate  = errors.New("aggregated signature does not verify against the group key")
	ErrInconsistentGroup = errors.New("signers disagree about the group")
)

// RefusedError lists each refusing signer's policy violations.
type RefusedError struct {
	Refusals map[string][]string // signer identifier -> violations
}

func (e *RefusedError) Error() string {
	var parts []string
	for id, v := range e.Refusals {
		parts = append(parts, fmt.Sprintf("%s: %s", short(id), strings.Join(v, "; ")))
	}
	sort.Strings(parts)
	return "policy refused: " + strings.Join(parts, " | ")
}

// Member is a signer whose identity is known.
type Member struct {
	Client *signer.Client
	Info   signer.Info
}

// Coordinator signs transactions for one Tessera group.
type Coordinator struct {
	Network   string
	Account   string
	Threshold int
	GroupKey  ed25519.PublicKey
	Members   []Member
	Audit     *audit.Log
	Timeout   time.Duration
}

// New contacts every signer, checks that they agree on the group, account,
// threshold and network, and requires at least a threshold of them to answer.
func New(ctx context.Context, passphrase string, clients []*signer.Client, log *audit.Log) (*Coordinator, error) {
	infos := make([]*signer.Info, len(clients))
	errs := make([]error, len(clients))
	var wg sync.WaitGroup
	for i, c := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			infos[i], errs[i] = c.Info(ctx)
		}()
	}
	wg.Wait()

	co := &Coordinator{Network: passphrase, Audit: log, Timeout: 20 * time.Second}
	seen := map[string]bool{}
	for i, info := range infos {
		if errs[i] != nil {
			continue
		}
		if co.Account == "" {
			co.Account, co.Threshold = info.Account, info.Threshold
		}
		switch {
		case info.Account != co.Account, info.Threshold != co.Threshold:
			return nil, fmt.Errorf("%w: %s reports %s (%d-of-%d)", ErrInconsistentGroup, clients[i].URL, info.Account, info.Threshold, info.Signers)
		case info.Network != passphrase:
			return nil, fmt.Errorf("%w: %s signs for %q, not %q", ErrInconsistentGroup, clients[i].URL, info.Network, passphrase)
		case seen[info.Identifier]:
			return nil, fmt.Errorf("%w: two signers share identifier %s", ErrInconsistentGroup, info.Identifier)
		}
		seen[info.Identifier] = true
		co.Members = append(co.Members, Member{Client: clients[i], Info: *info})
	}
	if co.Threshold == 0 || len(co.Members) < co.Threshold {
		return nil, fmt.Errorf("%w: %d of %d reachable, threshold %d: %w", ErrNotEnoughSigners, len(co.Members), len(clients), co.Threshold, errors.Join(errs...))
	}
	raw, err := strkey.Decode(strkey.VersionByteAccountID, co.Account)
	if err != nil {
		return nil, fmt.Errorf("group account %q: %w", co.Account, err)
	}
	co.GroupKey = ed25519.PublicKey(raw)
	return co, nil
}

// Result of a successful signing session.
type Result struct {
	Session  string   `json:"session"`
	Hash     string   `json:"hash"`
	Envelope string   `json:"envelope"`
	Signers  []string `json:"signers"`
}

type commitment struct {
	member      Member
	commitments string
}

// Sign runs both rounds with the first Threshold signers to answer round 1.
func (co *Coordinator) Sign(ctx context.Context, envelope string) (*Result, error) {
	var env xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(envelope, &env); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadEnvelope, err)
	}
	hash, err := network.HashTransactionInEnvelope(env, co.Network)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadEnvelope, err)
	}
	session := newSession()
	ctx, cancel := context.WithTimeout(ctx, co.Timeout)
	defer cancel()

	signed, ids, err := co.run(ctx, session, job{
		round2: func(ctx context.Context, c *signer.Client, commitments map[string]string) (string, error) {
			return c.Round2(ctx, session, envelope, commitments)
		},
		aggregate: func(ctx context.Context, c *signer.Client, commitments, shares map[string]string) (string, error) {
			agg, err := c.Aggregate(ctx, envelope, commitments, shares)
			if err != nil {
				return "", err
			}
			return agg.Envelope, co.check(agg.Hash, agg.Signature, agg.Envelope, hash)
		},
	})
	var res *Result
	if err == nil {
		res = &Result{Session: session, Hash: hex.EncodeToString(hash[:]), Envelope: signed, Signers: ids}
	}
	co.record(session, hash, ids, err)
	return res, err
}

// job is what differs between signing a transaction and an authorization entry.
type job struct {
	round2    func(ctx context.Context, c *signer.Client, commitments map[string]string) (share string, err error)
	aggregate func(ctx context.Context, c *signer.Client, commitments, shares map[string]string) (signed string, err error)
}

// run relays both rounds and returns the signed artefact and the participants.
func (co *Coordinator) run(ctx context.Context, session string, j job) (string, []string, error) {
	chosen, err := co.round1(ctx, session)
	if err != nil {
		return "", nil, err
	}
	commitments := map[string]string{}
	ids := make([]string, 0, len(chosen))
	for _, c := range chosen {
		commitments[c.member.Info.Identifier] = c.commitments
		ids = append(ids, c.member.Info.Identifier)
	}

	shares := map[string]string{}
	refusals := map[string][]string{}
	var mu sync.Mutex
	var failures []error
	var wg sync.WaitGroup
	for _, c := range chosen {
		wg.Add(1)
		go func() {
			defer wg.Done()
			share, err := j.round2(ctx, c.member.Client, commitments)
			mu.Lock()
			defer mu.Unlock()
			var refused *signer.RefusedError
			switch {
			case errors.As(err, &refused):
				refusals[c.member.Info.Identifier] = refused.Violations
			case err != nil:
				failures = append(failures, err)
			default:
				shares[c.member.Info.Identifier] = share
			}
		}()
	}
	wg.Wait()
	if len(refusals) > 0 {
		return "", nil, &RefusedError{Refusals: refusals}
	}
	if len(failures) > 0 {
		return "", nil, fmt.Errorf("round 2: %w", errors.Join(failures...))
	}

	signed, err := j.aggregate(ctx, chosen[0].member.Client, commitments, shares)
	if errors.Is(err, ErrInvalidAggregate) {
		return "", nil, err
	}
	if err != nil {
		return "", nil, fmt.Errorf("aggregate: %w", err)
	}
	return signed, ids, nil
}

// round1 asks every member for commitments and keeps the first Threshold, by identifier.
func (co *Coordinator) round1(ctx context.Context, session string) ([]commitment, error) {
	var mu sync.Mutex
	var got []commitment
	var failures []error
	var wg sync.WaitGroup
	for _, m := range co.Members {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, c, err := m.Client.Round1(ctx, session)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				failures = append(failures, err)
			case id != m.Info.Identifier:
				failures = append(failures, fmt.Errorf("%s answered as %s, expected %s", m.Client.URL, id, m.Info.Identifier))
			default:
				got = append(got, commitment{member: m, commitments: c})
			}
		}()
	}
	wg.Wait()
	if len(got) < co.Threshold {
		return nil, fmt.Errorf("%w: %d of %d needed: %w", ErrNotEnoughSigners, len(got), co.Threshold, errors.Join(failures...))
	}
	sort.Slice(got, func(i, j int) bool { return got[i].member.Info.Identifier < got[j].member.Info.Identifier })
	return got[:co.Threshold], nil
}

// check verifies the aggregate independently of the signers.
func (co *Coordinator) check(hashHex, sigHex, signedEnvelope string, want [32]byte) error {
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize || hashHex != hex.EncodeToString(want[:]) {
		return ErrInvalidAggregate
	}
	if !ed25519.Verify(co.GroupKey, want[:], sig) {
		return ErrInvalidAggregate
	}
	var env xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(signedEnvelope, &env); err != nil {
		return ErrInvalidAggregate
	}
	got, err := network.HashTransactionInEnvelope(env, co.Network)
	if err != nil || got != want {
		return ErrInvalidAggregate
	}
	for _, s := range env.Signatures() {
		if string(s.Signature) == string(sig) {
			return nil
		}
	}
	return ErrInvalidAggregate
}

func (co *Coordinator) record(session string, hash [32]byte, signers []string, err error) {
	if co.Audit == nil {
		return
	}
	r := audit.Record{Time: time.Now().UTC(), Session: session, TxHash: hex.EncodeToString(hash[:])}
	var refused *RefusedError
	switch {
	case err == nil:
		r.Outcome, r.Signers = "signed", signers
	case errors.As(err, &refused):
		r.Outcome, r.Refusals = "refused", refused.Refusals
	default:
		r.Outcome, r.Error = "failed", err.Error()
	}
	_, _ = co.Audit.Append(r)
}

func newSession() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
