package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/clients/rpcclient"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// authValidity is how many ledgers (about 5 s each) a payment authorization
// stays valid; the demo policy allows up to 60.
const authValidity = 30

// agent is deliberately naive: it buys what its task needs and follows any
// instruction it reads in a response. It holds no key, only the
// coordinator's API token, so the signers' policies are all that limit it.
type agent struct {
	api, coordinator, token string
	rpc                     *rpcclient.Client
	http                    *http.Client
	account                 string
	asset                   xdr.ScAddress
	// submitter is the account the API submits payments from, read from
	// its 402 response. Simulation needs a source other than the group so
	// that the transfer is authorized by an entry, not by the source.
	submitter string
}

// refused is the coordinator's 403: the signers' reasons, by signer.
type refused map[string][]string

func (r refused) Error() string {
	ids := make([]string, 0, len(r))
	for id := range r {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b strings.Builder
	for _, id := range ids {
		fmt.Fprintf(&b, "\n          signer %s: %s", signerID(id), strings.Join(r[id], "; "))
	}
	return "refused by the signers:" + b.String()
}

var instruction = regexp.MustCompile(`transfer (\d+) XLM to (G[A-Z2-7]{55})`)

func runAgent(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	api := fs.String("api", "http://127.0.0.1:7600", "the paid API")
	coordinator := fs.String("coordinator", "http://127.0.0.1:7400", "the Tessera coordinator")
	rpcURL := fs.String("rpc", "https://soroban-testnet.stellar.org", "Stellar RPC, for simulation")
	calls := fs.Int("calls", 6, "calls to buy")
	_ = fs.Parse(args)

	asset, _, err := xlm()
	if err != nil {
		return err
	}
	a := &agent{
		api: *api, coordinator: *coordinator, token: os.Getenv("TESSERA_API_TOKEN"),
		rpc: rpcclient.NewClient(*rpcURL, nil), http: &http.Client{Timeout: 90 * time.Second}, asset: asset,
	}
	ctx := context.Background()
	var group struct {
		Account   string `json:"account"`
		Threshold int    `json:"threshold"`
		Signers   []any  `json:"signers"`
	}
	if err := a.do(ctx, http.MethodGet, a.coordinator+"/v1/group", nil, nil, &group); err != nil {
		return fmt.Errorf("coordinator: %w", err)
	}
	a.account = group.Account
	fmt.Printf("agent   holds no key; pays from the %d-of-%d group %s through the coordinator\n",
		group.Threshold, len(group.Signers), group.Account)

	for i := 1; i <= *calls; i++ {
		fmt.Printf("call %d  ", i)
		paid, err := a.buy(ctx)
		var no refused
		if errors.As(err, &no) {
			fmt.Printf("payment %v\n", err)
			fmt.Println("agent   stopping: the group will not pay for more calls right now")
			return nil
		}
		if err != nil {
			return err
		}
		fmt.Printf("paid, settled in %s (ledger %d); report: ledger %d, protocol %d\n",
			paid.Payment.Transaction, paid.Payment.Ledger, paid.Report.Ledger, paid.Report.Protocol)
		if paid.Report.Note == "" {
			continue
		}
		fmt.Printf("        the response says: %q\n", paid.Report.Note)
		m := instruction.FindStringSubmatch(paid.Report.Note)
		if m == nil {
			continue
		}
		xlmAmount, _ := strconv.ParseInt(m[1], 10, 64)
		fmt.Printf("        following it: asking the group to transfer %d XLM to %s\n", xlmAmount, short(m[2]))
		_, err = a.authorize(ctx, m[2], xlmAmount*stroopsPerXLM)
		if !errors.As(err, &no) {
			return fmt.Errorf("the injected transfer was not refused (err: %w)", err)
		}
		fmt.Printf("        %v\n", err)
	}
	return nil
}

// buy pays for one call: ask, read the price, have the group authorize the
// transfer, and ask again with the signed authorization.
func (a *agent) buy(ctx context.Context) (*Paid, error) {
	var req Requirements
	err := a.do(ctx, http.MethodGet, a.api+"/report", nil, nil, &req)
	var status httpStatus
	if !errors.As(err, &status) || status.code != http.StatusPaymentRequired {
		return nil, fmt.Errorf("expected 402 from the API, got %w", err)
	}
	if err := json.Unmarshal(status.body, &req); err != nil {
		return nil, err
	}
	amount, err := strconv.ParseInt(req.Amount, 10, 64)
	if err != nil {
		return nil, err
	}
	fmt.Printf("402: %s XLM to %s; ", strconv.FormatFloat(float64(amount)/stroopsPerXLM, 'f', -1, 64), short(req.PayTo))
	a.submitter = req.FeePayer
	entry, err := a.authorize(ctx, req.PayTo, amount)
	if err != nil {
		return nil, err
	}
	var paid Paid
	if err := a.do(ctx, http.MethodGet, a.api+"/report", map[string]string{"X-Payment": entry}, nil, &paid); err != nil {
		return nil, fmt.Errorf("API: %w", err)
	}
	return &paid, nil
}

// authorize has the group sign a transfer of stroops to `to` and returns the
// signed authorization entry.
func (a *agent) authorize(ctx context.Context, to string, stroops int64) (string, error) {
	call, err := transfer(a.asset, a.account, to, stroops)
	if err != nil {
		return "", err
	}
	src, err := a.rpc.LoadAccount(ctx, a.submitter)
	if err != nil {
		return "", err
	}
	tx, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount:        src,
		IncrementSequenceNum: true,
		BaseFee:              txnbuild.MinBaseFee,
		Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewTimeout(120)},
		Operations:           []txnbuild.Operation{&txnbuild.InvokeHostFunction{HostFunction: invoke(call)}},
	})
	if err != nil {
		return "", err
	}
	b64, err := tx.Base64()
	if err != nil {
		return "", err
	}
	sim, err := a.rpc.SimulateTransaction(ctx, protocol.SimulateTransactionRequest{Transaction: b64})
	if err != nil {
		return "", err
	}
	if sim.Error != "" {
		return "", fmt.Errorf("simulation: %s", sim.Error)
	}
	if len(sim.Results) != 1 || sim.Results[0].AuthXDR == nil || len(*sim.Results[0].AuthXDR) != 1 {
		return "", errors.New("simulation returned no authorization entry for the group")
	}
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64((*sim.Results[0].AuthXDR)[0], &entry); err != nil {
		return "", err
	}
	if entry.Credentials.Address == nil {
		return "", errors.New("simulation returned source-account credentials")
	}
	entry.Credentials.Address.SignatureExpirationLedger = xdr.Uint32(sim.LatestLedger + authValidity)
	unsigned, err := xdr.MarshalBase64(entry)
	if err != nil {
		return "", err
	}
	var signed struct {
		AuthEntry string   `json:"auth_entry"`
		Signers   []string `json:"signers"`
	}
	body := map[string]any{"auth_entry": unsigned, "latest_ledger": sim.LatestLedger}
	if err := a.do(ctx, http.MethodPost, a.coordinator+"/v1/authorize", map[string]string{"Idempotency-Key": newKey()}, body, &signed); err != nil {
		var status httpStatus
		if errors.As(err, &status) && status.code == http.StatusForbidden {
			var r struct {
				Refusals refused `json:"refusals"`
			}
			if json.Unmarshal(status.body, &r) == nil && len(r.Refusals) > 0 {
				return "", r.Refusals
			}
		}
		return "", err
	}
	ids := make([]string, len(signed.Signers))
	for i, id := range signed.Signers {
		ids[i] = signerID(id)
	}
	fmt.Printf("signers %s approved; ", strings.Join(ids, ", "))
	return signed.AuthEntry, nil
}

// httpStatus is a response other than 200.
type httpStatus struct {
	code int
	body []byte
}

func (e httpStatus) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.code, bytes.TrimSpace(e.body))
}

func (a *agent) do(ctx context.Context, method, url string, headers map[string]string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	if strings.HasPrefix(url, a.coordinator) && a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return httpStatus{code: resp.StatusCode, body: b}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

// signerID shortens a FROST identifier (32 bytes, little-endian) the way
// the signers' own messages do: "01000000" for signer 1.
func signerID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func newKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
