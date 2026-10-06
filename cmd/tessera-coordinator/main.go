// Command tessera-coordinator runs FROST signing sessions for a Tessera group.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Use-Tessera/tessera-coordinator/internal/api"
	"github.com/Use-Tessera/tessera-coordinator/internal/audit"
	"github.com/Use-Tessera/tessera-coordinator/internal/config"
	"github.com/Use-Tessera/tessera-coordinator/internal/coordinator"
	"github.com/Use-Tessera/tessera-coordinator/internal/signer"
	"github.com/Use-Tessera/tessera-coordinator/internal/submit"
	"github.com/stellar/go-stellar-sdk/txnbuild"
)

var version = "dev"

const usage = `tessera-coordinator runs threshold signing sessions for a Tessera group.

Usage:
  tessera-coordinator serve  [--config coordinator.toml]
  tessera-coordinator pay    [--config coordinator.toml] --to G... --amount 1 [--horizon URL] [--submit]
  tessera-coordinator authorize [--config coordinator.toml] [--latest-ledger N] < entry.b64
  tessera-coordinator audit  verify <audit.jsonl>
  tessera-coordinator version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "pay":
		err = pay(os.Args[2:])
	case "authorize":
		err = authorize(os.Args[2:], os.Stdin)
	case "audit":
		err = auditCmd(os.Args[2:])
	case "version":
		fmt.Println("tessera-coordinator", version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func setup(ctx context.Context, path string) (*config.Config, *coordinator.Coordinator, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, nil, err
	}
	var clients []*signer.Client
	for _, s := range cfg.Signers {
		token, err := config.Env(s.TokenEnv)
		if err != nil {
			return nil, nil, fmt.Errorf("signer %s: %w", s.URL, err)
		}
		clients = append(clients, signer.New(s.URL, token))
	}
	log, err := audit.Open(cfg.AuditLog)
	if err != nil {
		return nil, nil, err
	}
	co, err := coordinator.New(ctx, cfg.Passphrase(), clients, log)
	return cfg, co, err
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("config", "coordinator.toml", "config file")
	_ = fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, co, err := setup(ctx, *path)
	if err != nil {
		return err
	}
	token, err := config.Env(cfg.APITokenEnv)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if token == "" {
		logger.Warn("no api_token_env configured: anyone who can reach the coordinator can request signatures")
	}
	s := &api.Server{Coordinator: co, Token: token, Log: logger}
	if cfg.RPC != "" {
		s.Submitter = submit.New(cfg.RPC)
	}
	srv := &http.Server{Addr: cfg.Listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	logger.Info("serving", "addr", cfg.Listen, "account", co.Account, "threshold", co.Threshold, "signers", len(co.Members))
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func pay(args []string) error {
	fs := flag.NewFlagSet("pay", flag.ExitOnError)
	path := fs.String("config", "coordinator.toml", "config file")
	to := fs.String("to", "", "destination account")
	amount := fs.String("amount", "", "amount of XLM")
	horizonURL := fs.String("horizon", "https://horizon-testnet.stellar.org", "Horizon URL used to read the sequence number")
	doSubmit := fs.Bool("submit", false, "submit through the configured rpc and wait for the result")
	_ = fs.Parse(args)
	if *to == "" || *amount == "" {
		return errors.New("--to and --amount are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cfg, co, err := setup(ctx, *path)
	if err != nil {
		return err
	}
	seq, err := sequence(ctx, *horizonURL, co.Account)
	if err != nil {
		return err
	}
	tx, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount:        &txnbuild.SimpleAccount{AccountID: co.Account, Sequence: seq},
		IncrementSequenceNum: true,
		BaseFee:              txnbuild.MinBaseFee,
		Memo:                 txnbuild.MemoText("tessera"),
		Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewTimeout(300)},
		Operations:           []txnbuild.Operation{&txnbuild.Payment{Destination: *to, Amount: *amount, Asset: txnbuild.NativeAsset{}}},
	})
	if err != nil {
		return err
	}
	unsigned, err := tx.Base64()
	if err != nil {
		return err
	}
	res, err := co.Sign(ctx, unsigned)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "signed %s: %d-of-%d group, %d of %d signers reachable\n",
		res.Hash, co.Threshold, len(cfg.Signers), len(co.Members), len(cfg.Signers))
	if !*doSubmit {
		fmt.Println(res.Envelope)
		return nil
	}
	if cfg.RPC == "" {
		return errors.New("--submit needs rpc in the config")
	}
	outcome, err := submit.New(cfg.RPC).Submit(ctx, res.Envelope, res.Hash)
	if err != nil {
		return err
	}
	fmt.Printf("%s %s ledger %d\n", outcome.Status, res.Hash, outcome.Ledger)
	if outcome.Status != "SUCCESS" {
		return errors.New("transaction failed on chain")
	}
	return nil
}

// authorize signs one base64 SorobanAuthorizationEntry read from stdin and
// prints the signed entry.
func authorize(args []string, in io.Reader) error {
	fs := flag.NewFlagSet("authorize", flag.ExitOnError)
	path := fs.String("config", "coordinator.toml", "config file")
	latest := fs.Uint("latest-ledger", 0, "the network's latest ledger; read from rpc when configured")
	_ = fs.Parse(args)

	raw, err := io.ReadAll(io.LimitReader(in, 1<<20))
	if err != nil {
		return err
	}
	entry := strings.TrimSpace(string(raw))
	if entry == "" {
		return errors.New("pipe a base64 SorobanAuthorizationEntry on stdin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cfg, co, err := setup(ctx, *path)
	if err != nil {
		return err
	}
	ledger := uint32(min(*latest, math.MaxUint32)) //nolint:gosec // G115: clamped above
	if cfg.RPC != "" {
		if ledger, err = submit.New(cfg.RPC).LatestLedger(ctx); err != nil {
			return err
		}
	}
	if ledger == 0 {
		return errors.New("--latest-ledger is required when no rpc is configured")
	}
	res, err := co.SignAuth(ctx, entry, ledger)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "signed authorization %s at ledger %d: signers %s\n", res.Hash, ledger, strings.Join(res.Signers, ", "))
	fmt.Println(res.AuthEntry)
	return nil
}

func sequence(ctx context.Context, horizon, account string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, horizon+"/accounts/"+account, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("account %s: HTTP %d (is it funded?)", account, resp.StatusCode)
	}
	var a struct {
		Sequence string `json:"sequence"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
		return 0, err
	}
	return strconv.ParseInt(a.Sequence, 10, 64)
}

func auditCmd(args []string) error {
	if len(args) != 2 || args[0] != "verify" {
		return errors.New("usage: tessera-coordinator audit verify <audit.jsonl>")
	}
	recs, err := audit.Read(args[1])
	if err != nil {
		return err
	}
	if err := audit.Verify(recs); err != nil {
		return err
	}
	fmt.Printf("ok: %d records, chain intact\n", len(recs))
	return nil
}
