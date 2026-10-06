<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo.svg" alt="Tessera" height="64">
  </picture>
</p>

<p align="center"><b>The Tessera coordinator runs threshold signing sessions across a group's signers. It holds no keys.</b></p>

<p align="center">
  <a href="https://github.com/Use-Tessera/tessera-coordinator/actions/workflows/ci.yml"><img src="https://github.com/Use-Tessera/tessera-coordinator/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a>
</p>

---

Applications (wallets, treasuries, AI agents) send the coordinator an unsigned
Stellar transaction. It asks every [signer](https://github.com/Use-Tessera/tessera)
for nonce commitments, runs round 2 with the first `threshold` to answer, has
the shares aggregated, **verifies the resulting Ed25519 signature itself**, and
returns the signed envelope, or submits it.

The coordinator is deliberately powerless. It cannot sign, it cannot get a
share for a transaction a signer hasn't decoded and approved, and it cannot
pass off a bad signature. The worst it can do is refuse to coordinate.

```console
$ tessera-coordinator pay --config coordinator.toml --to GAIH3U… --amount 1 --submit
signed ddfa10791ce6…5009: 2-of-3 group, 2 of 3 signers reachable
SUCCESS ddfa10791ce6f24fa1950eee3dd1ae71fa3335c92a58737751c606079bfd5009 ledger 5045354

$ tessera-coordinator pay --config coordinator.toml --to GAIH3U… --amount 150 --submit
error: policy refused: 01000000: spends 150 native, more than per_transaction 100 | 03000000: spends 150 native, more than per_transaction 100
```

That is a real testnet run with one signer offline:
[`ddfa1079…5009`](https://stellar.expert/explorer/testnet/tx/ddfa10791ce6f24fa1950eee3dd1ae71fa3335c92a58737751c606079bfd5009).
Reproduce it with [`scripts/testnet-demo.sh`](scripts/testnet-demo.sh).

## Quick start

```sh
go install github.com/Use-Tessera/tessera-coordinator/cmd/tessera-coordinator@latest
cp examples/coordinator.toml .   # list your signers
tessera-coordinator serve
```

On startup the coordinator asks every signer for its identity and refuses to
run if they disagree on the group account, threshold or network, or if fewer
than `threshold` are reachable.

## HTTP API

| Route | Body / result |
|---|---|
| `POST /v1/sign` | `{"envelope": "<base64 XDR>", "submit": false}` → `{"hash", "envelope", "signers", "session"}`; with `submit`, also `"submission": {"status", "ledger"}` |
| `GET /v1/group` | Account, threshold, network, and each signer's identifier and policy hash |
| `GET /healthz` | Liveness |

`/v1/*` requires `Authorization: Bearer $api_token_env` when configured.
Refusals return 403 with every refusing signer's reasons:

```json
{"error": "policy refused the transaction",
 "refusals": {"0100…": ["spends 150 native, more than per_transaction 100"]}}
```

Other errors: 400 (bad envelope), 503 (not enough signers), 502 (signer or RPC failure).

## Audit log

Every attempt, signed, refused or failed, is appended to `audit_log` as a JSON
line that carries the SHA-256 of the previous line. Editing, deleting or
reordering records breaks the chain:

```console
$ tessera-coordinator audit verify audit.jsonl
ok: 2 records, chain intact
```

## Layout

| Package | Responsibility |
|---|---|
| `internal/coordinator` | Group discovery, rounds, signer selection, independent signature verification |
| `internal/signer` | `tessera/signer/v1` client |
| `internal/audit` | Hash-chained append-only log |
| `internal/submit` | `sendTransaction` + `getTransaction` polling |
| `internal/api` | HTTP routes, auth, error mapping |
| `cmd/tessera-coordinator` | `serve`, `pay`, `audit verify` |

Tests replay a real 2-of-3 FROST run recorded by the signer's test suite
(`testdata/transcript.json`), so the coordinator's checks run against genuine
signatures. CI keeps the transcript identical to upstream.

## Contributing

Run `gofmt`, `go vet ./...` and `go test -race ./...` before opening a PR.
Ground rules and the security model live in the
[tessera](https://github.com/Use-Tessera/tessera) repository.

## License

[Apache-2.0](LICENSE)
