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
Reproduce it with [`scripts/testnet-demo.sh`](scripts/testnet-demo.sh), or with
Docker in [`examples/compose`](examples/compose/): three signer containers,
distributed key generation, and a payment with one signer offline.

Testnet is reset every few months, after which these links stop resolving; the script reproduces the whole run on a fresh network.

## Quick start

```sh
go install github.com/Use-Tessera/tessera-coordinator/cmd/tessera-coordinator@latest
cp examples/coordinator.toml .   # list your signers
tessera-coordinator serve
```

Binaries for Linux, macOS and Windows are on
[Releases](https://github.com/Use-Tessera/tessera-coordinator/releases), and the
image is `ghcr.io/use-tessera/tessera-coordinator` (amd64 and arm64).

On startup the coordinator asks every signer for its identity and refuses to
run if they disagree on the group account, threshold or network, or if fewer
than `threshold` are reachable.

## HTTP API

| Route | Body / result |
|---|---|
| `POST /v1/sign` | `{"envelope": "<base64 XDR>", "submit": false}` → `{"hash", "envelope", "signers", "session"}`; with `submit`, also `"submission": {"status", "ledger"}` |
| `POST /v1/authorize` | `{"auth_entry": "<base64 XDR>", "latest_ledger": 0}` → `{"hash", "auth_entry", "signers", "session", "latest_ledger"}` |
| `GET /v1/group` | Account, threshold, network, and each signer's identifier and policy hash |
| `GET /healthz` | Liveness |
| `GET /metrics` | Prometheus counters by route and status |

The full schema is in [`api/openapi.yaml`](api/openapi.yaml). `/v1/*` requires
`Authorization: Bearer $api_token_env` when configured; every response carries
an `X-Request-ID`, echoed from the request when given.

Send an `Idempotency-Key` with every signing request your client may retry.
Signers count spend when they approve, so a retried payment without one runs a
second session and uses the daily limit twice. With a key, a repeat within 24
hours gets the first response back (`Idempotent-Replayed: true`), a concurrent
duplicate waits for the first, and reusing a key for a different request is a
422.

Refusals return 403 with every refusing signer's reasons:

```json
{"error": "policy refused the request",
 "refusals": {"0100…": ["spends 150 native, more than per_transaction 100"]}}
```

Other errors: 400 (bad envelope or entry), 503 (not enough signers), 502 (signer or RPC failure).

### Authorizing contract calls

When the group is not the transaction source, say an agent pays through a
contract that calls `token.transfer(group, …)`, Soroban needs the group's
signature on a `SorobanAuthorizationEntry` instead. Pass the entry from
`simulateTransaction` to `/v1/authorize`: each signer decodes the invocation
tree, applies its `[[contract]]`, `[[token]]` and `[auth]` limits, and signs
the payload hash only if they hold. The coordinator recomputes that hash,
checks the returned entry is unchanged apart from a
`[{public_key, signature}]` that verifies under the group key, and returns it
ready to put back into the transaction.

Signers bound an authorization's lifetime by the latest ledger. With `rpc`
configured the coordinator reads it from the network and ignores the caller's
`latest_ledger`. Signers configured with their own `rpc` go further and ignore
the coordinator's value too, so not even a compromised coordinator can stretch
an authorization's validity.

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
| `internal/coordinator` | Group discovery, rounds, signer selection, independent verification of transactions and authorization entries |
| `internal/signer` | `tessera/signer/v1` client |
| `internal/audit` | Hash-chained append-only log |
| `internal/submit` | `sendTransaction` with `TRY_AGAIN_LATER` resends, `getTransaction` polling, `getLatestLedger` |
| `internal/api` | HTTP routes, auth, error mapping |
| `cmd/tessera-coordinator` | `serve`, `pay`, `authorize`, `audit verify` |

Tests replay a real 2-of-3 FROST run recorded by the signer's test suite
(`testdata/transcript.json`, one transaction and one authorization entry), so the coordinator's checks run against genuine
signatures. CI keeps the transcript identical to upstream.

## Contributing

Run `gofmt`, `go vet ./...` and `go test -race ./...` before opening a PR.
Ground rules and the security model live in the
[tessera](https://github.com/Use-Tessera/tessera) repository.

## License

[Apache-2.0](LICENSE)
