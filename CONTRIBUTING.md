# Contributing

The coordinator runs FROST signing sessions across Tessera signers. It takes
part in the [Stellar Wave](https://www.drips.network/wave/stellar) program; Wave
issues are labeled with their complexity. The ground rules for every Tessera
repository are in the
[organization guide](https://github.com/Use-Tessera/.github/blob/main/CONTRIBUTING.md).

## Setup

```sh
git clone https://github.com/Use-Tessera/tessera-coordinator && cd tessera-coordinator
go test ./...
```

Go 1.25 or later. Tests replay real signer sessions from `testdata/` through
`internal/testsigner`, so no Rust toolchain or network is needed. To run the
whole stack, see [`examples/compose`](examples/compose/) or
[`scripts/testnet-demo.sh`](scripts/testnet-demo.sh).

## Before you open a PR

```sh
gofmt -l .            # must print nothing
go vet ./...
go test -race ./...
golangci-lint run
```

CI also runs govulncheck, builds the Docker image, and checks the transcript
fixture.

## Rules specific to the coordinator

- **The coordinator is untrusted.** Signers decide; the coordinator relays.
  Never add logic that assumes a signer will accept something because the
  coordinator checked it.
- **A new endpoint needs an entry in `api/openapi.yaml`**; a test checks that
  every route is described.
- **The audit log is append-only and hash-chained.** A format change must keep
  `tessera-coordinator audit verify` passing on existing logs.

## Fixtures

`testdata/transcript.json` must stay byte-identical to
[tessera](https://github.com/Use-Tessera/tessera)'s
`crates/tessera-signer/tests/fixtures/transcript.json`; CI compares them.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org): `feat(api): …`,
`fix(coordinator): …`, `docs: …`.
