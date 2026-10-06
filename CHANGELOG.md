# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Threshold signing sessions across `tessera/signer/v1` signers: group
  discovery and consistency checks on startup, round 1 with every signer,
  round 2 with the first `threshold` to answer, and independent Ed25519
  verification of every aggregate before it is released.
- `POST /v1/sign`, optionally submitting through Stellar RPC and waiting for
  the outcome.
- `POST /v1/authorize` and `tessera-coordinator authorize`: sign Soroban
  authorization entries. The coordinator recomputes the payload hash and
  rejects any aggregate whose entry differs from the request in anything but
  its signature. With RPC configured, the latest ledger is read from the
  network rather than trusted from the caller.
- Hash-chained audit log of every attempt, with the kind of payload signed,
  and `tessera-coordinator audit verify`.
- `Idempotency-Key` on both signing routes, so a client retry cannot run a
  second session and spend a daily limit twice.
- Request IDs, structured access logs and `GET /metrics`.
- `session_timeout` setting; read, write and idle limits per connection.
- OpenAPI 3.1 description in `api/openapi.yaml`, checked against the routes
  by a test.
- Release binaries for Linux, macOS and Windows, and a multi-arch image at
  `ghcr.io/use-tessera/tessera-coordinator`.

### Fixed

- Submission resends when RPC answers `TRY_AGAIN_LATER` instead of failing.

[Unreleased]: https://github.com/Use-Tessera/tessera-coordinator/commits/main
