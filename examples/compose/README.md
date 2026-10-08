# A 2-of-3 group with Docker Compose

Three `tessera-signer` containers and the coordinator, on Stellar testnet,
from the published images. About five minutes, start to finish.

You need Docker, curl, and the `tessera` CLI from
[Releases](https://github.com/Use-Tessera/tessera/releases) on your `PATH`.

## 1. Generate the group

```sh
./setup.sh
```

This runs distributed key generation for three participants: each one
starts, everyone compares the round-1 fingerprint, each one encrypts a
round-2 file for every other, and each derives its own share. No file or
process ever holds the whole key. Here the three participants share one
machine; in production each runs its own `tessera dkg` steps and only the
round-1 and round-2 files travel between them.

It then writes `signer-N/` (share, policy, config), `coordinator/`, and
`.env` with the passphrase and tokens, and funds the group account with
friendbot. The policy is [`policy.toml`](policy.toml): payments up to 100 XLM
each, transactions must expire within 15 minutes.

## 2. Start it

```sh
docker compose up -d
docker compose logs coordinator
```

The coordinator logs the group it found: the account, threshold 2, three signers.

## 3. Pay with one signer offline

```sh
docker compose stop signer-2
docker compose run --rm --no-deps coordinator pay \
  --config /etc/tessera/coordinator.toml \
  --to GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR --amount 1 --submit
```

```text
signed c4b69750…15a2: 2-of-3 group, 2 of 3 signers reachable
SUCCESS c4b69750…15a2 ledger 5084699
```

The two remaining signers each decoded the transaction, checked it against
their policy, and produced one FROST share of a single Ed25519 signature.
On chain it is an ordinary payment with one signature.

## 4. Ask for too much

```sh
docker compose run --rm --no-deps coordinator pay \
  --config /etc/tessera/coordinator.toml \
  --to GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR --amount 150 --submit
```

```text
error: policy refused: 01000000: spends 150 native, more than per_transaction 100 | 03000000: spends 150 native, more than per_transaction 100
```

## 5. Use the API and check the audit log

The coordinator listens on `127.0.0.1:7400`:

```sh
. ./.env
curl -H "Authorization: Bearer $TESSERA_API_TOKEN" http://127.0.0.1:7400/v1/group
docker compose run --rm --no-deps coordinator audit verify /etc/tessera/audit.jsonl
```

Applications sign with `POST /v1/sign` and `POST /v1/authorize`; see
[`api/openapi.yaml`](../../api/openapi.yaml).

## Clean up

```sh
./reset.sh
```

Stops the containers and deletes the shares, state, audit log and `.env`.
The passphrase in `.env` is for this demo only: real deployments give each
signer its own passphrase and token, on its own machine.

On Git Bash for Windows, set `MSYS_NO_PATHCONV=1` so the container paths
above are passed through unchanged.
