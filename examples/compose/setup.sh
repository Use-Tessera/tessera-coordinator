#!/usr/bin/env bash
# Prepares a 2-of-3 Tessera group for compose.yaml on Stellar testnet.
#
# Runs distributed key generation for three participants with the `tessera`
# CLI, so no file or process ever holds the whole key, then writes each
# signer's config next to its share, the coordinator's config, and .env.
# Here the three participants share one machine; in production each runs
# its own steps and only the round-1 and round-2 files travel.
#
# Needs `tessera` (https://github.com/Use-Tessera/tessera/releases) and curl.
set -euo pipefail
cd "$(dirname "$0")"

if [ -e .env ]; then
  echo "already set up; run ./reset.sh first to make a new group" >&2
  exit 1
fi
# The images run as this user so they can write state and the audit log.
uid=$(id -u 2>/dev/null || echo 1000); gid=$(id -g 2>/dev/null || echo 1000)
TESSERA_PASSPHRASE="demo-$(date +%s)-$RANDOM$RANDOM"
TESSERA_TOKEN="signer-$RANDOM$RANDOM$RANDOM"
TESSERA_API_TOKEN="api-$RANDOM$RANDOM$RANDOM"
export TESSERA_PASSPHRASE

dkg=$(mktemp -d)
trap 'rm -rf "$dkg"' EXIT

echo "==> round 1: each participant starts"
for i in 1 2 3; do
  tessera dkg start --index "$i" --threshold 2 --signers 3 --state "$dkg/state-$i.json" >"$dkg/round1-$i.json" 2>/dev/null
done
fingerprint=$(tessera dkg fingerprint "$dkg"/round1-*.json)
echo "    fingerprint every participant compares out of band: $fingerprint"

echo "==> round 2: each participant checks the set and encrypts a file for each other one"
for i in 1 2 3; do
  tessera dkg exchange --state "$dkg/state-$i.json" --fingerprint "$fingerprint" --out "$dkg/round2" "$dkg"/round1-*.json 2>/dev/null
done

echo "==> finish: each participant derives its own share"
for i in 1 2 3; do
  mkdir -p "signer-$i/state"
  account=$(tessera dkg finish --state "$dkg/state-$i.json" --out "signer-$i/share.json" "$dkg"/round2/*.json 2>/dev/null)
  cp policy.toml "signer-$i/policy.toml"
  cat >"signer-$i/signer.toml" <<EOF
listen = "0.0.0.0:7401"
network = "testnet"
share = "share.json"
policy = "policy.toml"
state_dir = "state"
token_env = "TESSERA_TOKEN"
EOF
done
echo "    group account $account"

mkdir -p coordinator
cat >coordinator/coordinator.toml <<EOF
listen = "0.0.0.0:7400"
network = "testnet"
rpc = "https://soroban-testnet.stellar.org"
audit_log = "audit.jsonl"
api_token_env = "TESSERA_API_TOKEN"
$(for i in 1 2 3; do printf '\n[[signer]]\nurl = "http://signer-%s:7401"\ntoken_env = "TESSERA_TOKEN"\n' "$i"; done)
EOF

cat >.env <<EOF
TESSERA_ACCOUNT=$account
TESSERA_PASSPHRASE=$TESSERA_PASSPHRASE
TESSERA_TOKEN=$TESSERA_TOKEN
TESSERA_API_TOKEN=$TESSERA_API_TOKEN
UID_GID=$uid:$gid
EOF

echo "==> funding $account with friendbot"
curl -fsS "https://friendbot.stellar.org/?addr=$account" >/dev/null
echo "done: run 'docker compose up -d'"
