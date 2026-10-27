#!/usr/bin/env bash
# An AI agent pays for an API from a Tessera group on Stellar testnet:
#   2-of-3 keygen -> three signers with an agent policy -> coordinator ->
#   a paid API that answers 402 -> the agent buys calls until its policy stops it.
#
# The agent holds only the coordinator's API token. It pays with Soroban
# authorizations the group signs, and it obeys an instruction the API slips
# into one response to send 100 XLM elsewhere: the signers refuse that, and
# later refuse the call that would pass the hourly limit.
#
# Run from the repository root. Needs `tessera` and `tessera-signer` from
# Use-Tessera/tessera (main or a release with per_hour) on PATH, Go, and
# curl. Uses ports 7400, 7401-7403 and 7600.
set -euo pipefail

WORK=$(mktemp -d)
# Native Windows binaries need Windows paths inside config files.
winpath() { command -v cygpath >/dev/null && cygpath -m "$1" || echo "$1"; }
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

EXE=$(go env GOEXE)
go build -o "$WORK/tessera-coordinator$EXE" ./cmd/tessera-coordinator
(cd examples/agent && go build -o "$WORK/agent$EXE" .)

export TESSERA_PASSPHRASE="demo-$(date +%s)-$RANDOM"
export TESSERA_TOKEN="token-$RANDOM$RANDOM"
export TESSERA_API_TOKEN="agent-$RANDOM$RANDOM"

fund() {
  curl -fsS "https://friendbot.stellar.org/?addr=$1" >/dev/null
  for _ in $(seq 20); do
    curl -fsS "https://horizon-testnet.stellar.org/accounts/$1" >/dev/null 2>&1 && return
    sleep 2
  done
  echo "could not fund $1" >&2
  exit 1
}

echo "==> generating a 2-of-3 group and the API's account"
ACCOUNT=$(tessera keygen --threshold 2 --signers 3 --out "$(winpath "$WORK")")
read -r PAYWALL_SECRET API_ACCOUNT < <("$WORK/agent$EXE" newkey)
export PAYWALL_SECRET
echo "    group $ACCOUNT, API $API_ACCOUNT"
fund "$ACCOUNT"
fund "$API_ACCOUNT"

# The agent may pay the API, and only the API: 2 XLM a call, 5 an hour,
# 20 a day, through authorizations that expire within about 5 minutes.
cat >"$WORK/policy.toml" <<EOF
network = "testnet"
max_fee = 100000
max_validity = 300

[operations]
allow = ["invoke_contract"]

[destinations]
allow = ["$API_ACCOUNT"]

[[token]]
contract = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"
per_transaction = "2"
per_hour = "5"
per_day = "20"

[auth]
max_validity_ledgers = 60
EOF

for i in 1 2 3; do
  mkdir -p "$WORK/state-$i"
  cat >"$WORK/signer-$i.toml" <<EOF
listen = "127.0.0.1:740$i"
network = "testnet"
share = "share-$i.json"
policy = "policy.toml"
state_dir = "state-$i"
token_env = "TESSERA_TOKEN"
rpc = "https://soroban-testnet.stellar.org"
EOF
  tessera-signer --config "$(winpath "$WORK/signer-$i.toml")" >"$WORK/signer-$i.log" 2>&1 &
  PIDS+=($!)
done
sleep 2

cat >"$WORK/coordinator.toml" <<EOF
listen = "127.0.0.1:7400"
network = "testnet"
rpc = "https://soroban-testnet.stellar.org"
audit_log = "audit.jsonl"
api_token_env = "TESSERA_API_TOKEN"
$(for i in 1 2 3; do printf '[[signer]]\nurl = "http://127.0.0.1:740%s"\ntoken_env = "TESSERA_TOKEN"\n' "$i"; done)
EOF
"$WORK/tessera-coordinator$EXE" serve --config "$(winpath "$WORK/coordinator.toml")" 2>"$WORK/coordinator.log" &
PIDS+=($!)
"$WORK/agent$EXE" paywall --inject-at 3 2>"$WORK/paywall.log" &
PIDS+=($!)
for _ in $(seq 20); do
  curl -fsS http://127.0.0.1:7400/healthz >/dev/null 2>&1 && break
  sleep 1
done

echo "==> the agent buys reports at 1 XLM each"
"$WORK/agent$EXE" run --calls 7

echo "==> audit log"
"$WORK/tessera-coordinator$EXE" audit verify "$(winpath "$WORK/audit.jsonl")"
