#!/usr/bin/env bash
# End-to-end Tessera demo on Stellar testnet:
#   2-of-3 keygen -> three signers -> one signer offline -> coordinator pays 1 XLM,
#   then asks for 150 XLM, which every signer's policy refuses.
#
# Needs `tessera`, `tessera-signer` (from Use-Tessera/tessera) and
# `tessera-coordinator` on PATH, plus curl. Uses ports 7401-7403.
set -euo pipefail

TESSERA_POLICY=${TESSERA_POLICY:?set TESSERA_POLICY to a testnet policy file, e.g. tessera/examples/policy.toml}
DEST=${DEST:-GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR}
WORK=$(mktemp -d)
# Native Windows binaries need Windows paths inside config files.
abspath() { local p; p="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; command -v cygpath >/dev/null && cygpath -m "$p" || echo "$p"; }
POLICY_PATH=$(abspath "$TESSERA_POLICY")
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

export TESSERA_PASSPHRASE="demo-$(date +%s)-$RANDOM"
export TESSERA_TOKEN="token-$RANDOM$RANDOM"

echo "==> generating a 2-of-3 group"
ACCOUNT=$(tessera keygen --threshold 2 --signers 3 --out "$WORK")
echo "    account $ACCOUNT"

echo "==> funding it with friendbot"
curl -fsS "https://friendbot.stellar.org/?addr=$ACCOUNT" >/dev/null
for _ in $(seq 20); do
  curl -fsS "https://horizon-testnet.stellar.org/accounts/$ACCOUNT" >/dev/null 2>&1 && break
  sleep 2
done

for i in 1 2 3; do
  mkdir -p "$WORK/state-$i"
  cat >"$WORK/signer-$i.toml" <<EOF
listen = "127.0.0.1:740$i"
network = "testnet"
share = "share-$i.json"
policy = "$POLICY_PATH"
state_dir = "state-$i"
token_env = "TESSERA_TOKEN"
EOF
  tessera-signer --config "$WORK/signer-$i.toml" >"$WORK/signer-$i.log" 2>&1 &
  PIDS+=($!)
done
sleep 2

cat >"$WORK/coordinator.toml" <<EOF
network = "testnet"
rpc = "https://soroban-testnet.stellar.org"
audit_log = "audit.jsonl"
$(for i in 1 2 3; do printf '[[signer]]\nurl = "http://127.0.0.1:740%s"\ntoken_env = "TESSERA_TOKEN"\n' "$i"; done)
EOF

echo "==> taking signer 2 offline"
kill "${PIDS[1]}"
sleep 1

echo "==> paying 1 XLM with the two remaining signers"
tessera-coordinator pay --config "$WORK/coordinator.toml" --to "$DEST" --amount 1 --submit

echo "==> asking for 150 XLM (policy allows 100 per transaction)"
if tessera-coordinator pay --config "$WORK/coordinator.toml" --to "$DEST" --amount 150 --submit; then
  echo "unexpected: the oversized payment was signed" >&2
  exit 1
fi

echo "==> audit log"
tessera-coordinator audit verify "$WORK/audit.jsonl"
