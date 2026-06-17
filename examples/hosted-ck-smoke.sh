#!/usr/bin/env bash
set -euo pipefail

# Post-deploy smoke for hosted CK attestation on Vercel.
#
# Prereqs:
# - Go toolchain (builds 21pins from repo root)
# - For production/preview: routes must exist at PINS21_HOSTED_URL
# - For local Vercel dev (once website/api routes land):
#     cd website && vercel dev --listen 3000
#     export PINS21_HOSTED_URL=http://localhost:3000
#
# Signing key compatibility:
# - Live smoke checks session start + poll(pending) only (no browser OIDC).
# - Set PINS21_HOSTED_PUBLIC_KEY_HOSTED_ED25519_V1 for env decode check.
# - Full Ed25519 attestation verify/sign round-trip:
#     go test ./internal/hosted ./internal/policy -count=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${PINS21_BIN:-$(mktemp -t 21pins-smoke.XXXXXX)}"
cleanup() {
  if [[ "${PINS21_BIN:-}" == "" && -f "$BIN" ]]; then
    rm -f "$BIN"
  fi
}
trap cleanup EXIT

echo "[1/4] Building 21pins..."
go build -o "$BIN" "$ROOT/cmd/21pins"

HOSTED_URL="${PINS21_HOSTED_URL:-https://21pins.com}"
echo "[2/4] Health via hosted status ($HOSTED_URL)..."
"$BIN" hosted status --hosted-url "$HOSTED_URL"

echo "[3/4] Session start + poll(pending)..."
SMOKE_ARGS=(hosted smoke --hosted-url "$HOSTED_URL")
if [[ -n "${PINS21_HOSTED_PUBLIC_KEY_HOSTED_ED25519_V1:-}" ]]; then
  SMOKE_ARGS+=(--require-public-key)
fi
"$BIN" "${SMOKE_ARGS[@]}"

echo "[4/4] Local signing/key compatibility tests..."
go test "$ROOT/internal/hosted" "$ROOT/internal/policy" -count=1

echo "[done] Hosted CK smoke passed for $HOSTED_URL"
