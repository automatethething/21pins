#!/usr/bin/env bash
set -euo pipefail

# Demo: run pi through local 21pins gateway in JSON mode.
# Prereqs:
# - 21pins gateway running on 127.0.0.1:8787
# - PINS21_TOKEN exported with proxy:chat,usage:read scopes
# - pi installed
# - jq installed

if ! command -v pi >/dev/null 2>&1; then
  echo "error: pi not found in PATH"
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq not found in PATH"
  exit 1
fi

if [[ -z "${PINS21_TOKEN:-}" ]]; then
  echo "error: PINS21_TOKEN is not set"
  echo "export PINS21_TOKEN='<token-from-21pins-token-create --scopes proxy:chat,usage:read>'"
  exit 1
fi

echo "[1/3] Checking 21pins gateway health..."
curl -fsS http://127.0.0.1:8787/health >/dev/null
echo "ok"

echo "[2/3] Running pi JSON-mode prompt via 21pins..."
pi --mode json \
  --provider pins21 \
  --model openrouter/openai/gpt-4o-mini \
  "Explain in one sentence what 21pins does" \
  2>/dev/null \
| jq -c 'select(.type == "message_end")'

echo "[3/3] Running pi JSON-mode tool demo..."
pi --mode json \
  --provider pins21 \
  --model openrouter/openai/gpt-4o-mini \
  "List files in this directory" \
  2>/dev/null \
| jq -c 'select(.type|test("tool_execution_"))'

echo "[done] View recorded usage: curl -H \"Authorization: Bearer $PINS21_TOKEN\" http://127.0.0.1:8787/v1/usage"
echo "[done] Or open http://127.0.0.1:8787/ui"
