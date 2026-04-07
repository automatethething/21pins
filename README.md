# 21pins CLI (Go)

Local-first CLI + localhost gateway for managing LLM provider keys in one place and using them from apps/agents without embedding provider keys everywhere.

> Repo note: `website/` contains the static marketing site deployed to **https://21pins.com**. The CLI/gateway source of truth is `cmd/` + `internal/`.

## Why "21pins"

The long-term policy layer is modeled as seven control pins:
1. Identity (ConsentKeys OIDC)
2. Delegation (who issued grant)
3. Scope (allowed actions/tools)
4. Data boundaries (allowed data classes)
5. Budget (spend window/limit)
6. Vendor (allowed API targets)
7. Approval threshold (human-in-loop trigger)

## What ships in v1

- Store provider keys locally in `~/.config/21pins/state.json` (file mode `0600`)
- Create per-app bearer tokens with scopes
- Run a local gateway at `127.0.0.1:8787`
- OpenAI-compatible chat endpoint: `POST /v1/chat/completions`
- Provider passthrough endpoint: `ANY /v1/providers/{provider}/{path}`
- **Phase 1 policy core:** canonical grant objects + signed grant exports (15m default TTL)
- **7-pin evaluation engine:** per-pin pass/fail/requires_approval output + final decision
- **Execution receipts:** persisted record of grant, pin states, spend, target, decision

Providers wired:
- OpenAI
- OpenRouter
- Anthropic
- Gemini
- Ollama

## Install (local build)

```bash
go build -o 21pins ./cmd/21pins
./21pins init
```


## Quickstart

### 1) Check supported providers and add keys

```bash
./21pins key providers

./21pins key set openai --value "$OPENAI_API_KEY"
./21pins key set openrouter --value "$OPENROUTER_API_KEY"
./21pins key set anthropic --value "$ANTHROPIC_API_KEY"
./21pins key set gemini --value "$GEMINI_API_KEY"
# ollama usually does not need an API key
```

Canonical provider names are:
- `openai`
- `openrouter`
- `anthropic`
- `gemini`
- `ollama`

Common aliases are accepted and auto-mapped (for example, `openrouter.ai` -> `openrouter`).

### Optional: rotate keys safely

```bash
./21pins key rotate start openai --value "$NEW_OPENAI_API_KEY"
./21pins key rotate verify openai
./21pins key rotate commit openai --keep-previous-hours 24
# later, once stable:
./21pins key revoke openai --previous
```

Default behavior keeps the previous key for a grace window so rollback is possible.
Use `--keep-previous-hours 0` for immediate old-key revocation.

### Optional: sync and choose models from your configured providers

```bash
./21pins models sync
./21pins models list --provider openrouter --search gemini
./21pins models choose --provider openrouter --search gpt
```

`models choose` prints a routing-ready model string like `openrouter/openai/gpt-4o`.

### 2) Create an app token

```bash
./21pins token create my-web-app --scopes proxy:chat,proxy:providers
```

Copy the token output. It is shown once.

### 3) Start gateway

```bash
./21pins serve --port 8787
```

## Web app usage

### OpenAI SDK pattern (OpenAI/OpenRouter/Ollama via provider/model prefix)

Use `provider/model` format in the model field.

```ts
import OpenAI from "openai";

const client = new OpenAI({
  apiKey: process.env.PINS21_TOKEN,
  baseURL: process.env.PINS21_BASE_URL || "http://127.0.0.1:8787/v1",
});

const resp = await client.chat.completions.create({
  model: "openai/gpt-4o-mini", // or openrouter/openai/gpt-4.1-mini, ollama/llama3.2
  messages: [{ role: "user", content: "hello" }],
});
```

### Provider passthrough pattern

```bash
curl -X POST "http://127.0.0.1:8787/v1/providers/anthropic/v1/messages" \
  -H "Authorization: Bearer $PINS21_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-3-5-sonnet-20241022","max_tokens":256,"messages":[{"role":"user","content":"hello"}]}'
```

## Grant + pin workflow (Phase 1)

Create a canonical grant:

```bash
./21pins grant create \
  --sub ck_sub_abc \
  --capabilities llm.chat \
  --data-classes public \
  --targets openrouter \
  --budget-limit-cents 10000 \
  --budget-window-minutes 1440 \
  --approval-threshold-cents 5000
```

Export a signed operational credential (default TTL 15 minutes):

```bash
./21pins grant export <grant_id> --ttl-minutes 15
```

Evaluate an action and emit an execution receipt:

```bash
./21pins evaluate \
  --grant <grant_id> \
  --sub ck_sub_abc \
  --capability llm.chat \
  --data-class public \
  --target openrouter \
  --cost-cents 250
```

If pin 7 requires approval, resolve it manually:

```bash
./21pins approvals list --grant <grant_id>
./21pins approvals approve <approval_id> --approver-sub ck_sub_admin --reason "reviewed"
```

Then re-run with approval:

```bash
./21pins evaluate \
  --grant <grant_id> \
  --sub ck_sub_abc \
  --capability llm.chat \
  --data-class public \
  --target openrouter \
  --cost-cents 250 \
  --approval-id <approval_id>
```

Fetch/export receipts:

```bash
./21pins receipts list --grant <grant_id>
./21pins receipts get <receipt_id>
./21pins receipts export <receipt_id> --out ./receipt.json
```

`receipts get` returns a compliance-focused artifact with signature and verification status.

## Security notes

- v1 is local-file storage (`0600`) + per-app access tokens.
- Gateway only listens on `127.0.0.1`.
- Canonical grant IDs are the revocation/audit source of truth.
- Signed grant exports are short-lived operational credentials (15m default TTL).
- Pin 7 is enforced: threshold-crossing actions require explicit approval before they can pass.
- Next milestone: encrypted vault + ConsentKeys CLI integration for stronger custody guarantees.

## Commands

```text
init
status
key providers
key set <provider> --value <apiKey>
key list
key history <provider>
key rotate start <provider> --value <apiKey>
key rotate verify <provider>
key rotate commit <provider> [--keep-previous-hours 24]
key rotate rollback <provider>
key revoke <provider> --previous
key revoke <provider> --key-id <id>
token create <name> [--scopes proxy:chat,proxy:providers]
token list
token revoke <token>
grant create --sub <ck_sub> --capabilities a,b --data-classes a,b --targets a,b [--budget-limit-cents 10000] [--budget-window-minutes 1440] [--approval-threshold-cents 0]
grant inspect <grant-id>
grant list
grant revoke <grant-id>
grant export <grant-id> [--ttl-minutes 15]
evaluate --grant <grant-id> --sub <ck_sub> --capability <cap> --data-class <class> --target <vendor> [--cost-cents N] [--approval-id <id>] [--json]
receipts get <receipt-id>
receipts list [--grant <grant-id>]
receipts export <receipt-id> [--out path]
approvals get <approval-id>
approvals list [--grant <grant-id>]
approvals approve <approval-id> --approver-sub <ck_sub> [--reason text]
approvals reject <approval-id> --approver-sub <ck_sub> [--reason text]
models sync [--provider <provider>]
models list [--provider <provider>] [--search text] [--json]
models choose [--provider <provider>] [--search text] [--index N]
serve [--port 8787]
```

Schema reference: `docs/phase1-schemas.md`

## Env vars

- `PINS21_STATE_PATH`
