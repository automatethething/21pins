# Pi → 21pins → OpenRouter Usage Ledger Design

**Date:** 2026-06-05  
**Repo:** `/Users/claw/flowstate/repos/21pins`  
**Scope:** First hardening slice for making 21pins excellent with one LLM path before mandating it across Pi.

## Goal

Make one path work reliably end-to-end: **Pi uses 21pins as an OpenAI-compatible provider, 21pins routes to OpenRouter, and the 21pins web UI shows token usage and estimated API cost for those requests.**

This is deliberately narrower than full Pi adoption, cmux tracking, browser/subscription tracking, or multi-provider observability.

## Non-goals for this slice

- Do not mandate 21pins for all Pi usage yet.
- Do not instrument `pi-cmux` yet.
- Do not track Claude/Gemini/Cursor subscription usage yet.
- Do not build team billing, PayRails, hosted sync, or a cloud dashboard.
- Do not require perfect OpenRouter pricing for every model before the first UI works.
- Do not modify Pi core unless a tiny config/example is unavoidable.

## Primary user flow

1. User stores OpenRouter key in 21pins:
   ```bash
   ./21pins key set openrouter --value "$OPENROUTER_API_KEY"
   ```
2. User creates a 21pins app token for Pi:
   ```bash
   ./21pins token create pi --scopes proxy:chat,proxy:providers,usage:read
   ```
3. User configures Pi provider:
   ```json
   {
     "providers": {
       "pins21": {
         "baseUrl": "http://127.0.0.1:8787/v1",
         "api": "openai-completions",
         "apiKey": "$PINS21_TOKEN",
         "models": [
           {
             "id": "openrouter/openai/gpt-4o-mini",
             "name": "21pins · OpenRouter · GPT-4o Mini",
             "input": ["text", "image"],
             "reasoning": false,
             "contextWindow": 128000,
             "maxTokens": 16384,
             "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 }
           }
         ]
       }
     }
   }
   ```
4. User runs Pi with the `pins21` provider.
5. 21pins forwards the request to OpenRouter.
6. 21pins records a usage event from the upstream response. For streaming requests, 21pins requests OpenRouter usage-in-stream data and records the final usage chunk when present.
7. User opens a loopback-only 21pins web UI, pastes the same Pi token when prompted, and sees the request, model, token counts, and cost estimate.

## Architecture

### Existing pieces to reuse

- `internal/gateway/server.go`
  - OpenAI-compatible `/v1/chat/completions`
  - provider/model splitting
  - token authentication
  - forwarding to OpenRouter
  - policy receipt creation when `X-21Pins-*` headers are present
- `internal/store/store.go`
  - local state file
  - token records
  - model catalogs
- `website/`
  - static marketing page only; keep separate from the local app UI unless the current codebase strongly favors reuse

### New pieces

#### 1. Usage event model

Add a local usage ledger separate from policy receipts.

Suggested type:

```go
type UsageEvent struct {
    ID              string    `json:"usage_id"`
    CreatedAt       time.Time `json:"created_at"`
    Source          string    `json:"source"` // pi for this slice
    Provider        string    `json:"provider"` // openrouter
    Model           string    `json:"model"` // openai/gpt-4o-mini
    RequestedModel  string    `json:"requested_model"` // openrouter/openai/gpt-4o-mini
    AppTokenName    string    `json:"app_token_name,omitempty"`
    BillingMode     string    `json:"billing_mode"` // api for OpenRouter
    PromptTokens    int64     `json:"prompt_tokens"`
    CompletionTokens int64    `json:"completion_tokens"`
    CacheReadTokens int64     `json:"cache_read_tokens,omitempty"`
    CacheWriteTokens int64    `json:"cache_write_tokens,omitempty"`
    TotalTokens     int64     `json:"total_tokens"`
    EstimatedCostMicros int64 `json:"estimated_cost_micros"`
    Currency        string    `json:"currency"` // USD
    PricingSource   string    `json:"pricing_source"` // openrouter_catalog|static|unknown
    RequestID       string    `json:"request_id,omitempty"`
    ReceiptID       string    `json:"receipt_id,omitempty"`
}
```

Keep this distinct from `policy.Receipt` because usage may exist without policy headers, and policy receipts may exist for non-LLM actions later.

#### 2. Usage capture in gateway forwarding

For OpenRouter chat responses:

- Preserve status code, headers, and the response format Pi expects.
- Non-streaming (`stream` absent or `false`): read the upstream JSON body before writing it to the client, then write the original body unchanged.
- Streaming (`stream: true`): merge `stream_options.include_usage = true` into the forwarded OpenRouter request while preserving any caller-supplied `stream_options` fields, tee SSE frames to the client as they arrive, and parse the final usage-bearing frame when present.
- For 2xx JSON or SSE usage-bearing frames, parse:
  - `id`
  - `model`
  - `usage.prompt_tokens`
  - `usage.completion_tokens`
  - `usage.total_tokens`
  - any OpenRouter/provider cache-token variants when present
- Record a usage event for every successful OpenRouter chat response. If usage fields are missing, record a zero-token event with `pricing_source: "unknown"` and a warning flag/message so the UI reveals the gap.
- Do not record failed requests as billable usage in v1. Failed request auditing can be added later.

#### 3. Cost estimation

Use API billing mode for OpenRouter.

Order of pricing sources:

1. OpenRouter model catalog pricing if available after `models sync --provider openrouter`.
2. Small static fallback table for the first supported model(s), starting with `openai/gpt-4o-mini`.
3. Unknown pricing with zero estimated cost and a visible UI warning.

Extend the existing model catalog schema for OpenRouter pricing. `ProviderModel` should gain optional fields such as:

```go
PromptPriceMicrosPerMillion     int64 `json:"prompt_price_micros_per_million,omitempty"`
CompletionPriceMicrosPerMillion int64 `json:"completion_price_micros_per_million,omitempty"`
PricingSource                   string `json:"pricing_source,omitempty"`
```

The OpenRouter sync parser should read the provider's prompt/completion pricing fields when present, convert them into micros per million tokens, and leave fields empty when pricing is missing or unparsable.

Store cost in micros of USD to avoid float drift:

- `$1.23` = `1_230_000` micros
- cost formula: `(promptTokens * promptPriceMicrosPerMillion + completionTokens * completionPriceMicrosPerMillion) / 1_000_000`
- integer division should round down; UI formatting can show `<$0.000001` only later if needed

Static fallback for this slice:

- `openai/gpt-4o-mini`: prompt `$0.15 / 1M tokens` = `150_000` micros per million; completion `$0.60 / 1M tokens` = `600_000` micros per million.

For this slice, one model with correct known pricing is enough if tests cover unknown pricing gracefully.

#### 4. App token/source attribution

`ValidateToken` currently returns a boolean. The usage ledger needs a token identity.

Add a store helper that resolves the bearer token to its token record when valid for a scope. Use the token `Name` as `AppTokenName`.

For this slice:

- If the token name is `pi`, set `Source: "pi"`.
- Otherwise set `Source: "api"` or the token name.
- Do not require a new Pi-specific header.

#### 5. Local web UI

Add local usage endpoints to the 21pins gateway:

- `GET /ui` — simple local HTML dashboard, loopback-only. If the gateway is bound to `0.0.0.0`, this endpoint must reject non-loopback remote addresses with `403`. The page should not embed secrets; it should prompt for a 21pins token and keep it in browser memory for same-origin `/v1/usage` fetches.
- `GET /v1/usage` — JSON list/summary endpoint. It must be protected by bearer auth with a new `usage:read` scope, and it must also reject non-loopback remote addresses unless a future explicit LAN dashboard flag is added.

The existing permissive CORS behavior must not make usage data readable from arbitrary websites. `/v1/usage` should either omit wildcard CORS or only allow it for authenticated loopback requests.

The first UI should show:

- totals row:
  - requests
  - prompt tokens
  - completion tokens
  - total tokens
  - estimated cost
- table columns:
  - time
  - source/app token
  - provider
  - model
  - prompt tokens
  - completion tokens
  - total tokens
  - estimated cost
  - pricing source
  - request/receipt id

Keep the UI intentionally plain. It is an operator console, not the marketing site.

#### 6. CLI helpers

Add one CLI command if useful:

```bash
./21pins usage list
./21pins usage summary
```

This is optional for v1 if the web UI and JSON endpoint are enough. Tests should decide whether it is cheap to include.

## Data flow

```text
Pi request
  ↓
21pins token auth
  ↓
provider/model split: openrouter/openai/gpt-4o-mini
  ↓
optional policy enforcement from X-21Pins-* headers
  ↓
forward to OpenRouter /api/v1/chat/completions
  ↓
read non-stream JSON response OR tee streaming SSE response
  ↓
extract usage + model + request id when available
  ↓
estimate cost
  ↓
persist UsageEvent
  ↓
return original OpenAI-compatible response to Pi
  ↓
web UI prompts for a usage-scoped token, then reads /v1/usage with Authorization: Bearer <token>
```

## Error handling

- If OpenRouter returns invalid JSON, forward the response unchanged and skip usage recording.
- If usage parsing fails on a successful OpenRouter request, record an event with model/request metadata where available, zero tokens, `pricing_source: "unknown"`, and a visible warning.
- If ledger persistence fails, log the error but do not fail the model response.
- If pricing is unknown, show `pricing_source: unknown` and estimated cost `$0.00` with a warning marker.
- If `/ui` or `/v1/usage` is requested from a non-loopback address, return `403`.
- If token attribution fails unexpectedly after auth passed, record `app_token_name: "unknown"`.

## Testing strategy

### Unit tests

- Parse OpenAI/OpenRouter usage bodies into normalized usage events.
- Estimate cost from known pricing.
- Unknown pricing returns zero cost and `unknown` source.
- Token lookup returns token name for valid bearer token.

### Gateway tests

- Mock OpenRouter upstream returns usage JSON.
- 21pins forwards response unchanged.
- 21pins records one usage event with model, token counts, source `pi`, billing mode `api`, and estimated cost.
- Failed upstream response does not record billable usage.
- Missing usage object on a successful OpenRouter response records a visible zero-token event with `pricing_source: "unknown"`.
- Streaming response test verifies SSE is forwarded and the final usage frame is captured when present, including when the frame arrives split across multiple network reads.

### UI tests

- `/v1/usage` with a token scoped `usage:read` returns totals and events.
- `/v1/usage` without `usage:read` returns `401` or `403`.
- `/ui` includes core labels: `21pins usage`, `Prompt tokens`, `Completion tokens`, `Estimated cost`.
- `/ui` and `/v1/usage` reject simulated non-loopback requests.

### Manual smoke test

```bash
./21pins key set openrouter --value "$OPENROUTER_API_KEY"
TOKEN=$(./21pins token create pi --scopes proxy:chat,proxy:providers,usage:read | tail -1)
PINS21_TOKEN="$TOKEN" ./21pins serve --port 8787
pi --provider pins21 --model openrouter/openai/gpt-4o-mini "Say pong"
curl -H "Authorization: Bearer $PINS21_TOKEN" http://127.0.0.1:8787/v1/usage
open http://127.0.0.1:8787/ui
```

## Acceptance criteria

This slice is done when:

1. A real Pi smoke test can call `openrouter/openai/gpt-4o-mini` through 21pins and receive an assistant message without Pi-side parsing errors.
2. Gateway tests prove non-streaming OpenAI-compatible responses are forwarded with the same status, content type, and JSON body returned by the mocked OpenRouter upstream.
3. Gateway tests prove streaming SSE responses are forwarded and usage is captured from the final usage chunk when present.
4. 21pins records prompt/completion/total tokens from successful OpenRouter responses, or a visible zero-token warning event when usage is absent.
5. 21pins estimates API cost for `openai/gpt-4o-mini` from catalog pricing or the static fallback.
6. `/v1/usage` returns authenticated totals and event rows containing source/app token, provider, model, tokens, billing mode, estimated cost, and pricing source.
7. `/v1/usage` rejects non-loopback requests and rejects tokens without `usage:read`.
8. `/v1/usage` is not wildcard-readable through CORS; tests prove arbitrary origins cannot read usage data without valid bearer auth.
9. `/ui` prompts for a token, shows the request and totals after token entry, and rejects non-loopback requests.
10. Unknown model pricing is visible and non-fatal.
11. Existing gateway auth/policy behavior still passes tests.

## Future slices

After this works well:

1. Add more OpenRouter model pricing coverage.
2. Package Pi provider registration as a 21pins Pi package.
3. Add `pi-cmux` usage events for `/cmux open/send/read` and later parse visible CLI token summaries where available.
4. Add subscription billing mode for browser-backed or CLI-subscription tools.
5. Add cmux-specific dashboard rows: agent, workspace, prompt sends, read calls, inferred or reported usage.
6. Add hosted control plane sync only after local-first observability feels solid.
