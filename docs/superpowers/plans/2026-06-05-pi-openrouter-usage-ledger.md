# Pi OpenRouter Usage Ledger Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `Pi → 21pins → OpenRouter` record token usage and estimated API cost, then display it in a local 21pins usage UI.

**Architecture:** Add a usage ledger to the existing local JSON store, capture OpenRouter usage in the gateway while preserving OpenAI-compatible responses, estimate cost from catalog/static pricing, expose authenticated loopback-only usage endpoints, and document the Pi configuration. Keep this slice local-first and OpenRouter-only.

**Tech Stack:** Go standard library HTTP/JSON/SSE, existing 21pins store/gateway/policy packages, `go test ./...`, local Pi smoke test.

---

## File structure

- Modify `internal/store/store.go`
  - Add `UsageEvent` to `State`.
  - Add token lookup helper for attribution.
  - Add usage persistence/list/summary helpers.
  - Extend `ProviderModel` pricing fields.
- Create `internal/usage/usage.go`
  - Normalize OpenAI/OpenRouter usage payloads.
  - Estimate costs.
  - Parse streaming SSE usage frames.
  - Format usage summaries.
- Create `internal/usage/usage_test.go`
  - Unit tests for parsing, cost estimation, missing usage, static fallback, SSE frame parsing.
- Modify `cmd/21pins/models.go`
  - Parse OpenRouter pricing into model catalog fields.
- Modify `internal/gateway/server.go`
  - Capture authenticated token record.
  - Capture OpenRouter usage for non-streaming and streaming chat responses.
  - Add `/v1/usage` and `/ui` endpoints with loopback/security constraints.
  - Avoid wildcard-readable CORS for usage endpoint.
- Modify `internal/gateway/server_test.go`
  - Gateway tests for usage capture, response preservation, auth, loopback checks, CORS safety, streaming SSE capture.
- Modify `README.md` and `docs/pi-21pins-json-demo.md`
  - Document `usage:read`, Pi provider config, `/ui`, and `/v1/usage`.
- Update `ideas/PORTFOLIO.md` after implementation changes reality.

## Notes for implementation workers

- Existing repo has uncommitted work from the prior 21pins hardening session. Do **not** discard it.
- Keep policy receipts and usage ledger separate.
- Preserve client responses exactly where tests say exact preservation is required.
- Do not add PayRails, hosted sync, cmux tracking, or browser/subscription tracking in this slice.
- Use TDD for each task: test red, implementation green, then refactor.

---

### Task 1: Add usage event storage and token attribution

**Files:**
- Modify: `internal/store/store.go`
- Test: `internal/store/store_test.go`

- [ ] **Step 1: Write failing tests for usage event persistence**

Add tests like:

```go
func TestStorePersistsUsageEvents(t *testing.T) {
    tempDir := t.TempDir()
    s, err := New(filepath.Join(tempDir, "state.json"))
    if err != nil { t.Fatalf("New failed: %v", err) }

    event := UsageEvent{
        ID: "use_123",
        CreatedAt: time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC),
        Source: "pi",
        Provider: "openrouter",
        Model: "openai/gpt-4o-mini",
        RequestedModel: "openrouter/openai/gpt-4o-mini",
        AppTokenName: "pi",
        BillingMode: "api",
        PromptTokens: 10,
        CompletionTokens: 5,
        TotalTokens: 15,
        EstimatedCostMicros: 6,
        Currency: "USD",
        PricingSource: "static",
    }
    if err := s.AddUsageEvent(event); err != nil { t.Fatalf("AddUsageEvent failed: %v", err) }

    reopened, err := New(filepath.Join(tempDir, "state.json"))
    if err != nil { t.Fatalf("reopen failed: %v", err) }
    events := reopened.ListUsageEvents()
    if len(events) != 1 { t.Fatalf("expected 1 event, got %d", len(events)) }
    if events[0].Model != "openai/gpt-4o-mini" { t.Fatalf("unexpected event: %+v", events[0]) }
}
```

- [ ] **Step 2: Write failing tests for token lookup**

```go
func TestValidateTokenRecordReturnsTokenName(t *testing.T) {
    s, _ := New(filepath.Join(t.TempDir(), "state.json"))
    raw, err := s.CreateToken("pi", []string{"proxy:chat", "usage:read"})
    if err != nil { t.Fatal(err) }

    record, ok := s.ValidateTokenRecord(raw, "proxy:chat")
    if !ok { t.Fatal("expected token to validate") }
    if record.Name != "pi" { t.Fatalf("expected pi token, got %q", record.Name) }
}
```

- [ ] **Step 3: Run tests and verify they fail**

Run:

```bash
go test ./internal/store -run 'TestStorePersistsUsageEvents|TestValidateTokenRecordReturnsTokenName' -v
```

Expected: FAIL because `UsageEvent`, `AddUsageEvent`, `ListUsageEvents`, and `ValidateTokenRecord` do not exist.

- [ ] **Step 4: Implement storage primitives**

In `internal/store/store.go`:

```go
type State struct {
    ProviderKeys    map[string]string         `json:"provider_keys"`
    ProviderKeySets map[string]ProviderKeySet `json:"provider_keysets,omitempty"`
    ModelCatalogs   map[string]ModelCatalog   `json:"model_catalogs,omitempty"`
    Tokens          []TokenRecord             `json:"tokens"`
    Grants          []policy.Grant            `json:"grants,omitempty"`
    Receipts        []policy.Receipt          `json:"receipts,omitempty"`
    Approvals       []policy.ApprovalRequest  `json:"approvals,omitempty"`
    SigningKeys     SigningKeys               `json:"signing_keys,omitempty"`
    UsageEvents     []UsageEvent              `json:"usage_events,omitempty"`
}

type UsageEvent struct {
    ID                         string    `json:"usage_id"`
    CreatedAt                  time.Time `json:"created_at"`
    Source                     string    `json:"source"`
    Provider                   string    `json:"provider"`
    Model                      string    `json:"model"`
    RequestedModel             string    `json:"requested_model"`
    AppTokenName               string    `json:"app_token_name,omitempty"`
    BillingMode                string    `json:"billing_mode"`
    PromptTokens               int64     `json:"prompt_tokens"`
    CompletionTokens           int64     `json:"completion_tokens"`
    CacheReadTokens            int64     `json:"cache_read_tokens,omitempty"`
    CacheWriteTokens           int64     `json:"cache_write_tokens,omitempty"`
    TotalTokens                int64     `json:"total_tokens"`
    EstimatedCostMicros        int64     `json:"estimated_cost_micros"`
    Currency                   string    `json:"currency"`
    PricingSource              string    `json:"pricing_source"`
    Warning                    string    `json:"warning,omitempty"`
    RequestID                  string    `json:"request_id,omitempty"`
    ReceiptID                  string    `json:"receipt_id,omitempty"`
}
```

Add nil initialization in `reloadLocked`/`loadOrInit` as needed.

Add:

```go
func (s *Store) AddUsageEvent(event UsageEvent) error { ... }
func (s *Store) ListUsageEvents() []UsageEvent { ... }
func (s *Store) ValidateTokenRecord(raw, requiredScope string) (TokenRecord, bool) { ... }
```

`ValidateTokenRecord` should reuse `tokenHash`, reload latest state like `ValidateToken`, update `LastUsedAt`, persist, and return a copy of the matching token record.

- [ ] **Step 5: Run store tests**

Run:

```bash
go test ./internal/store -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/store/store.go internal/store/store_test.go
git commit -m "feat(store): add usage ledger storage"
```

---

### Task 2: Add usage parsing and cost estimation package

**Files:**
- Create: `internal/usage/usage.go`
- Test: `internal/usage/usage_test.go`
- Modify: `go.mod` only if strictly required; prefer standard library only.

- [ ] **Step 1: Write failing parser tests**

Create `internal/usage/usage_test.go`:

```go
func TestParseChatCompletionUsage(t *testing.T) {
    body := []byte(`{
      "id":"gen_123",
      "model":"openai/gpt-4o-mini",
      "usage":{"prompt_tokens":1000,"completion_tokens":200,"total_tokens":1200}
    }`)
    parsed, ok := ParseChatUsage(body)
    if !ok { t.Fatal("expected usage") }
    if parsed.RequestID != "gen_123" || parsed.Model != "openai/gpt-4o-mini" { t.Fatalf("bad parsed: %+v", parsed) }
    if parsed.PromptTokens != 1000 || parsed.CompletionTokens != 200 || parsed.TotalTokens != 1200 { t.Fatalf("bad tokens: %+v", parsed) }
}

func TestParseChatCompletionUsageMissingUsage(t *testing.T) {
    parsed, ok := ParseChatUsage([]byte(`{"id":"gen_123","model":"unknown/model"}`))
    if !ok { t.Fatal("expected visible zero-token usage") }
    if parsed.Warning == "" || parsed.TotalTokens != 0 { t.Fatalf("expected warning zero event: %+v", parsed) }
}

func TestParseChatCompletionUsageCacheTokenDetailVariants(t *testing.T) {
    body := []byte(`{
      "id":"gen_123",
      "model":"openai/gpt-4o-mini",
      "usage":{
        "prompt_tokens":100,
        "completion_tokens":20,
        "total_tokens":120,
        "prompt_tokens_details":{"cached_tokens":30},
        "cache_creation_input_tokens":7
      }
    }`)
    parsed, ok := ParseChatUsage(body)
    if !ok { t.Fatal("expected usage") }
    if parsed.CacheReadTokens != 30 || parsed.CacheWriteTokens != 7 {
        t.Fatalf("expected cache tokens, got %+v", parsed)
    }
}

func TestParseChatCompletionUsageCacheTokenTopLevelVariants(t *testing.T) {
    body := []byte(`{
      "id":"gen_456",
      "model":"openai/gpt-4o-mini",
      "usage":{
        "prompt_tokens":100,
        "completion_tokens":20,
        "total_tokens":120,
        "cache_read_input_tokens":11,
        "cache_write_input_tokens":13
      }
    }`)
    parsed, ok := ParseChatUsage(body)
    if !ok { t.Fatal("expected usage") }
    if parsed.CacheReadTokens != 11 || parsed.CacheWriteTokens != 13 {
        t.Fatalf("expected top-level cache tokens, got %+v", parsed)
    }
}
```

Cache-token variants to support in v1:
- read/cache-hit: `usage.prompt_tokens_details.cached_tokens`, `usage.cache_read_input_tokens`
- write/cache-creation: `usage.cache_creation_input_tokens`, `usage.cache_write_input_tokens`

- [ ] **Step 2: Write failing cost tests**

```go
func TestEstimateCostUsesStaticOpenRouterFallback(t *testing.T) {
    cost := EstimateOpenRouterCostMicros("openai/gpt-4o-mini", 1_000_000, 1_000_000, nil)
    if cost.Micros != 750_000 { t.Fatalf("expected 750000 micros, got %d", cost.Micros) }
    if cost.Source != "static" { t.Fatalf("expected static, got %s", cost.Source) }
}

func TestEstimateCostUnknownModel(t *testing.T) {
    cost := EstimateOpenRouterCostMicros("unknown/model", 100, 100, nil)
    if cost.Micros != 0 || cost.Source != "unknown" { t.Fatalf("unexpected cost: %+v", cost) }
}

func TestEstimateCostUsesCatalogPrice(t *testing.T) {
    price := Price{PromptMicrosPerMillion: 10, CompletionMicrosPerMillion: 20, Source: "openrouter_catalog"}
    cost := EstimateOpenRouterCostMicros("any/model", 1_000_000, 2_000_000, &price)
    if cost.Micros != 50 || cost.Source != "openrouter_catalog" { t.Fatalf("unexpected cost: %+v", cost) }
}
```

- [ ] **Step 3: Write failing SSE tests**

```go
func TestParseSSEUsageFrames(t *testing.T) {
    stream := "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
        "data: {\"id\":\"gen_1\",\"model\":\"openai/gpt-4o-mini\",\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2,\"total_tokens\":6}}\n\n" +
        "data: [DONE]\n\n"
    parsed, ok := ParseSSEUsage([]byte(stream))
    if !ok { t.Fatal("expected usage") }
    if parsed.TotalTokens != 6 { t.Fatalf("bad parsed: %+v", parsed) }
}
```

- [ ] **Step 4: Run tests and verify they fail**

```bash
go test ./internal/usage -v
```

Expected: FAIL because package/functions do not exist.

- [ ] **Step 5: Implement usage package**

Create `internal/usage/usage.go` with:

```go
type ParsedUsage struct {
    RequestID string
    Model string
    PromptTokens int64
    CompletionTokens int64
    CacheReadTokens int64
    CacheWriteTokens int64
    TotalTokens int64
    Warning string
}

type CostEstimate struct {
    Micros int64
    Source string
    Currency string
}

type Price struct {
    PromptMicrosPerMillion int64
    CompletionMicrosPerMillion int64
    Source string
}
```

Functions:

```go
func ParseChatUsage(body []byte) (ParsedUsage, bool)
func ParseSSEUsage(body []byte) (ParsedUsage, bool)
func EstimateOpenRouterCostMicros(model string, promptTokens, completionTokens int64, catalogPrice *Price) CostEstimate
func MergeStreamOptionsIncludeUsage(payload map[string]any)
```

When gateway uses catalog pricing, convert `store.ProviderModel` fields into `usage.Price`:

```go
price := &usage.Price{
    PromptMicrosPerMillion: model.PromptPriceMicrosPerMillion,
    CompletionMicrosPerMillion: model.CompletionPriceMicrosPerMillion,
    Source: model.PricingSource,
}
```

Only pass catalog price when both prompt and completion prices are > 0.

Implementation notes:
- `ParseChatUsage` should return `ok=true` for valid JSON with `id`/`model` but missing usage, with warning `usage_missing`.
- `ParseSSEUsage` should parse complete SSE frames from bytes using `\n\n` frame separators. For streaming across network reads, gateway can accumulate bytes and call this at the end in Task 4.
- Static fallback: `openai/gpt-4o-mini`, prompt `150_000`, completion `600_000` micros per million.
- Formula: `(prompt*promptPrice + completion*completionPrice)/1_000_000`.
- Cache reads/writes are recorded but not charged in this slice unless OpenRouter catalog later exposes separate cache pricing.

- [ ] **Step 6: Run usage tests**

```bash
go test ./internal/usage -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/usage/usage.go internal/usage/usage_test.go
git commit -m "feat(usage): parse OpenRouter token usage"
```

---

### Task 3: Extend OpenRouter model catalog pricing

**Files:**
- Modify: `internal/store/store.go`
- Modify: `cmd/21pins/models.go`
- Test: `internal/store/models_catalog_test.go`
- Test: add focused tests near `cmd/21pins/models.go` if the current package structure permits; otherwise test through a small exported/unexported helper in `cmd/21pins`.

- [ ] **Step 1: Write failing catalog pricing test**

In `internal/store/models_catalog_test.go`:

```go
func TestModelCatalogStoresPricing(t *testing.T) {
    s, _ := New(filepath.Join(t.TempDir(), "state.json"))
    models := []ProviderModel{{
        ID: "openai/gpt-4o-mini",
        Name: "GPT-4o mini",
        PromptPriceMicrosPerMillion: 150_000,
        CompletionPriceMicrosPerMillion: 600_000,
        PricingSource: "openrouter_catalog",
    }}
    if err := s.SaveModelCatalog("openrouter", models); err != nil { t.Fatal(err) }
    catalog, ok := s.GetModelCatalog("openrouter")
    if !ok { t.Fatal("missing catalog") }
    got := catalog.Models[0]
    if got.PromptPriceMicrosPerMillion != 150_000 || got.CompletionPriceMicrosPerMillion != 600_000 {
        t.Fatalf("pricing not persisted: %+v", got)
    }
}
```

- [ ] **Step 2: Write failing OpenRouter parser test**

If `discoveredModel` can carry pricing, add a test in `cmd/21pins/models_test.go`:

```go
func TestParseOpenRouterPricing(t *testing.T) {
    price := parseOpenRouterPriceToMicrosPerMillion("0.00000015")
    if price != 150_000 { t.Fatalf("expected 150000, got %d", price) }
}
```

- [ ] **Step 3: Run failing tests**

```bash
go test ./internal/store -run TestModelCatalogStoresPricing -v
go test ./cmd/21pins -run TestParseOpenRouterPricing -v
```

Expected: FAIL due to missing fields/helper.

- [ ] **Step 4: Implement pricing fields**

In `internal/store/store.go`, extend `ProviderModel`:

```go
type ProviderModel struct {
    ID string `json:"id"`
    Name string `json:"name,omitempty"`
    ContextWindow int `json:"context_window,omitempty"`
    PromptPriceMicrosPerMillion int64 `json:"prompt_price_micros_per_million,omitempty"`
    CompletionPriceMicrosPerMillion int64 `json:"completion_price_micros_per_million,omitempty"`
    PricingSource string `json:"pricing_source,omitempty"`
}
```

Update any conversion between `discoveredModel` and `ProviderModel` in `cmd/21pins/models.go`.

- [ ] **Step 5: Implement OpenRouter pricing parsing**

OpenRouter model records commonly include `pricing.prompt` and `pricing.completion` as decimal dollars per token. Parse them with standard library decimal-safe enough for this use:

```go
func parseOpenRouterPriceToMicrosPerMillion(raw string) int64 {
    f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
    if err != nil || f <= 0 { return 0 }
    return int64(f * 1_000_000 * 1_000_000)
}
```

This converts dollars/token → micros/million tokens. Tests should tolerate exact static examples. If floating precision causes off-by-one, add rounding with `math.Round`.

Update `fetchOpenRouterModels` item struct:

```go
type item struct {
    ID string `json:"id"`
    Name string `json:"name"`
    ContextLength int `json:"context_length"`
    Pricing struct {
        Prompt string `json:"prompt"`
        Completion string `json:"completion"`
    } `json:"pricing"`
}
```

- [ ] **Step 6: Run tests**

```bash
go test ./internal/store ./cmd/21pins -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/store/store.go internal/store/models_catalog_test.go cmd/21pins/models.go cmd/21pins/models_test.go
git commit -m "feat(models): store OpenRouter pricing"
```

---

### Task 4: Capture non-streaming OpenRouter usage in gateway

**Files:**
- Modify: `internal/gateway/server.go`
- Test: `internal/gateway/server_test.go`

- [ ] **Step 1: Write failing gateway test for response preservation and usage event**

Add:

```go
func TestGatewayRecordsOpenRouterUsageForPiToken(t *testing.T) {
    upstreamBody := `{"id":"gen_123","model":"openai/gpt-4o-mini","usage":{"prompt_tokens":1000,"completion_tokens":200,"total_tokens":1200},"choices":[{"message":{"role":"assistant","content":"pong"}}]}`
    upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/api/v1/chat/completions" { t.Fatalf("bad path: %s", r.URL.Path) }
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(upstreamBody))
    }))
    defer upstream.Close()

    s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
    _ = s.SetProviderKey("openrouter", "or-key")
    token, _ := s.CreateToken("pi", []string{"proxy:chat", "usage:read"})
    g := NewServer(s, Config{OpenRouterBaseURL: upstream.URL})

    req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"openrouter/openai/gpt-4o-mini","messages":[{"role":"user","content":"ping"}]}`))
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")
    w := httptest.NewRecorder()
    g.Handler().ServeHTTP(w, req)

    if w.Code != http.StatusOK { t.Fatalf("status=%d body=%s", w.Code, w.Body.String()) }
    if strings.TrimSpace(w.Body.String()) != upstreamBody { t.Fatalf("response changed: %s", w.Body.String()) }

    events := s.ListUsageEvents()
    if len(events) != 1 { t.Fatalf("expected 1 usage event, got %d", len(events)) }
    event := events[0]
    if event.Source != "pi" || event.AppTokenName != "pi" || event.Provider != "openrouter" { t.Fatalf("bad attribution: %+v", event) }
    if event.PromptTokens != 1000 || event.CompletionTokens != 200 || event.TotalTokens != 1200 { t.Fatalf("bad usage: %+v", event) }
    if event.EstimatedCostMicros <= 0 || event.BillingMode != "api" { t.Fatalf("bad cost: %+v", event) }
}
```

- [ ] **Step 2: Write failing missing-usage test**

```go
func TestGatewayRecordsZeroWarningWhenOpenRouterUsageMissing(t *testing.T) { ... }
```

Assert one usage event with `TotalTokens == 0`, `PricingSource == "unknown"`, and `Warning != ""`.

- [ ] **Step 3: Write failing failed-upstream test**

```go
func TestGatewayDoesNotRecordUsageForFailedOpenRouterResponse(t *testing.T) {
    upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        http.Error(w, "upstream failed", http.StatusTooManyRequests)
    }))
    defer upstream.Close()

    s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
    _ = s.SetProviderKey("openrouter", "or-key")
    token, _ := s.CreateToken("pi", []string{"proxy:chat", "usage:read"})
    g := NewServer(s, Config{OpenRouterBaseURL: upstream.URL})

    req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"openrouter/openai/gpt-4o-mini","messages":[{"role":"user","content":"ping"}]}`))
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")
    w := httptest.NewRecorder()
    g.Handler().ServeHTTP(w, req)

    if w.Code != http.StatusTooManyRequests { t.Fatalf("expected upstream status, got %d", w.Code) }
    if got := len(s.ListUsageEvents()); got != 0 { t.Fatalf("expected no usage events for failed upstream, got %d", got) }
}
```

- [ ] **Step 4: Run failing tests**

```bash
go test ./internal/gateway -run 'TestGatewayRecordsOpenRouterUsage|TestGatewayRecordsZeroWarning|TestGatewayDoesNotRecordUsageForFailedOpenRouterResponse' -v
```

Expected: FAIL because gateway does not record usage.

- [ ] **Step 5: Refactor auth to carry token record**

In `server.go`, introduce request context or a small wrapper type:

```go
type contextKey string
const tokenRecordContextKey contextKey = "token_record"
```

Change `withAuth` to call `ValidateTokenRecord`, put token record into context, then call next with `r.WithContext(ctx)`.

Keep old behavior/status unchanged.

- [ ] **Step 6: Add OpenRouter usage recording path**

Add a specialized forwarder for OpenAI-compatible chat:

```go
func (s *Server) forwardChat(provider, requestedModel, providerModel, target string, incoming http.Header, body []byte, w http.ResponseWriter, r *http.Request) error
```

For provider `openrouter` and non-streaming:
- perform upstream request
- read body into bytes
- copy headers/status/body to client
- if status 2xx, parse usage and persist event

For other providers, delegate to existing `forwardRequest`.

Build event:

```go
source := "api"
if token.Name == "pi" { source = "pi" } else if token.Name != "" { source = token.Name }
```

Set:
- Provider `openrouter`
- Model `providerModel`
- RequestedModel original `model`
- BillingMode `api`
- Currency `USD`

Cost source:
- catalog price if found
- static fallback if available
- unknown if no usage/pricing

- [ ] **Step 7: Run gateway tests**

```bash
go test ./internal/gateway -v
```

Expected: PASS.

- [ ] **Step 8: Run full tests**

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/gateway/server.go internal/gateway/server_test.go
git commit -m "feat(gateway): record OpenRouter usage"
```

---

### Task 5: Capture streaming OpenRouter usage

**Files:**
- Modify: `internal/gateway/server.go`
- Modify: `internal/usage/usage.go` if needed
- Test: `internal/gateway/server_test.go`

- [ ] **Step 1: Write failing streaming forwarding/capture test**

Add a test where upstream emits:

```text
data: {"choices":[{"delta":{"content":"po"}}]}

data: {"choices":[{"delta":{"content":"ng"}}]}

data: {"id":"gen_stream","model":"openai/gpt-4o-mini","usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}

data: [DONE]

```

Assert:
- Response content type is `text/event-stream` or preserves upstream.
- Response body contains all `data:` frames.
- `s.ListUsageEvents()` has one event with total tokens 6.
- Upstream request body includes `stream_options.include_usage: true`.

- [ ] **Step 2: Write failing split-frame streaming test**

Add a test where upstream writes one usage frame across two writes with a flush between writes, for example:

```go
_, _ = w.Write([]byte("data: {\"id\":\"gen_split\",\"model\":\"openai/gpt-4o-mini\",\"usage\":{"))
flusher.Flush()
_, _ = w.Write([]byte("\"prompt_tokens\":4,\"completion_tokens\":2,\"total_tokens\":6}}\n\n"))
```

Assert the client still receives the full frame and one usage event is recorded with `TotalTokens == 6`.

- [ ] **Step 3: Write failing test preserving caller stream_options**

Caller body:

```json
{"model":"openrouter/openai/gpt-4o-mini","stream":true,"stream_options":{"foo":"bar"}}
```

Assert upstream receives `stream_options.foo == "bar"` and `include_usage == true`.

- [ ] **Step 4: Run failing tests**

```bash
go test ./internal/gateway -run 'TestGatewayStreamsOpenRouterUsage|TestGatewayStreamsSplitUsageFrame|TestGatewayMergesStreamOptions' -v
```

Expected: FAIL.

- [ ] **Step 5: Implement streaming path**

Before marshal in `handleOpenAICompatChat`, if provider is OpenRouter and payload has `stream == true`, call `usage.MergeStreamOptionsIncludeUsage(payload)`.

In streaming forwarder:
- Execute request.
- Copy headers.
- Write status.
- Use `io.TeeReader` or manual loop to write bytes to response and append to a `bytes.Buffer`.
- Flush if `w` implements `http.Flusher` after each write.
- After EOF, parse accumulated SSE via `usage.ParseSSEUsage` and persist event.

- [ ] **Step 6: Run streaming tests**

```bash
go test ./internal/gateway -run 'TestGatewayStreamsOpenRouterUsage|TestGatewayStreamsSplitUsageFrame|TestGatewayMergesStreamOptions' -v
```

Expected: PASS.

- [ ] **Step 7: Run full tests**

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/gateway/server.go internal/gateway/server_test.go internal/usage/usage.go internal/usage/usage_test.go
git commit -m "feat(gateway): capture streaming OpenRouter usage"
```

---

### Task 6: Add authenticated usage API and loopback-only UI

**Files:**
- Modify: `internal/gateway/server.go`
- Test: `internal/gateway/server_test.go`

- [ ] **Step 1: Write failing `/v1/usage` auth test**

```go
func TestUsageEndpointRequiresUsageReadScope(t *testing.T) {
    s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
    token, _ := s.CreateToken("pi", []string{"proxy:chat"})
    g := NewServer(s, Config{})
    req := httptest.NewRequest(http.MethodGet, "/v1/usage", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    w := httptest.NewRecorder()
    g.Handler().ServeHTTP(w, req)
    if w.Code != http.StatusUnauthorized { t.Fatalf("expected 401, got %d", w.Code) }
}
```

- [ ] **Step 2: Write failing `/v1/usage` response test**

Seed `s.AddUsageEvent(...)`; create token with `usage:read`; request `/v1/usage`; assert JSON includes totals and one event with all required fields: `source`, `app_token_name`, `provider`, `model`, `prompt_tokens`, `completion_tokens`, `total_tokens`, `billing_mode`, `estimated_cost_micros`, and `pricing_source`.

Expected JSON shape:

```json
{
  "totals": {
    "requests": 1,
    "prompt_tokens": 10,
    "completion_tokens": 5,
    "total_tokens": 15,
    "estimated_cost_micros": 6,
    "currency": "USD"
  },
  "events": [...]
}
```

- [ ] **Step 3: Write failing loopback/CORS tests**

Tests:
- Remote address `192.168.1.5:1234` on `/v1/usage` returns 403.
- Remote address `192.168.1.5:1234` on `/ui` returns 403.
- `/v1/usage` response does not expose wildcard `Access-Control-Allow-Origin: *` even when request includes `Origin: https://evil.example`.

- [ ] **Step 4: Write failing `/ui` HTML test**

Assert `/ui` from loopback includes:
- `21pins usage`
- `Prompt tokens`
- `Completion tokens`
- `Estimated cost`
- a token input field or prompt copy (`21pins token`).

- [ ] **Step 5: Run failing tests**

```bash
go test ./internal/gateway -run 'TestUsageEndpoint|TestUI|TestUsageCORS' -v
```

Expected: FAIL because endpoints do not exist.

- [ ] **Step 6: Implement loopback helper**

```go
func isLoopbackRequest(r *http.Request) bool {
    host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil { host = r.RemoteAddr }
    ip := net.ParseIP(host)
    return ip != nil && ip.IsLoopback()
}
```

In tests, set `req.RemoteAddr` explicitly.

- [ ] **Step 7: Register routes before root and bypass global wildcard CORS**

Current `NewServer` wraps the entire mux in `withCORSHandler`, so simply avoiding `withCORS` on `/v1/usage` is not enough. Refactor global CORS into a route-aware wrapper:

```go
func (s *Server) withCORSHandler(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/v1/usage" && r.URL.Path != "/ui" {
            setCORSHeaders(w)
        }
        next.ServeHTTP(w, r)
    })
}
```

Then register:

```go
mux.HandleFunc("/ui", s.handleUsageUI)
mux.HandleFunc("/v1/usage", s.withUsageAuth(s.handleUsageAPI))
```

Do not wrap `/v1/usage` in `withCORS`; tests must prove it does not receive `Access-Control-Allow-Origin: *` for arbitrary origins. `/ui` may omit CORS entirely because it is same-origin and loopback-only.

- [ ] **Step 8: Implement `/v1/usage`**

- Require loopback.
- Require `usage:read` via `ValidateTokenRecord`.
- Build totals from `store.ListUsageEvents()`.
- Return events newest-first or stable newest-first; document through tests.

- [ ] **Step 9: Implement `/ui`**

Return simple HTML with inline JS:
- token input
- button “Load usage”
- fetch `/v1/usage` with `Authorization: Bearer ${token}`
- render totals and table

Keep the token only in JS memory, not localStorage.

- [ ] **Step 10: Run endpoint tests**

```bash
go test ./internal/gateway -run 'TestUsageEndpoint|TestUI|TestUsageCORS' -v
```

Expected: PASS.

- [ ] **Step 11: Run full tests**

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 12: Commit**

```bash
git add internal/gateway/server.go internal/gateway/server_test.go
git commit -m "feat(gateway): add local usage dashboard"
```

---

### Task 7: Add optional CLI usage commands

**Files:**
- Modify: `cmd/21pins/main.go`
- Test: if CLI command tests are not currently structured, keep this task minimal and manually verify.

- [ ] **Step 1: Decide if CLI helper is cheap**

If `main.go` can support it without a large refactor, add:

```text
usage list
usage summary
```

If this becomes intrusive, skip and rely on `/v1/usage` + `/ui` for this slice.

- [ ] **Step 2: Add usage command to help text**

Update `usage()` with:

```text
usage list
usage summary
```

- [ ] **Step 3: Implement `handleUsage`**

- `usage list`: print JSON array of usage events.
- `usage summary`: print JSON totals matching `/v1/usage` totals.

- [ ] **Step 4: Manual verify**

Run:

```bash
go run ./cmd/21pins usage list
go run ./cmd/21pins usage summary
```

Expected: valid JSON, empty arrays/totals when no events exist.

- [ ] **Step 5: Run tests**

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 6: Commit or skip explicitly**

If implemented:

```bash
git add cmd/21pins/main.go
git commit -m "feat(cli): add usage ledger commands"
```

If skipped, document skip reason in final notes.

---

### Task 8: Documentation and Pi smoke setup

**Files:**
- Modify: `README.md`
- Modify: `docs/pi-21pins-json-demo.md`
- Modify: `examples/pi-21pins-json-demo.sh`
- Modify: `/Users/claw/flowstate/ideas/PORTFOLIO.md`

- [ ] **Step 1: Update README quickstart**

Add:

```bash
./21pins token create pi --scopes proxy:chat,proxy:providers,usage:read
```

Document:

- `~/.pi/agent/models.json` provider `pins21`
- `/v1/usage`
- `/ui`
- `usage:read` scope
- OpenRouter is the first “awesome path” before cmux/subscription tracking.

- [ ] **Step 2: Update Pi demo doc**

In `docs/pi-21pins-json-demo.md`, update token creation and add usage check:

```bash
curl -H "Authorization: Bearer $PINS21_TOKEN" http://127.0.0.1:8787/v1/usage
open http://127.0.0.1:8787/ui
```

- [ ] **Step 3: Update example script**

After Pi run, fetch `/v1/usage` if token exists:

```bash
echo "[4/4] Fetching 21pins usage ledger..."
curl -fsS -H "Authorization: Bearer $PINS21_TOKEN" http://127.0.0.1:8787/v1/usage | jq .totals
```

- [ ] **Step 4: Update portfolio reality**

In `/Users/claw/flowstate/ideas/PORTFOLIO.md`, update 21pins notes to say:

- First Pi integration path now records OpenRouter token usage and estimated API cost in local 21pins usage UI.
- cmux/subscription usage remains a future slice.

- [ ] **Step 5: Run docs-adjacent verification**

```bash
go test ./...
bash -n examples/pi-21pins-json-demo.sh
```

Expected: PASS/no syntax errors.

- [ ] **Step 6: Commit**

```bash
git add README.md docs/pi-21pins-json-demo.md examples/pi-21pins-json-demo.sh /Users/claw/flowstate/ideas/PORTFOLIO.md
git commit -m "docs: document Pi OpenRouter usage ledger"
```

---

### Task 9: Real manual smoke test

**Files:**
- No required source edits unless smoke reveals bugs.

- [ ] **Step 1: Build binary**

```bash
go build -o /tmp/21pins-smoke ./cmd/21pins
```

Expected: PASS.

- [ ] **Step 2: Prepare OpenRouter key and token**

```bash
/tmp/21pins-smoke key set openrouter --value "$OPENROUTER_API_KEY"
TOKEN=$(/tmp/21pins-smoke token create pi --scopes proxy:chat,proxy:providers,usage:read | tail -1)
export PINS21_TOKEN="$TOKEN"
```

Expected: token created. If `OPENROUTER_API_KEY` unavailable, stop and report that real smoke could not run.

- [ ] **Step 3: Start gateway**

```bash
/tmp/21pins-smoke serve --port 8787
```

Use a separate terminal/session. If an existing 21pins gateway is running, stop it first or use another port and matching Pi config.

- [ ] **Step 4: Configure Pi provider**

Ensure `~/.pi/agent/models.json` includes `pins21` provider from the spec, or run Pi with existing provider if already configured.

- [ ] **Step 5: Run Pi smoke**

```bash
pi --provider pins21 --model openrouter/openai/gpt-4o-mini --no-session -p "Say exactly: pong"
```

Expected: assistant returns `pong` or a normal assistant message without Pi parse errors.

- [ ] **Step 6: Verify usage endpoint**

```bash
curl -fsS -H "Authorization: Bearer $PINS21_TOKEN" http://127.0.0.1:8787/v1/usage | jq .
```

Expected:
- at least one usage event
- provider `openrouter`
- source/app token `pi`
- model `openai/gpt-4o-mini`
- token counts present or visible zero-token warning
- estimated cost present

- [ ] **Step 7: Verify UI manually**

```bash
open http://127.0.0.1:8787/ui
```

Paste token. Expected: totals and request table render.

- [ ] **Step 8: Commit any smoke fixes**

If bugs were fixed:

```bash
git add <changed-files>
git commit -m "fix: harden Pi OpenRouter usage smoke"
```

---

### Task 10: Final verification and review

**Files:**
- All changed files.

- [ ] **Step 1: Run full automated verification**

```bash
go test ./...
bash -n examples/pi-21pins-json-demo.sh
```

Expected: PASS.

- [ ] **Step 2: Check git diff**

```bash
git status --short
git diff --stat
```

Expected: only intentional changes remain.

- [ ] **Step 3: Request code review**

Use the review loop or reviewer subagent. Review focus:

- response preservation
- token/cost correctness
- `/v1/usage` security and CORS
- loopback detection
- streaming behavior
- no secret leakage in logs/UI

- [ ] **Step 4: Fix review findings**

For each valid issue:
- write/adjust failing test
- implement minimal fix
- run targeted tests
- run `go test ./...`

- [ ] **Step 5: Final commit**

If review fixes changed code:

```bash
git add <files>
git commit -m "fix: address usage ledger review"
```

- [ ] **Step 6: Final status**

```bash
git status --short
git log --oneline -5
```

Report:
- commits made
- tests run
- smoke result
- remaining limitations: cmux/subscription tracking deferred
