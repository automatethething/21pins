package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/petrichor/21pins-cli/internal/policy"
	"github.com/petrichor/21pins-cli/internal/store"
)

func TestGatewayRejectsMissingToken(t *testing.T) {
	tempDir := t.TempDir()
	s, err := store.New(filepath.Join(tempDir, "state.json"))
	if err != nil {
		t.Fatalf("store.New failed: %v", err)
	}
	_ = s.SetProviderKey("openai", "test-key")

	g := NewServer(s, Config{Port: 0})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`))
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func createGatewayGrant(t *testing.T, s *store.Store, target string) policy.Grant {
	t.Helper()
	now := time.Now().UTC()
	grant, err := s.CreateGrant(policy.Grant{
		Sub: "ck_sub_abc",
		Pins: policy.Pins{
			Identity:         policy.IdentityPin{Sub: "ck_sub_abc"},
			Authority:        policy.AuthorityPin{Chain: []string{"ck_sub_abc"}},
			Capabilities:     policy.CapabilityPin{Allowed: []string{"llm.chat"}},
			DataPolicy:       policy.DataPolicyPin{AllowedClasses: []string{"public"}},
			SpendPolicy:      policy.SpendPolicyPin{LimitCents: 1000, WindowStart: now.Add(-time.Hour), WindowEnd: now.Add(time.Hour)},
			ExecutionTargets: policy.ExecutionTargetPin{AllowedTargets: []string{target}},
			ApprovalPolicy:   policy.ApprovalPolicyPin{ThresholdCents: 0},
		},
	})
	if err != nil {
		t.Fatalf("CreateGrant failed: %v", err)
	}
	return grant
}

func addPolicyHeaders(req *http.Request, grantID string) {
	req.Header.Set("X-21Pins-Grant-ID", grantID)
	req.Header.Set("X-21Pins-Sub", "ck_sub_abc")
	req.Header.Set("X-21Pins-Capability", "llm.chat")
	req.Header.Set("X-21Pins-Data-Class", "public")
	req.Header.Set("X-21Pins-Cost-Cents", "7")
}

func signTestApproverAttestation(t *testing.T, subject string) (policy.IdentityAttestation, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	a := policy.IdentityAttestation{
		ID:        "att_approver",
		Subject:   subject,
		Issuer:    "https://21pins.com",
		Audience:  "21pins",
		Method:    "hosted_ck",
		IssuedAt:  now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
		KeyID:     "hosted-ed25519-v1",
	}
	signed, err := policy.SignIdentityAttestationForTest(a, priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed, pub
}

func TestGatewayPolicyAllowsAndRecordsReceipt(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"ok"}`))
	}))
	defer upstream.Close()

	tempDir := t.TempDir()
	s, err := store.New(filepath.Join(tempDir, "state.json"))
	if err != nil {
		t.Fatalf("store.New failed: %v", err)
	}
	_ = s.SetProviderKey("openai", "provider-key")
	grant := createGatewayGrant(t, s, "openai")
	appToken, err := s.CreateToken("web", []string{"proxy:chat"})
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}

	g := NewServer(s, Config{Port: 0, OpenAIBaseURL: upstream.URL})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer "+appToken)
	req.Header.Set("Content-Type", "application/json")
	addPolicyHeaders(req, grant.ID)
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	receipts := s.ListReceipts(grant.ID)
	if len(receipts) != 1 {
		t.Fatalf("expected one receipt, got %d", len(receipts))
	}
	if receipts[0].Decision != policy.DecisionAllow || receipts[0].Target != "openai" || receipts[0].CostCents != 7 {
		t.Fatalf("unexpected receipt: %+v", receipts[0])
	}
	updated, err := s.GetGrant(grant.ID)
	if err != nil {
		t.Fatalf("GetGrant failed: %v", err)
	}
	if updated.Pins.SpendPolicy.SpentCents != 7 {
		t.Fatalf("expected spend to be recorded, got %d", updated.Pins.SpendPolicy.SpentCents)
	}
}

func TestGatewayPolicyBlocksDisallowedTargetBeforeForwarding(t *testing.T) {
	called := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer upstream.Close()

	tempDir := t.TempDir()
	s, err := store.New(filepath.Join(tempDir, "state.json"))
	if err != nil {
		t.Fatalf("store.New failed: %v", err)
	}
	_ = s.SetProviderKey("openai", "provider-key")
	grant := createGatewayGrant(t, s, "openrouter")
	appToken, err := s.CreateToken("web", []string{"proxy:chat"})
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}

	g := NewServer(s, Config{Port: 0, OpenAIBaseURL: upstream.URL})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer "+appToken)
	req.Header.Set("Content-Type", "application/json")
	addPolicyHeaders(req, grant.ID)
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", w.Code, w.Body.String())
	}
	if called {
		t.Fatalf("upstream should not be called for blocked policy request")
	}
}

func TestRedactURLForLogHidesQueryAPIKeys(t *testing.T) {
	got := redactURLForLog("https://generativelanguage.googleapis.com/v1/models?key=secret&alt=sse")
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("redacted URL should parse: %v", err)
	}
	if parsed.Query().Get("key") != "REDACTED" || parsed.Query().Get("alt") != "sse" {
		t.Fatalf("unexpected redacted URL: %s", got)
	}
}

func TestGatewayRecordsOpenRouterUsageForPiToken(t *testing.T) {
	upstreamBody := `{"id":"gen_123","model":"openai/gpt-4o-mini","usage":{"prompt_tokens":1000,"completion_tokens":200,"total_tokens":1200},"choices":[{"message":{"role":"assistant","content":"pong"}}]}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/chat/completions" {
			t.Fatalf("bad path: %s", r.URL.Path)
		}
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

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.TrimSpace(w.Body.String()) != upstreamBody {
		t.Fatalf("response changed: %s", w.Body.String())
	}
	events := s.ListUsageEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 usage event, got %d", len(events))
	}
	event := events[0]
	if event.Source != "pi" || event.AppTokenName != "pi" || event.Provider != "openrouter" {
		t.Fatalf("bad attribution: %+v", event)
	}
	if event.Model != "openai/gpt-4o-mini" || event.RequestedModel != "openrouter/openai/gpt-4o-mini" {
		t.Fatalf("bad model fields: %+v", event)
	}
	if event.PromptTokens != 1000 || event.CompletionTokens != 200 || event.TotalTokens != 1200 {
		t.Fatalf("bad usage: %+v", event)
	}
	if event.EstimatedCostMicros <= 0 || event.BillingMode != "api" || event.Currency != "USD" {
		t.Fatalf("bad cost: %+v", event)
	}
	if event.RequestID != "gen_123" {
		t.Fatalf("expected request id gen_123, got %q", event.RequestID)
	}
}

func TestGatewayOpenRouterUsageLinksPolicyReceipt(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"gen_receipt","model":"openai/gpt-4o-mini","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
	}))
	defer upstream.Close()

	s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
	_ = s.SetProviderKey("openrouter", "or-key")
	grant := createGatewayGrant(t, s, "openrouter")
	token, _ := s.CreateToken("agent-app", []string{"proxy:chat"})
	g := NewServer(s, Config{OpenRouterBaseURL: upstream.URL})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"openrouter/openai/gpt-4o-mini","messages":[{"role":"user","content":"ping"}]}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	addPolicyHeaders(req, grant.ID)
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	events := s.ListUsageEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 usage event, got %d", len(events))
	}
	if events[0].ReceiptID == "" {
		t.Fatalf("expected usage event to link receipt: %+v", events[0])
	}
	if events[0].Source != "agent-app" || events[0].AppTokenName != "agent-app" {
		t.Fatalf("expected non-pi token source attribution, got %+v", events[0])
	}
	if receipts := s.ListReceipts(grant.ID); len(receipts) != 1 || receipts[0].ID != events[0].ReceiptID {
		t.Fatalf("usage receipt link mismatch: receipts=%+v event=%+v", receipts, events[0])
	}
}

func TestGatewayCORSAllowsProxyButNotUsageSurface(t *testing.T) {
	s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
	g := NewServer(s, Config{})

	health := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "https://app.example")
	g.Handler().ServeHTTP(health, req)
	if health.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("expected wildcard CORS on non-usage route, got %q", health.Header().Get("Access-Control-Allow-Origin"))
	}

	usageReq := httptest.NewRequest(http.MethodOptions, "/v1/usage", nil)
	usageReq.RemoteAddr = "127.0.0.1:1234"
	usageReq.Header.Set("Origin", "https://app.example")
	usageResp := httptest.NewRecorder()
	g.Handler().ServeHTTP(usageResp, usageReq)
	if usageResp.Header().Get("Access-Control-Allow-Origin") == "*" {
		t.Fatalf("usage route should not be wildcard CORS-readable")
	}
}

func TestGatewayRecordsZeroWarningWhenOpenRouterUsageMissing(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"gen_123","model":"unknown/model","choices":[{"message":{"content":"pong"}}]}`))
	}))
	defer upstream.Close()

	s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
	_ = s.SetProviderKey("openrouter", "or-key")
	token, _ := s.CreateToken("pi", []string{"proxy:chat"})
	g := NewServer(s, Config{OpenRouterBaseURL: upstream.URL})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"openrouter/unknown/model","messages":[{"role":"user","content":"ping"}]}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	events := s.ListUsageEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 usage event, got %d", len(events))
	}
	if events[0].TotalTokens != 0 || events[0].PricingSource != "unknown" || events[0].Warning == "" {
		t.Fatalf("expected warning zero event: %+v", events[0])
	}
}

func TestGatewayRecordsKnownModelMissingUsageAsUnknownPricingWarning(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"gen_missing","model":"openai/gpt-4o-mini","choices":[{"message":{"content":"pong"}}]}`))
	}))
	defer upstream.Close()

	s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
	_ = s.SetProviderKey("openrouter", "or-key")
	token, _ := s.CreateToken("pi", []string{"proxy:chat"})
	g := NewServer(s, Config{OpenRouterBaseURL: upstream.URL})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"openrouter/openai/gpt-4o-mini","messages":[{"role":"user","content":"ping"}]}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	events := s.ListUsageEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 usage event, got %d", len(events))
	}
	if events[0].TotalTokens != 0 || events[0].PricingSource != "unknown" || events[0].Warning == "" {
		t.Fatalf("expected unknown-pricing warning zero event: %+v", events[0])
	}
}

func TestGatewayRecordsUnparseableSuccessfulOpenRouterResponseAsWarning(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"pong"}}]}`))
	}))
	defer upstream.Close()

	s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
	_ = s.SetProviderKey("openrouter", "or-key")
	token, _ := s.CreateToken("pi", []string{"proxy:chat"})
	g := NewServer(s, Config{OpenRouterBaseURL: upstream.URL})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"openrouter/openai/gpt-4o-mini","messages":[{"role":"user","content":"ping"}]}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	events := s.ListUsageEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 usage event, got %d", len(events))
	}
	if events[0].Model != "openai/gpt-4o-mini" || events[0].TotalTokens != 0 || events[0].PricingSource != "unknown" || events[0].Warning != "usage_unparseable" {
		t.Fatalf("expected unparseable warning zero event: %+v", events[0])
	}
}

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
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected upstream status, got %d", w.Code)
	}
	if got := len(s.ListUsageEvents()); got != 0 {
		t.Fatalf("expected no usage events for failed upstream, got %d", got)
	}
}

func TestGatewayStreamsOpenRouterUsage(t *testing.T) {
	var upstreamPayload map[string]any
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&upstreamPayload)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"po\"}}]}\n\n"))
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"ng\"}}]}\n\n"))
		_, _ = w.Write([]byte("data: {\"id\":\"gen_stream\",\"model\":\"openai/gpt-4o-mini\",\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2,\"total_tokens\":6}}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()

	s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
	_ = s.SetProviderKey("openrouter", "or-key")
	token, _ := s.CreateToken("pi", []string{"proxy:chat"})
	g := NewServer(s, Config{OpenRouterBaseURL: upstream.URL})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"openrouter/openai/gpt-4o-mini","messages":[{"role":"user","content":"ping"}],"stream":true}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "data: [DONE]") {
		t.Fatalf("stream not preserved: %s", w.Body.String())
	}
	streamOptions := upstreamPayload["stream_options"].(map[string]any)
	if streamOptions["include_usage"] != true {
		t.Fatalf("expected include_usage stream option, got %#v", streamOptions)
	}
	events := s.ListUsageEvents()
	if len(events) != 1 || events[0].TotalTokens != 6 || events[0].RequestID != "gen_stream" {
		t.Fatalf("bad usage events: %+v", events)
	}
}

func TestGatewayStreamsSplitUsageFrame(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"id\":\"gen_split\",\"model\":\"openai/gpt-4o-mini\",\"usage\":{"))
		if flusher != nil {
			flusher.Flush()
		}
		_, _ = w.Write([]byte("\"prompt_tokens\":4,\"completion_tokens\":2,\"total_tokens\":6}}\n\n"))
	}))
	defer upstream.Close()
	s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
	_ = s.SetProviderKey("openrouter", "or-key")
	token, _ := s.CreateToken("pi", []string{"proxy:chat"})
	g := NewServer(s, Config{OpenRouterBaseURL: upstream.URL})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"openrouter/openai/gpt-4o-mini","messages":[],"stream":true}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "gen_split") {
		t.Fatalf("split frame not forwarded: %s", w.Body.String())
	}
	events := s.ListUsageEvents()
	if len(events) != 1 || events[0].TotalTokens != 6 {
		t.Fatalf("bad events: %+v", events)
	}
}

func TestGatewayMergesStreamOptions(t *testing.T) {
	var upstreamPayload map[string]any
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&upstreamPayload)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()
	s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
	_ = s.SetProviderKey("openrouter", "or-key")
	token, _ := s.CreateToken("pi", []string{"proxy:chat"})
	g := NewServer(s, Config{OpenRouterBaseURL: upstream.URL})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"openrouter/openai/gpt-4o-mini","messages":[],"stream":true,"stream_options":{"foo":"bar"}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	streamOptions := upstreamPayload["stream_options"].(map[string]any)
	if streamOptions["foo"] != "bar" || streamOptions["include_usage"] != true {
		t.Fatalf("unexpected stream options: %#v", streamOptions)
	}
}

func TestUsageEndpointRequiresUsageReadScope(t *testing.T) {
	s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
	token, _ := s.CreateToken("pi", []string{"proxy:chat"})
	g := NewServer(s, Config{})
	req := httptest.NewRequest(http.MethodGet, "/v1/usage", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestUsageEndpointReturnsTotalsAndEvents(t *testing.T) {
	s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
	_ = s.AddUsageEvent(store.UsageEvent{ID: "use_1", CreatedAt: time.Now().UTC(), Source: "pi", AppTokenName: "pi", Provider: "openrouter", Model: "openai/gpt-4o-mini", RequestedModel: "openrouter/openai/gpt-4o-mini", BillingMode: "api", PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15, EstimatedCostMicros: 6, Currency: "USD", PricingSource: "static"})
	token, _ := s.CreateToken("pi", []string{"usage:read"})
	g := NewServer(s, Config{})
	req := httptest.NewRequest(http.MethodGet, "/v1/usage", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	totals := body["totals"].(map[string]any)
	if totals["requests"].(float64) != 1 || totals["total_tokens"].(float64) != 15 {
		t.Fatalf("bad totals: %#v", totals)
	}
	if !strings.Contains(w.Body.String(), "app_token_name") || !strings.Contains(w.Body.String(), "pricing_source") {
		t.Fatalf("missing required event fields: %s", w.Body.String())
	}
}

func TestUsageEndpointsRejectNonLoopbackAndNoWildcardCORS(t *testing.T) {
	s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
	token, _ := s.CreateToken("pi", []string{"usage:read"})
	g := NewServer(s, Config{})
	for _, path := range []string{"/v1/usage", "/ui"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "192.168.1.5:1234"
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Origin", "https://evil.example")
		w := httptest.NewRecorder()
		g.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s expected 403, got %d", path, w.Code)
		}
		if w.Header().Get("Access-Control-Allow-Origin") == "*" {
			t.Fatalf("%s should not be wildcard CORS-readable", path)
		}
	}
}

func TestUsageUIIncludesLabels(t *testing.T) {
	s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
	g := NewServer(s, Config{})
	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	for _, want := range []string{"21pins usage", "Prompt tokens", "Completion tokens", "Estimated cost", "21pins token"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("ui missing %q: %s", want, w.Body.String())
		}
	}
}

func createApprovalRequiredGrant(t *testing.T, s *store.Store, target string) policy.Grant {
	t.Helper()
	now := time.Now().UTC()
	grant, err := s.CreateGrant(policy.Grant{
		Sub: "ck_sub_abc",
		Pins: policy.Pins{
			Identity:         policy.IdentityPin{Sub: "ck_sub_abc"},
			Authority:        policy.AuthorityPin{Chain: []string{"ck_sub_abc"}},
			Capabilities:     policy.CapabilityPin{Allowed: []string{"llm.chat"}},
			DataPolicy:       policy.DataPolicyPin{AllowedClasses: []string{"public"}},
			SpendPolicy:      policy.SpendPolicyPin{LimitCents: 1000, WindowStart: now.Add(-time.Hour), WindowEnd: now.Add(time.Hour)},
			ExecutionTargets: policy.ExecutionTargetPin{AllowedTargets: []string{target}},
			ApprovalPolicy:   policy.ApprovalPolicyPin{ThresholdCents: 1},
		},
	})
	if err != nil {
		t.Fatalf("CreateGrant failed: %v", err)
	}
	return grant
}

func createMatchingApproval(t *testing.T, s *store.Store, grantID string) policy.ApprovalRequest {
	t.Helper()
	a, err := s.CreateApproval(policy.ApprovalRequest{GrantID: grantID, Sub: "ck_sub_abc", Capability: "llm.chat", DataClass: "public", Target: "openai", CostCents: 7})
	if err != nil {
		t.Fatalf("CreateApproval failed: %v", err)
	}
	return a
}

func requestWithApproval(t *testing.T, s *store.Store, appToken, grantID, approvalID string, upstreamURL string) int {
	t.Helper()
	g := NewServer(s, Config{Port: 0, OpenAIBaseURL: upstreamURL})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer "+appToken)
	req.Header.Set("Content-Type", "application/json")
	addPolicyHeaders(req, grantID)
	req.Header.Set("X-21Pins-Approval-ID", approvalID)
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)
	return w.Code
}

func TestGatewayRejectsApprovedApprovalWithoutApproverAttestation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"id":"ok"}`)) }))
	defer upstream.Close()

	s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
	_ = s.SetProviderKey("openai", "provider-key")
	appToken, _ := s.CreateToken("web", []string{"proxy:chat"})
	grant := createApprovalRequiredGrant(t, s, "openai")
	approval := createMatchingApproval(t, s, grant.ID)
	approved, err := s.ResolveApproval(approval.ID, policy.ApprovalApproved, "ck_sub_admin", "ok")
	if err != nil || approved.Status != policy.ApprovalApproved {
		t.Fatalf("ResolveApproval failed: %v", err)
	}

	if code := requestWithApproval(t, s, appToken, grant.ID, approval.ID, upstream.URL); code != http.StatusForbidden {
		t.Fatalf("expected unattested approval to be rejected, got %d", code)
	}
}

func TestGatewayAcceptsApprovalWithValidApproverAttestation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"id":"ok"}`)) }))
	defer upstream.Close()

	s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
	_ = s.SetProviderKey("openai", "provider-key")
	appToken, _ := s.CreateToken("web", []string{"proxy:chat"})
	grant := createApprovalRequiredGrant(t, s, "openai")
	approval := createMatchingApproval(t, s, grant.ID)
	att, pub := signTestApproverAttestation(t, "ck_sub_admin")
	t.Setenv("PINS21_HOSTED_PUBLIC_KEY_HOSTED_ED25519_V1", base64.StdEncoding.EncodeToString(pub))
	approved, err := s.ResolveApprovalWithAttestation(approval.ID, policy.ApprovalApproved, "ck_sub_admin", "ok", att)
	if err != nil || approved.ApproverAttestation == nil {
		t.Fatalf("ResolveApprovalWithAttestation failed: %v", err)
	}

	if code := requestWithApproval(t, s, appToken, grant.ID, approval.ID, upstream.URL); code != http.StatusOK {
		t.Fatalf("expected attested approval to pass, got %d", code)
	}
}

func TestGatewayForwardsDeepSeekOpenAICompatibleRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer deepseek-key" {
			t.Fatalf("unexpected auth header: %s", got)
		}
		b, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(b, &payload)
		if payload["model"] != "deepseek-chat" {
			t.Fatalf("expected stripped model, got %v", payload["model"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ok"}`))
	}))
	defer upstream.Close()

	s, _ := store.New(filepath.Join(t.TempDir(), "state.json"))
	_ = s.SetProviderKey("deepseek", "deepseek-key")
	appToken, _ := s.CreateToken("web", []string{"proxy:chat"})
	g := NewServer(s, Config{DeepSeekBaseURL: upstream.URL})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"deepseek/deepseek-chat","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer "+appToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestGatewayForwardsOpenAICompatibleRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer provider-key" {
			t.Fatalf("unexpected auth header: %s", got)
		}
		b, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(b, &payload)
		if payload["model"] != "gpt-4o-mini" {
			t.Fatalf("expected stripped model, got %v", payload["model"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ok"}`))
	}))
	defer upstream.Close()

	tempDir := t.TempDir()
	s, err := store.New(filepath.Join(tempDir, "state.json"))
	if err != nil {
		t.Fatalf("store.New failed: %v", err)
	}
	_ = s.SetProviderKey("openai", "provider-key")
	appToken, err := s.CreateToken("web", []string{"proxy:chat"})
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}

	g := NewServer(s, Config{
		Port:              0,
		OpenAIBaseURL:     upstream.URL,
		OpenRouterBaseURL: "https://openrouter.ai/api",
		OllamaBaseURL:     "http://localhost:11434",
		AnthropicBaseURL:  "https://api.anthropic.com",
		GeminiBaseURL:     "https://generativelanguage.googleapis.com",
	})

	payload := `{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(payload))
	req.Header.Set("Authorization", "Bearer "+appToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
}
