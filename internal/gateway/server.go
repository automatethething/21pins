package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/petrichor/21pins-cli/internal/hosted"
	"github.com/petrichor/21pins-cli/internal/policy"
	"github.com/petrichor/21pins-cli/internal/store"
	"github.com/petrichor/21pins-cli/internal/usage"
)

type Config struct {
	Host              string
	Port              int
	OpenAIBaseURL     string
	OpenRouterBaseURL string
	OllamaBaseURL     string
	AnthropicBaseURL  string
	DeepSeekBaseURL   string
	GeminiBaseURL     string
}

type Server struct {
	store   *store.Store
	cfg     Config
	handler http.Handler
}

func NewServer(st *store.Store, cfg Config) *Server {
	if cfg.OpenAIBaseURL == "" {
		cfg.OpenAIBaseURL = "https://api.openai.com"
	}
	if cfg.OpenRouterBaseURL == "" {
		cfg.OpenRouterBaseURL = "https://openrouter.ai"
	}
	if cfg.OllamaBaseURL == "" {
		cfg.OllamaBaseURL = "http://127.0.0.1:11434"
	}
	if cfg.AnthropicBaseURL == "" {
		cfg.AnthropicBaseURL = "https://api.anthropic.com"
	}
	if cfg.DeepSeekBaseURL == "" {
		cfg.DeepSeekBaseURL = "https://api.deepseek.com"
	}
	if cfg.GeminiBaseURL == "" {
		cfg.GeminiBaseURL = "https://generativelanguage.googleapis.com"
	}

	s := &Server{store: st, cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/v1/chat/completions", s.withCORS(s.withAuth("proxy:chat", s.handleOpenAICompatChat)))
	mux.HandleFunc("/v1/providers/", s.withCORS(s.withAuth("proxy:providers", s.handleProviderPassthrough)))
	mux.HandleFunc("/v1/usage", s.handleUsage)
	mux.HandleFunc("/ui", s.handleUsageUI)
	mux.HandleFunc("/", s.handleRoot)
	s.handler = s.withCORSHandler(mux)
	return s
}

func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) ListenAndServe() error {
	host := strings.TrimSpace(s.cfg.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	port := s.cfg.Port
	if port == 0 {
		port = 8787
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	return http.ListenAndServe(addr, s.handler)
}

func (s *Server) withAuth(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		token := bearerToken(r.Header.Get("Authorization"))
		if !s.store.ValidateToken(token, scope) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid token"})
			return
		}
		next(w, r)
	}
}

func (s *Server) withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w)
		next(w, r)
	}
}

func (s *Server) withCORSHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isUsageSurface(r.URL.Path) {
			setCORSHeaders(w)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "21pins gateway",
		"status":  "ok",
		"endpoints": map[string]any{
			"health":                 "GET /health",
			"openai_compatible_chat": "POST /v1/chat/completions",
			"provider_passthrough":   "ANY /v1/providers/{provider}/{path}",
			"usage":                  "GET /v1/usage",
			"ui":                     "GET /ui",
			"auth_header":            "Authorization: Bearer <21pins-token>",
			"required_scopes": map[string]string{
				"/v1/chat/completions": "proxy:chat",
				"/v1/providers/*":      "proxy:providers",
			},
		},
	})
}

func (s *Server) handleOpenAICompatChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid body"})
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(b, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	model, _ := payload["model"].(string)
	requestedModel := model
	provider, providerModel, err := splitProviderModel(model)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	payload["model"] = providerModel
	streaming, _ := payload["stream"].(bool)
	if provider == "openrouter" && streaming {
		usage.MergeStreamOptionsIncludeUsage(payload)
	}
	newBody, _ := json.Marshal(payload)

	target := ""
	switch provider {
	case "openai":
		target = strings.TrimRight(s.cfg.OpenAIBaseURL, "/") + "/v1/chat/completions"
	case "openrouter":
		target = strings.TrimRight(s.cfg.OpenRouterBaseURL, "/") + "/api/v1/chat/completions"
	case "deepseek":
		target = strings.TrimRight(s.cfg.DeepSeekBaseURL, "/") + "/v1/chat/completions"
	case "ollama":
		target = strings.TrimRight(s.cfg.OllamaBaseURL, "/") + "/v1/chat/completions"
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "provider not supported on openai-compatible endpoint"})
		return
	}

	allowed, receiptID := s.enforcePolicy(w, r, provider)
	if !allowed {
		return
	}

	if provider == "openrouter" {
		var result bufferedResponse
		var err error
		if streaming {
			result, err = s.forwardRequestStreaming(provider, target, http.MethodPost, r.Header, newBody, w)
		} else {
			result, err = s.forwardRequestBuffered(provider, target, http.MethodPost, r.Header, newBody)
			if err == nil {
				writeBufferedResponse(w, result)
			}
		}
		if err != nil {
			if result.StatusCode == 0 {
				writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			}
			return
		}
		if result.StatusCode >= 200 && result.StatusCode < 300 {
			s.recordOpenRouterUsage(r, result, requestedModel, providerModel, receiptID)
		}
		return
	}

	if err := s.forwardJSON(provider, target, r.Header, newBody, w); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
}

func (s *Server) handleProviderPassthrough(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/providers/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "expected /v1/providers/{provider}/{path}"})
		return
	}
	provider := strings.ToLower(strings.TrimSpace(parts[0]))
	restPath := "/" + strings.TrimLeft(parts[1], "/")
	query := r.URL.RawQuery
	if provider == "gemini" {
		if query == "" {
			query = "key=" + url.QueryEscape(s.store.GetProviderKey("gemini"))
		} else {
			query += "&key=" + url.QueryEscape(s.store.GetProviderKey("gemini"))
		}
	}

	base, err := s.providerBase(provider)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	upstream := strings.TrimRight(base, "/") + restPath
	if query != "" {
		upstream += "?" + query
	}
	allowed, _ := s.enforcePolicy(w, r, provider)
	if !allowed {
		return
	}

	body, _ := io.ReadAll(r.Body)
	logUpstream := redactURLForLog(upstream)
	log.Printf("[gateway] Proxying %s request to %s (provider: %s)\n", r.Method, logUpstream, provider)
	if err := s.forwardRequest(provider, upstream, r.Method, r.Header, body, w); err != nil {
		log.Printf("[gateway] Error proxying request to %s: %v\n", logUpstream, err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	log.Printf("[gateway] Successfully proxied %s request to %s\n", r.Method, logUpstream)
}

func redactURLForLog(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	query := parsed.Query()
	for _, key := range []string{"key", "api_key", "apikey", "access_token", "token"} {
		if query.Has(key) {
			query.Set(key, "REDACTED")
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (s *Server) enforcePolicy(w http.ResponseWriter, r *http.Request, target string) (bool, string) {
	grantID := strings.TrimSpace(r.Header.Get("X-21Pins-Grant-ID"))
	if grantID == "" {
		return true, ""
	}
	sub := strings.TrimSpace(r.Header.Get("X-21Pins-Sub"))
	capability := strings.TrimSpace(r.Header.Get("X-21Pins-Capability"))
	dataClass := strings.TrimSpace(r.Header.Get("X-21Pins-Data-Class"))
	if sub == "" || capability == "" || dataClass == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "policy headers require X-21Pins-Sub, X-21Pins-Capability, and X-21Pins-Data-Class"})
		return false, ""
	}
	costCents := int64(0)
	if rawCost := strings.TrimSpace(r.Header.Get("X-21Pins-Cost-Cents")); rawCost != "" {
		parsed, err := strconv.ParseInt(rawCost, 10, 64)
		if err != nil || parsed < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid X-21Pins-Cost-Cents"})
			return false, ""
		}
		costCents = parsed
	}

	grant, err := s.store.GetGrant(grantID)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "grant not found"})
		return false, ""
	}

	approvalID := strings.TrimSpace(r.Header.Get("X-21Pins-Approval-ID"))
	approvalGranted := false
	if approvalID != "" {
		approval, err := s.store.GetApproval(approvalID)
		if err != nil || approval.Status != policy.ApprovalApproved || approval.GrantID != grantID || approval.Sub != sub || approval.Capability != capability || approval.DataClass != dataClass || approval.Target != target || approval.CostCents != costCents {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "approval does not match policy request"})
			return false, ""
		}
		if approval.ApproverAttestation == nil || approval.ApproverAttestation.Subject != approval.ApproverSub {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "approval missing approver attestation"})
			return false, ""
		}
		if hosted.VerifyStoredAttestation(*approval.ApproverAttestation, time.Now().UTC()) != nil {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "invalid approver attestation"})
			return false, ""
		}
		approvalGranted = true
	}

	req := policy.ActionRequest{
		GrantID:         grantID,
		Sub:             sub,
		Capability:      capability,
		DataClass:       dataClass,
		Target:          target,
		CostCents:       costCents,
		ApprovalID:      approvalID,
		ApprovalGranted: approvalGranted,
	}
	now := time.Now().UTC()
	result := policy.EvaluateAction(grant, req, now)
	receipt := policy.NewReceipt(grant, req, result, now)
	if approvalID != "" {
		receipt.ApprovalRef = approvalID
	}
	if _, priv, keyID, err := s.store.SigningKeypair(); err == nil {
		receipt, _ = policy.SignReceipt(receipt, priv, keyID)
	}
	_ = s.store.AddReceipt(receipt)

	if result.Decision == policy.DecisionAllow {
		if costCents > 0 {
			_ = s.store.AddGrantSpend(grantID, costCents)
		}
		return true, receipt.ID
	}
	status := http.StatusForbidden
	if result.Decision == policy.DecisionRequireApproval {
		status = http.StatusPreconditionRequired
	}
	writeJSON(w, status, map[string]any{
		"error":      "policy denied request",
		"decision":   result.Decision,
		"pin_states": result.PinStates,
		"reasons":    result.Reasons,
		"receipt_id": receipt.ID,
	})
	return false, receipt.ID
}

func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	if !isLoopbackRequest(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "usage endpoint is loopback-only"})
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if !s.store.ValidateToken(bearerToken(r.Header.Get("Authorization")), "usage:read") {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid token"})
		return
	}
	events := s.store.ListUsageEvents()
	totals := usageTotals(events)
	writeJSON(w, http.StatusOK, map[string]any{"totals": totals, "events": events})
}

func (s *Server) handleUsageUI(w http.ResponseWriter, r *http.Request) {
	if !isLoopbackRequest(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "usage UI is loopback-only"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(usageUIHTML))
}

func usageTotals(events []store.UsageEvent) map[string]any {
	totals := map[string]any{
		"requests":              int64(len(events)),
		"prompt_tokens":         int64(0),
		"completion_tokens":     int64(0),
		"cache_read_tokens":     int64(0),
		"cache_write_tokens":    int64(0),
		"total_tokens":          int64(0),
		"estimated_cost_micros": int64(0),
		"currency":              "USD",
	}
	for _, e := range events {
		totals["prompt_tokens"] = totals["prompt_tokens"].(int64) + e.PromptTokens
		totals["completion_tokens"] = totals["completion_tokens"].(int64) + e.CompletionTokens
		totals["cache_read_tokens"] = totals["cache_read_tokens"].(int64) + e.CacheReadTokens
		totals["cache_write_tokens"] = totals["cache_write_tokens"].(int64) + e.CacheWriteTokens
		totals["total_tokens"] = totals["total_tokens"].(int64) + e.TotalTokens
		totals["estimated_cost_micros"] = totals["estimated_cost_micros"].(int64) + e.EstimatedCostMicros
	}
	return totals
}

func isLoopbackRequest(r *http.Request) bool {
	host := r.RemoteAddr
	if strings.TrimSpace(host) == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

const usageUIHTML = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>21pins usage</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem;max-width:1100px}input{width:28rem;max-width:100%;padding:.5rem}button{padding:.55rem .8rem}table{border-collapse:collapse;width:100%;margin-top:1rem}th,td{border-bottom:1px solid #ddd;text-align:left;padding:.45rem}code{background:#f4f4f4;padding:.15rem .25rem}.cards{display:flex;gap:1rem;flex-wrap:wrap}.card{border:1px solid #ddd;border-radius:.5rem;padding:1rem;min-width:12rem}</style></head>
<body><h1>21pins usage</h1><p>Paste a local 21pins token with <code>usage:read</code> scope.</p><label>21pins token <input id="token" type="password" autocomplete="off"></label> <button id="load">Load usage</button><pre id="error"></pre><section class="cards"><div class="card"><strong>Prompt tokens</strong><div id="prompt">—</div></div><div class="card"><strong>Completion tokens</strong><div id="completion">—</div></div><div class="card"><strong>Total tokens</strong><div id="total">—</div></div><div class="card"><strong>Estimated cost</strong><div id="cost">—</div></div></section><table><thead><tr><th>Time</th><th>Source</th><th>Provider</th><th>Model</th><th>Prompt</th><th>Completion</th><th>Total</th><th>Cost</th><th>Pricing</th><th>Token</th><th>Warning</th></tr></thead><tbody id="rows"></tbody></table><script>
const esc=v=>String(v??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));const fmtCost=m=>'$'+((m||0)/1000000).toFixed(6);document.getElementById('load').onclick=async()=>{const t=document.getElementById('token').value.trim();document.getElementById('error').textContent='';const r=await fetch('/v1/usage',{headers:{Authorization:'Bearer '+t}});if(!r.ok){document.getElementById('error').textContent=await r.text();return}const d=await r.json();document.getElementById('prompt').textContent=d.totals.prompt_tokens||0;document.getElementById('completion').textContent=d.totals.completion_tokens||0;document.getElementById('total').textContent=d.totals.total_tokens||0;document.getElementById('cost').textContent=fmtCost(d.totals.estimated_cost_micros);document.getElementById('rows').innerHTML=(d.events||[]).map(e=>'<tr><td>'+esc(e.created_at)+'</td><td>'+esc(e.source)+'</td><td>'+esc(e.provider)+'</td><td>'+esc(e.model)+'</td><td>'+esc(e.prompt_tokens||0)+'</td><td>'+esc(e.completion_tokens||0)+'</td><td>'+esc(e.total_tokens||0)+'</td><td>'+esc(fmtCost(e.estimated_cost_micros))+'</td><td>'+esc(e.pricing_source)+'</td><td>'+esc(e.app_token_name)+'</td><td>'+esc(e.warning)+'</td></tr>').join('')};
</script></body></html>`

func (s *Server) providerBase(provider string) (string, error) {
	switch provider {
	case "openai":
		return s.cfg.OpenAIBaseURL, nil
	case "openrouter":
		return s.cfg.OpenRouterBaseURL, nil
	case "ollama":
		return s.cfg.OllamaBaseURL, nil
	case "anthropic":
		return s.cfg.AnthropicBaseURL, nil
	case "deepseek":
		return s.cfg.DeepSeekBaseURL, nil
	case "gemini":
		return s.cfg.GeminiBaseURL, nil
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

func (s *Server) forwardJSON(provider, target string, incoming http.Header, body []byte, w http.ResponseWriter) error {
	return s.forwardRequest(provider, target, http.MethodPost, incoming, body, w)
}

func (s *Server) forwardRequest(provider, target, method string, incoming http.Header, body []byte, w http.ResponseWriter) error {
	result, err := s.forwardRequestBuffered(provider, target, method, incoming, body)
	if err != nil {
		return err
	}
	writeBufferedResponse(w, result)
	return nil
}

type bufferedResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func (s *Server) providerRequest(provider, target, method string, incoming http.Header, body []byte) (*http.Request, error) {
	apiKey := s.store.GetProviderKey(provider)
	if apiKey == "" && provider != "ollama" {
		return nil, fmt.Errorf("no API key configured for provider %s", provider)
	}
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", incoming.Get("Content-Type"))
	switch provider {
	case "openai", "openrouter", "deepseek":
		req.Header.Set("Authorization", "Bearer "+apiKey)
	case "anthropic":
		req.Header.Set("x-api-key", apiKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	case "gemini":
		// API key goes in query string.
	case "ollama":
		// no auth by default.
	}
	return req, nil
}

func (s *Server) forwardRequestBuffered(provider, target, method string, incoming http.Header, body []byte) (bufferedResponse, error) {
	req, err := s.providerRequest(provider, target, method, incoming, body)
	if err != nil {
		return bufferedResponse{}, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return bufferedResponse{}, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return bufferedResponse{}, err
	}
	return bufferedResponse{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: respBody}, nil
}

func (s *Server) forwardRequestStreaming(provider, target, method string, incoming http.Header, body []byte, w http.ResponseWriter) (bufferedResponse, error) {
	req, err := s.providerRequest(provider, target, method, incoming, body)
	if err != nil {
		return bufferedResponse{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return bufferedResponse{}, err
	}
	defer resp.Body.Close()

	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 8192)
	captured := bytes.Buffer{}
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			captured.Write(chunk)
			if _, err := w.Write(chunk); err != nil {
				return bufferedResponse{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: captured.Bytes()}, err
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return bufferedResponse{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: captured.Bytes()}, readErr
		}
	}
	return bufferedResponse{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: captured.Bytes()}, nil
}

func writeBufferedResponse(w http.ResponseWriter, result bufferedResponse) {
	for k, vals := range result.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(result.StatusCode)
	_, _ = w.Write(result.Body)
}

func (s *Server) recordOpenRouterUsage(r *http.Request, result bufferedResponse, requestedModel, providerModel, receiptID string) {
	var parsed usage.ParsedUsage
	var ok bool
	if strings.Contains(strings.ToLower(result.Header.Get("Content-Type")), "text/event-stream") {
		parsed, ok = usage.ParseSSEUsage(result.Body)
	} else {
		parsed, ok = usage.ParseChatUsage(result.Body)
	}
	if !ok {
		parsed = usage.ParsedUsage{Model: providerModel, Warning: "usage_unparseable"}
	}
	model := parsed.Model
	if model == "" {
		model = providerModel
	}
	var cost usage.CostEstimate
	if parsed.Warning != "" && parsed.PromptTokens == 0 && parsed.CompletionTokens == 0 && parsed.TotalTokens == 0 {
		cost = usage.CostEstimate{Micros: 0, Source: "unknown", Currency: "USD"}
	} else {
		price := s.catalogUsagePrice("openrouter", model)
		cost = usage.EstimateOpenRouterCostMicros(model, parsed.PromptTokens, parsed.CompletionTokens, price)
	}
	appTokenName := ""
	if record, valid := s.store.ValidateTokenRecord(bearerToken(r.Header.Get("Authorization")), "proxy:chat"); valid {
		appTokenName = record.Name
	}
	_ = s.store.AddUsageEvent(store.UsageEvent{
		CreatedAt:           time.Now().UTC(),
		Source:              sourceForTokenName(appTokenName),
		Provider:            "openrouter",
		Model:               model,
		RequestedModel:      requestedModel,
		AppTokenName:        appTokenName,
		BillingMode:         "api",
		PromptTokens:        parsed.PromptTokens,
		CompletionTokens:    parsed.CompletionTokens,
		CacheReadTokens:     parsed.CacheReadTokens,
		CacheWriteTokens:    parsed.CacheWriteTokens,
		TotalTokens:         parsed.TotalTokens,
		EstimatedCostMicros: cost.Micros,
		Currency:            cost.Currency,
		PricingSource:       cost.Source,
		Warning:             parsed.Warning,
		RequestID:           parsed.RequestID,
		ReceiptID:           receiptID,
	})
}

func (s *Server) catalogUsagePrice(provider, model string) *usage.Price {
	catalog, ok := s.store.GetModelCatalog(provider)
	if !ok {
		return nil
	}
	for _, m := range catalog.Models {
		if m.ID == model && m.PromptPriceMicrosPerMillion > 0 && m.CompletionPriceMicrosPerMillion > 0 {
			return &usage.Price{PromptMicrosPerMillion: m.PromptPriceMicrosPerMillion, CompletionMicrosPerMillion: m.CompletionPriceMicrosPerMillion, Source: m.PricingSource}
		}
	}
	return nil
}

func sourceForTokenName(name string) string {
	name = strings.TrimSpace(name)
	if strings.EqualFold(name, "pi") {
		return "pi"
	}
	if name != "" {
		return name
	}
	return "api"
}

func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	const prefix = "Bearer "
	if strings.HasPrefix(strings.ToLower(header), strings.ToLower(prefix)) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func isUsageSurface(path string) bool {
	return path == "/v1/usage" || path == "/ui"
}

func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
}
