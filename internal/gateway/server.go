package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/petrichor/21pins-cli/internal/store"
)

type Config struct {
	Host              string
	Port              int
	OpenAIBaseURL     string
	OpenRouterBaseURL string
	OllamaBaseURL     string
	AnthropicBaseURL  string
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
		cfg.OpenRouterBaseURL = "https://openrouter.ai/api"
	}
	if cfg.OllamaBaseURL == "" {
		cfg.OllamaBaseURL = "http://127.0.0.1:11434"
	}
	if cfg.AnthropicBaseURL == "" {
		cfg.AnthropicBaseURL = "https://api.anthropic.com"
	}
	if cfg.GeminiBaseURL == "" {
		cfg.GeminiBaseURL = "https://generativelanguage.googleapis.com"
	}

	s := &Server{store: st, cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/v1/chat/completions", s.withCORS(s.withAuth("proxy:chat", s.handleOpenAICompatChat)))
	mux.HandleFunc("/v1/providers/", s.withCORS(s.withAuth("proxy:providers", s.handleProviderPassthrough)))
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
		setCORSHeaders(w)
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
			"health":                    "GET /health",
			"openai_compatible_chat":    "POST /v1/chat/completions",
			"provider_passthrough":      "ANY /v1/providers/{provider}/{path}",
			"auth_header":               "Authorization: Bearer <21pins-token>",
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
	provider, providerModel, err := splitProviderModel(model)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	payload["model"] = providerModel
	newBody, _ := json.Marshal(payload)

	target := ""
	switch provider {
	case "openai":
		target = strings.TrimRight(s.cfg.OpenAIBaseURL, "/") + "/v1/chat/completions"
	case "openrouter":
		target = strings.TrimRight(s.cfg.OpenRouterBaseURL, "/") + "/chat/completions"
	case "ollama":
		target = strings.TrimRight(s.cfg.OllamaBaseURL, "/") + "/v1/chat/completions"
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "provider not supported on openai-compatible endpoint"})
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
	body, _ := io.ReadAll(r.Body)
	log.Printf("[gateway] Proxying %s request to %s (provider: %s)\n", r.Method, upstream, provider)
	if err := s.forwardRequest(provider, upstream, r.Method, r.Header, body, w); err != nil {
		log.Printf("[gateway] Error proxying request to %s: %v\n", upstream, err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	log.Printf("[gateway] Successfully proxied %s request to %s\n", r.Method, upstream)
}

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
	apiKey := s.store.GetProviderKey(provider)
	if apiKey == "" && provider != "ollama" {
		return fmt.Errorf("no API key configured for provider %s", provider)
	}
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", incoming.Get("Content-Type"))
	switch provider {
	case "openai", "openrouter":
		req.Header.Set("Authorization", "Bearer "+apiKey)
	case "anthropic":
		req.Header.Set("x-api-key", apiKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	case "gemini":
		// API key goes in query string.
	case "ollama":
		// no auth by default.
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return err
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

func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
}
