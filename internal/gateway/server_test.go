package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

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
