package hosted

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSmokeSuccess(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/health":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ck/attestation-sessions":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"session_id":              "cas_smoke123",
				"verification_url":        "https://21pins.com/ck/attest?session=cas_smoke123",
				"user_code":               "WXYZ-1234",
				"expires_at":              time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
				"poll_interval_seconds":   2,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/ck/attestation-sessions/cas_smoke123":
			json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv(PublicKeyEnvName(DefaultSmokeKeyID), base64.StdEncoding.EncodeToString(pub))

	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	report, err := c.Smoke(context.Background(), DefaultSmokeKeyID)
	if err != nil {
		t.Fatalf("Smoke failed: %v", err)
	}
	if report.HealthState != "reachable" {
		t.Fatalf("expected reachable, got %s", report.HealthState)
	}
	if report.SessionID != "cas_smoke123" {
		t.Fatalf("unexpected session id: %s", report.SessionID)
	}
	if report.PollStatus != "pending" {
		t.Fatalf("expected pending poll, got %s", report.PollStatus)
	}
	if !report.PublicKeyLoaded {
		t.Fatal("expected public key env to load")
	}
}

func TestSmokeFailsWhenHealthOffline(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1", HTTPClient: &http.Client{Timeout: 100 * time.Millisecond}}
	_, err := c.Smoke(context.Background(), DefaultSmokeKeyID)
	if err == nil || !strings.Contains(err.Error(), "health check") {
		t.Fatalf("expected health check error, got %v", err)
	}
}

func TestVerifySmokePublicKeyEnv(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(PublicKeyEnvName(DefaultSmokeKeyID), base64.StdEncoding.EncodeToString(pub))
	if err := VerifySmokePublicKeyEnv(DefaultSmokeKeyID); err != nil {
		t.Fatalf("expected valid public key env: %v", err)
	}
}
