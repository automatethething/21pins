//go:build integration

package hosted

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestSmokeLiveHosted(t *testing.T) {
	baseURL := os.Getenv("PINS21_HOSTED_URL")
	if baseURL == "" {
		baseURL = DefaultBaseURL()
	}

	requirePublicKey := os.Getenv("PINS21_HOSTED_SMOKE_REQUIRE_PUBLIC_KEY") == "1"
	keyID := os.Getenv("PINS21_HOSTED_SMOKE_KEY_ID")
	if keyID == "" {
		keyID = DefaultSmokeKeyID
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c := &Client{BaseURL: baseURL, HTTPClient: &http.Client{Timeout: 10 * time.Second}}
	report, err := c.Smoke(ctx, keyID)
	if err != nil {
		t.Fatalf("live smoke against %s failed: %v (report=%+v)", baseURL, err, report)
	}
	if requirePublicKey && !report.PublicKeyLoaded {
		t.Fatalf("expected pinned public key env %s to load", report.PublicKeyEnv)
	}
}
