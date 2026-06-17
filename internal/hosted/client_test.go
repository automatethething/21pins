package hosted

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/petrichor/21pins-cli/internal/policy"
)

func TestPublicKeyEnvName(t *testing.T) {
	if got := PublicKeyEnvName("hosted-ed25519-v1"); got != "PINS21_HOSTED_PUBLIC_KEY_HOSTED_ED25519_V1" {
		t.Fatalf("unexpected env name: %s", got)
	}
}

func TestPublicKeyFromEnvAcceptsDERSPKI(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(PublicKeyEnvName("hosted-ed25519-v1"), base64.StdEncoding.EncodeToString(der))
	got, err := PublicKeyFromEnv("hosted-ed25519-v1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(base64.StdEncoding.EncodeToString(got), base64.StdEncoding.EncodeToString(pub)) {
		t.Fatalf("unexpected key")
	}
}

func TestClientStatusReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		}
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	status := c.Status(context.Background())
	if status.State != "reachable" {
		t.Fatalf("expected reachable, got %s: %+v", status.State, status)
	}
	if !status.CKAttestationAvailable {
		t.Fatal("expected ck attestation available when /health returns 200")
	}
}

func TestClientStatusOffline(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1", HTTPClient: &http.Client{Timeout: 100 * time.Millisecond}}
	status := c.Status(context.Background())
	if status.State != "offline" {
		t.Fatalf("expected offline, got %s", status.State)
	}
}

func TestClientCompleteAttestation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var sessionID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/ck/attestation-sessions" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"session_id":           "cas_test123",
				"verification_url":     "https://21pins.com/ck/attest?session=cas_test123",
				"user_code":            "ABCD-EFGH",
				"expires_at":           time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
				"poll_interval_seconds": 0,
				"issuer":                "https://issuer.21pins.test",
			})
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/ck/attestation-sessions/") {
			sessionID = strings.TrimPrefix(r.URL.Path, "/v1/ck/attestation-sessions/")
			a := policy.IdentityAttestation{
				ID:        "att_test",
				Subject:   "ck_sub_hosted",
				Issuer:    "https://issuer.21pins.test",
				Audience:  "21pins",
				Method:    "hosted_ck",
				IssuedAt:  time.Now().UTC().Add(-time.Minute),
				ExpiresAt: time.Now().UTC().Add(time.Hour),
				KeyID:     "hosted-ed25519-v1",
			}
			signed, err := policy.SignIdentityAttestationForTest(a, priv)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"status":      "approved",
				"attestation": signed,
			})
			return
		}
		http.Error(w, "not found", 404)
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	t.Setenv(PublicKeyEnvName("hosted-ed25519-v1"), base64.StdEncoding.EncodeToString(pub))

	var buf strings.Builder
	att, err := c.CompleteHostedAttestation(context.Background(), 60, srv.URL, time.Now().UTC(), &buf)
	if err != nil {
		t.Fatalf("CompleteHostedAttestation failed: %v", err)
	}
	if att.Subject != "ck_sub_hosted" {
		t.Fatalf("expected ck_sub_hosted, got %s", att.Subject)
	}
	if !strings.Contains(buf.String(), "cas_test123") {
		t.Fatalf("expected session id in output: %s", buf.String())
	}
	_ = sessionID
}

func TestClientCompleteAttestationRejectsNonHTTPSIssuer(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/ck/attestation-sessions" {
			json.NewEncoder(w).Encode(map[string]any{"session_id": "cas_test", "verification_url": "http://localhost/ck/attest", "user_code": "ABCD-EFGH", "expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339), "poll_interval_seconds": 0, "issuer": "http://localhost:3000"})
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/ck/attestation-sessions/") {
			a := policy.IdentityAttestation{ID: "att", Subject: "ck_sub_hosted", Issuer: "http://localhost:3000", Audience: "21pins", Method: "hosted_ck", IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour), KeyID: "hosted-ed25519-v1"}
			signed, err := policy.SignIdentityAttestationForTest(a, priv)
			if err != nil { http.Error(w, err.Error(), 500); return }
			json.NewEncoder(w).Encode(map[string]any{"status": "approved", "attestation": signed})
			return
		}
		http.Error(w, "not found", 404)
	}))
	defer srv.Close()
	t.Setenv(PublicKeyEnvName("hosted-ed25519-v1"), base64.StdEncoding.EncodeToString(pub))
	_, err = (&Client{BaseURL: srv.URL, HTTPClient: srv.Client()}).CompleteHostedAttestation(context.Background(), 60, srv.URL, time.Now().UTC(), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "invalid attestation issuer") {
		t.Fatalf("expected invalid issuer error, got %v", err)
	}
}

func TestClientCompleteAttestationFailsOnHostedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal"}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	var buf strings.Builder
	_, err := c.CompleteHostedAttestation(context.Background(), 60, "https://21pins.com", time.Now().UTC(), &buf)
	if err == nil {
		t.Fatal("expected error on hosted 500")
	}
}
