package hosted

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/petrichor/21pins-cli/internal/policy"
)

const defaultHostedURL = "https://21pins.com"

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

type Status struct {
	URL                    string    `json:"url"`
	State                  string    `json:"state"` // reachable|offline|degraded
	CheckedAt              time.Time `json:"checked_at"`
	CKAttestationAvailable bool      `json:"ck_attestation_available"`
	Error                  string    `json:"error,omitempty"`
}

type SessionStart struct {
	SessionID           string `json:"session_id"`
	VerificationURL     string `json:"verification_url"`
	UserCode            string `json:"user_code"`
	ExpiresAt           string `json:"expires_at"`
	PollIntervalSeconds int    `json:"poll_interval_seconds"`
	Issuer              string `json:"issuer,omitempty"`
}

type PollResponse struct {
	Status      string                      `json:"status"`
	Attestation *policy.IdentityAttestation `json:"attestation,omitempty"`
	Error       string                      `json:"error,omitempty"`
}

func DefaultBaseURL() string {
	if v := os.Getenv("PINS21_HOSTED_URL"); v != "" {
		return v
	}
	return defaultHostedURL
}

func PublicKeyEnvName(keyID string) string {
	// hosted-ed25519-v1 -> PINS21_HOSTED_PUBLIC_KEY_HOSTED_ED25519_V1
	s := strings.ToUpper(keyID)
	s = strings.NewReplacer("-", "_", ".", "_").Replace(s)
	return "PINS21_HOSTED_PUBLIC_KEY_" + s
}

func PublicKeyFromEnv(keyID string) (ed25519.PublicKey, error) {
	envName := PublicKeyEnvName(keyID)
	b64 := os.Getenv(envName)
	if b64 == "" {
		return nil, fmt.Errorf("env %s not set", envName)
	}
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", envName, err)
	}
	if len(decoded) == ed25519.PublicKeySize {
		return ed25519.PublicKey(decoded), nil
	}
	parsed, err := x509.ParsePKIXPublicKey(decoded)
	if err == nil {
		if pub, ok := parsed.(ed25519.PublicKey); ok {
			return pub, nil
		}
	}
	return nil, fmt.Errorf("%s: expected raw Ed25519 public key or DER SPKI public key", envName)
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (c *Client) baseURL() string {
	if strings.TrimSpace(c.BaseURL) != "" {
		return c.BaseURL
	}
	return DefaultBaseURL()
}

func (c *Client) Status(ctx context.Context) Status {
	baseURL := c.baseURL()
	u := strings.TrimRight(baseURL, "/") + "/health"
	s := Status{URL: baseURL, CheckedAt: time.Now().UTC()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		s.State = "offline"
		s.Error = err.Error()
		return s
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		s.State = "offline"
		s.Error = err.Error()
		return s
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		s.State = "reachable"
		s.CKAttestationAvailable = true
		return s
	}
	s.State = "degraded"
	s.Error = fmt.Sprintf("health check returned %d", resp.StatusCode)
	return s
}

func (c *Client) StartAttestationSession(ctx context.Context, ttlMinutes int) (SessionStart, error) {
	u := strings.TrimRight(c.baseURL(), "/") + "/v1/ck/attestation-sessions"
	body := map[string]any{
		"audience":              "21pins",
		"purpose":               "grant_create",
		"requested_ttl_minutes": ttlMinutes,
	}
	b, err := json.Marshal(body)
	if err != nil {
		return SessionStart{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return SessionStart{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return SessionStart{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return SessionStart{}, fmt.Errorf("hosted returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var s SessionStart
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return SessionStart{}, err
	}
	return s, nil
}

func (c *Client) PollAttestation(ctx context.Context, sessionID, userCode string) (PollResponse, error) {
	u := strings.TrimRight(c.baseURL(), "/") + "/v1/ck/attestation-sessions/" + sessionID + "?user_code=" + url.QueryEscape(userCode)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return PollResponse{}, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return PollResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return PollResponse{}, fmt.Errorf("hosted returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var pr PollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return PollResponse{}, err
	}
	return pr, nil
}

func (c *Client) CompleteHostedAttestation(ctx context.Context, ttlMinutes int, expectedIssuer string, now time.Time, out io.Writer) (policy.IdentityAttestation, error) {
	session, err := c.StartAttestationSession(ctx, ttlMinutes)
	if err != nil {
		return policy.IdentityAttestation{}, fmt.Errorf("start session: %w", err)
	}

	fmt.Fprintf(out, "Verification URL: %s\n", session.VerificationURL)
	fmt.Fprintf(out, "User code: %s\n", session.UserCode)
	fmt.Fprintf(out, "Session ID: %s\n", session.SessionID)

	pollInterval := session.PollIntervalSeconds
	if pollInterval < 1 {
		pollInterval = 2
	}
	ticker := time.NewTicker(time.Duration(pollInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return policy.IdentityAttestation{}, ctx.Err()
		case <-ticker.C:
			resp, err := c.PollAttestation(ctx, session.SessionID, session.UserCode)
			if err != nil {
				return policy.IdentityAttestation{}, fmt.Errorf("poll session: %w", err)
			}
			switch resp.Status {
			case "pending":
				continue
			case "approved":
				if resp.Attestation == nil {
					return policy.IdentityAttestation{}, fmt.Errorf("hosted approved but missing attestation")
				}
				issuer := strings.TrimSpace(session.Issuer)
				if issuer == "" {
					issuer = expectedIssuer
				}
				if strings.TrimSpace(resp.Attestation.Issuer) != issuer {
					return policy.IdentityAttestation{}, fmt.Errorf("attestation issuer mismatch")
				}
				if err := VerifyStoredAttestation(*resp.Attestation, now); err != nil {
					return policy.IdentityAttestation{}, fmt.Errorf("attestation verification: %w", err)
				}
				return *resp.Attestation, nil
			case "denied":
				return policy.IdentityAttestation{}, fmt.Errorf("hosted attestation denied: %s", resp.Error)
			case "expired":
				return policy.IdentityAttestation{}, fmt.Errorf("hosted attestation session expired: %s", resp.Error)
			default:
				return policy.IdentityAttestation{}, fmt.Errorf("unexpected poll status: %s", resp.Status)
			}
		}
	}
}
