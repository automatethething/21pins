package hosted

import (
	"context"
	"fmt"
	"strings"
)

const DefaultSmokeKeyID = "hosted-ed25519-v1"

type SmokeReport struct {
	URL             string `json:"url"`
	HealthState     string `json:"health_state"`
	SessionID       string `json:"session_id,omitempty"`
	PollStatus      string `json:"poll_status,omitempty"`
	PublicKeyEnv    string `json:"public_key_env,omitempty"`
	PublicKeyLoaded bool   `json:"public_key_loaded"`
}

// VerifySmokePublicKeyEnv checks that the pinned hosted public key env var is set and decodes.
func VerifySmokePublicKeyEnv(keyID string) error {
	if strings.TrimSpace(keyID) == "" {
		keyID = DefaultSmokeKeyID
	}
	_, err := PublicKeyFromEnv(keyID)
	return err
}

// Smoke runs post-deploy checks against the hosted control plane:
// GET /health, POST /v1/ck/attestation-sessions, GET poll (expect pending).
// It optionally records whether the pinned public key env var loads; full signature
// verification is covered by unit tests in this package and internal/policy.
func (c *Client) Smoke(ctx context.Context, keyID string) (SmokeReport, error) {
	report := SmokeReport{URL: c.baseURL()}
	if strings.TrimSpace(keyID) == "" {
		keyID = DefaultSmokeKeyID
	}
	report.PublicKeyEnv = PublicKeyEnvName(keyID)
	if err := VerifySmokePublicKeyEnv(keyID); err == nil {
		report.PublicKeyLoaded = true
	}

	status := c.Status(ctx)
	report.HealthState = status.State
	if status.State != "reachable" {
		return report, fmt.Errorf("health check: %s (%s)", status.State, status.Error)
	}

	session, err := c.StartAttestationSession(ctx, 60)
	if err != nil {
		return report, fmt.Errorf("start session: %w", err)
	}
	if strings.TrimSpace(session.SessionID) == "" {
		return report, fmt.Errorf("start session: missing session_id")
	}
	report.SessionID = session.SessionID

	poll, err := c.PollAttestation(ctx, session.SessionID, session.UserCode)
	if err != nil {
		return report, fmt.Errorf("poll session: %w", err)
	}
	report.PollStatus = poll.Status
	if poll.Status != "pending" {
		return report, fmt.Errorf("poll session: expected pending, got %q", poll.Status)
	}
	return report, nil
}
