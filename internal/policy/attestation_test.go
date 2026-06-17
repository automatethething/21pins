package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func signedTestAttestation(t *testing.T, mutate func(*IdentityAttestation), now time.Time) (IdentityAttestation, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := IdentityAttestation{
		ID:        "att_123",
		Subject:   "ck_sub_abc",
		Issuer:    "https://21pins.com",
		Audience:  "21pins",
		Method:    "hosted_ck",
		IssuedAt:  now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
		KeyID:     "hosted-ed25519-v1",
	}
	if mutate != nil {
		mutate(&a)
	}
	signed, err := SignIdentityAttestationForTest(a, priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed, pub
}

func TestVerifyIdentityAttestationValid(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	a, pub := signedTestAttestation(t, nil, now)
	if err := VerifyIdentityAttestation(a, pub, "https://21pins.com", now); err != nil {
		t.Fatalf("expected valid attestation: %v", err)
	}
}

func TestVerifyIdentityAttestationAcceptsOIDCSubject(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	a, pub := signedTestAttestation(t, func(a *IdentityAttestation) { a.Subject = "user-123@example.test" }, now)
	if err := VerifyIdentityAttestation(a, pub, "https://21pins.com", now); err != nil {
		t.Fatalf("expected OIDC subject to verify: %v", err)
	}
}

func TestVerifyIdentityAttestationRejectsBadSignature(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	a, pub := signedTestAttestation(t, nil, now)
	a.Subject = "ck_sub_evil"
	if err := VerifyIdentityAttestation(a, pub, "https://21pins.com", now); err == nil {
		t.Fatal("expected bad signature rejection")
	}
}

func TestVerifyIdentityAttestationRejectsWrongAudience(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	a, pub := signedTestAttestation(t, func(a *IdentityAttestation) { a.Audience = "other" }, now)
	if err := VerifyIdentityAttestation(a, pub, "https://21pins.com", now); err == nil {
		t.Fatal("expected wrong audience rejection")
	}
}

func TestVerifyIdentityAttestationAllowsSmallClockSkew(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	a, pub := signedTestAttestation(t, func(a *IdentityAttestation) { a.IssuedAt = now.Add(90 * time.Second) }, now)
	if err := VerifyIdentityAttestation(a, pub, "https://21pins.com", now); err != nil {
		t.Fatalf("expected small clock skew to verify: %v", err)
	}
}

func TestVerifyIdentityAttestationAllowsSmallExpiryClockSkew(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	a, pub := signedTestAttestation(t, func(a *IdentityAttestation) { a.ExpiresAt = now.Add(-90 * time.Second) }, now)
	if err := VerifyIdentityAttestation(a, pub, "https://21pins.com", now); err != nil {
		t.Fatalf("expected small expiry skew to verify: %v", err)
	}
}

func TestVerifyIdentityAttestationRejectsExpired(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	a, pub := signedTestAttestation(t, func(a *IdentityAttestation) { a.ExpiresAt = now.Add(-3 * time.Minute) }, now)
	if err := VerifyIdentityAttestation(a, pub, "https://21pins.com", now); err == nil {
		t.Fatal("expected expired rejection")
	}
}
