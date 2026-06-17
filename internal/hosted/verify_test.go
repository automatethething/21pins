package hosted

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/petrichor/21pins-cli/internal/policy"
)

func TestVerifyStoredAttestationUsesSignedIssuer(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	att, err := policy.SignIdentityAttestationForTest(policy.IdentityAttestation{ID: "att", Subject: "approver", Issuer: "https://staging.21pins.test", Audience: "21pins", Method: "hosted_ck", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), KeyID: "hosted-ed25519-v1"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PINS21_HOSTED_PUBLIC_KEY_HOSTED_ED25519_V1", base64.StdEncoding.EncodeToString(pub))
	if err := VerifyStoredAttestation(att, now); err != nil {
		t.Fatalf("expected custom issuer attestation to verify: %v", err)
	}
}

func TestVerifyStoredAttestationRejectsNonHTTPSIssuer(t *testing.T) {
	now := time.Now().UTC()
	att := policy.IdentityAttestation{ID: "att", Subject: "approver", Issuer: "http://localhost:3000", Audience: "21pins", Method: "hosted_ck", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), KeyID: "hosted-ed25519-v1"}
	if err := VerifyStoredAttestation(att, now); err == nil {
		t.Fatal("expected non-https issuer to fail")
	}
}
