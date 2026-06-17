package policy

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
)

var ckSubPattern = regexp.MustCompile(`^[A-Za-z0-9._:@/-]{3,256}$`)

type signableIdentityAttestation struct {
	ID        string    `json:"attestation_id"`
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	Audience  string    `json:"audience"`
	Method    string    `json:"method"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	KeyID     string    `json:"key_id"`
}

func VerifyIdentityAttestation(a IdentityAttestation, publicKey ed25519.PublicKey, expectedIssuer string, now time.Time) error {
	if strings.TrimSpace(a.ID) == "" {
		return errors.New("missing attestation id")
	}
	if !ckSubPattern.MatchString(a.Subject) {
		return errors.New("invalid attestation subject")
	}
	if a.Issuer != expectedIssuer {
		return errors.New("invalid attestation issuer")
	}
	if a.Audience != "21pins" {
		return errors.New("invalid attestation audience")
	}
	if a.Method != "hosted_ck" {
		return errors.New("invalid attestation method")
	}
	if now.Add(2*time.Minute).Before(a.IssuedAt) || !now.Add(-2*time.Minute).Before(a.ExpiresAt) {
		return errors.New("attestation is not currently valid")
	}
	payload, err := identityAttestationPayloadBytes(a)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(a.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return errors.New("invalid attestation signature")
	}
	return nil
}

func identityAttestationPayloadBytes(a IdentityAttestation) ([]byte, error) {
	return json.Marshal(signableIdentityAttestation{
		ID:        a.ID,
		Subject:   a.Subject,
		Issuer:    a.Issuer,
		Audience:  a.Audience,
		Method:    a.Method,
		IssuedAt:  a.IssuedAt,
		ExpiresAt: a.ExpiresAt,
		KeyID:     a.KeyID,
	})
}

func SignIdentityAttestationForTest(a IdentityAttestation, privateKey ed25519.PrivateKey) (IdentityAttestation, error) {
	payload, err := identityAttestationPayloadBytes(a)
	if err != nil {
		return IdentityAttestation{}, err
	}
	a.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return a, nil
}
