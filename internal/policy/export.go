package policy

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

func SignGrantExport(grant Grant, privateKey ed25519.PrivateKey, keyID string, now time.Time, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	payload := GrantExportPayload{
		GrantID:      grant.ID,
		Sub:          grant.Sub,
		PinsSnapshot: grant.Pins,
		IssuedAt:     now,
		ExpiresAt:    now.Add(ttl),
		KeyID:        keyID,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(privateKey, b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func VerifyGrantExport(token string, publicKey ed25519.PublicKey, now time.Time) (GrantExportPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return GrantExportPayload{}, errors.New("invalid token format")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return GrantExportPayload{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return GrantExportPayload{}, err
	}
	if !ed25519.Verify(publicKey, payloadBytes, sig) {
		return GrantExportPayload{}, errors.New("invalid signature")
	}
	var payload GrantExportPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return GrantExportPayload{}, err
	}
	if now.After(payload.ExpiresAt) {
		return GrantExportPayload{}, errors.New("grant export expired")
	}
	return payload, nil
}
