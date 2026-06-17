package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestReceiptIncludesIdentityAttestationIDAndSignatureCoversIt(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	grant := Grant{
		ID:  "grt_123",
		Sub: "ck_sub_abc",
		Pins: Pins{
			Identity:  IdentityPin{Sub: "ck_sub_abc"},
			Authority: AuthorityPin{Chain: []string{"ck_sub_abc"}},
		},
		IdentityAttestation: &IdentityAttestation{ID: "att_123", Subject: "ck_sub_abc"},
	}
	req := ActionRequest{GrantID: grant.ID, Sub: "ck_sub_abc", Capability: "llm.chat", DataClass: "public", Target: "openrouter"}
	result := EvaluationResult{Decision: DecisionAllow, PinStates: map[string]PinStatus{"identity": "pass"}}
	receipt := NewReceipt(grant, req, result, now)
	if receipt.IdentityAttestationID != "att_123" {
		t.Fatalf("missing attestation id: %+v", receipt)
	}
	signed, err := SignReceipt(receipt, priv, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceipt(signed, pub); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	signed.IdentityAttestationID = "att_other"
	if err := VerifyReceipt(signed, pub); err == nil {
		t.Fatal("expected tampered attestation id to fail")
	}
}

func TestReceiptSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	r := Receipt{
		ID:         "rcp_123",
		GrantID:    "grt_123",
		Sub:        "ck_sub_123",
		Authority:  []string{"ck_sub_123"},
		PinStates:  map[string]PinStatus{"identity": PinPass},
		Decision:   DecisionAllow,
		Capability: "data.lookup",
		DataClass:  "public",
		Target:     "api.vendor.com",
		CostCents:  250,
		CreatedAt:  time.Now().UTC(),
	}

	signed, err := SignReceipt(r, priv, "local-ed25519-v1")
	if err != nil {
		t.Fatalf("SignReceipt failed: %v", err)
	}
	if signed.Signature == "" {
		t.Fatal("expected signature")
	}
	if err := VerifyReceipt(signed, pub); err != nil {
		t.Fatalf("VerifyReceipt failed: %v", err)
	}
}
