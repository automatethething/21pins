package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

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
