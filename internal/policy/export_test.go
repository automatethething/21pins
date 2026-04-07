package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestSignedExportRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	g := Grant{ID: "grt_123", Sub: "ck_sub_abc", Status: GrantStatusActive, Pins: Pins{Identity: IdentityPin{Sub: "ck_sub_abc"}}}
	now := time.Now().UTC()
	tok, err := SignGrantExport(g, priv, "local-ed25519-v1", now, 15*time.Minute)
	if err != nil {
		t.Fatalf("SignGrantExport failed: %v", err)
	}

	exp, err := VerifyGrantExport(tok, pub, now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("VerifyGrantExport failed: %v", err)
	}
	if exp.GrantID != g.ID || exp.Sub != g.Sub {
		t.Fatalf("unexpected export payload: %+v", exp)
	}
}
