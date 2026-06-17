package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/petrichor/21pins-cli/internal/policy"
	"github.com/petrichor/21pins-cli/internal/store"
)

func TestValidateApprovalForActionRequiresApproverAttestation(t *testing.T) {
	a := policy.ApprovalRequest{Status: policy.ApprovalApproved, GrantID: "g", Sub: "s", Capability: "llm.chat", DataClass: "public", Target: "openrouter", CostCents: 7, ApproverSub: "approver"}
	if err := validateApprovalForAction(a, "g", "s", "llm.chat", "public", "openrouter", 7, time.Now().UTC()); err == nil {
		t.Fatal("expected missing approver attestation to fail")
	}
}

func TestValidateApprovalForActionAcceptsValidApproverAttestation(t *testing.T) {
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
	a := policy.ApprovalRequest{Status: policy.ApprovalApproved, GrantID: "g", Sub: "s", Capability: "llm.chat", DataClass: "public", Target: "openrouter", CostCents: 7, ApproverSub: "approver", ApproverAttestation: &att}
	if err := validateApprovalForAction(a, "g", "s", "llm.chat", "public", "openrouter", 7, now); err != nil {
		t.Fatalf("expected valid approval: %v", err)
	}
}

func TestEvaluateWithApprovalStoresApprovalRefOnReceipt(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	att, err := policy.SignIdentityAttestationForTest(policy.IdentityAttestation{ID: "att", Subject: "approver", Issuer: "https://21pins.com", Audience: "21pins", Method: "hosted_ck", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), KeyID: "hosted-ed25519-v1"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PINS21_HOSTED_PUBLIC_KEY_HOSTED_ED25519_V1", base64.StdEncoding.EncodeToString(pub))

	st, err := store.New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := st.CreateGrant(policy.Grant{Sub: "s", Pins: policy.Pins{Identity: policy.IdentityPin{Sub: "s"}, Authority: policy.AuthorityPin{Chain: []string{"s"}}, Capabilities: policy.CapabilityPin{Allowed: []string{"llm.chat"}}, DataPolicy: policy.DataPolicyPin{AllowedClasses: []string{"public"}}, SpendPolicy: policy.SpendPolicyPin{LimitCents: 100, WindowStart: now.Add(-time.Hour), WindowEnd: now.Add(time.Hour)}, ExecutionTargets: policy.ExecutionTargetPin{AllowedTargets: []string{"openrouter"}}, ApprovalPolicy: policy.ApprovalPolicyPin{ThresholdCents: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	approval, err := st.CreateApproval(policy.ApprovalRequest{GrantID: grant.ID, Sub: "s", Capability: "llm.chat", DataClass: "public", Target: "openrouter", CostCents: 7})
	if err != nil {
		t.Fatal(err)
	}
	approval, err = st.ResolveApprovalWithAttestation(approval.ID, policy.ApprovalApproved, "approver", "ok", att)
	if err != nil {
		t.Fatal(err)
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	handleEvaluate(st, []string{"--grant", grant.ID, "--sub", "s", "--capability", "llm.chat", "--data-class", "public", "--target", "openrouter", "--cost-cents", "7", "--approval-id", approval.ID, "--json"})
	_ = w.Close()
	os.Stdout = old
	_, _ = io.ReadAll(r)
	receipts := st.ListReceipts(grant.ID)
	if len(receipts) != 1 || receipts[0].ApprovalRef != approval.ID {
		t.Fatalf("expected receipt approval ref %q, got %#v", approval.ID, receipts)
	}
}

func TestParseOpenRouterPricing(t *testing.T) {
	price := parseOpenRouterPriceToMicrosPerMillion("0.00000015")
	if price != 150_000 {
		t.Fatalf("expected 150000, got %d", price)
	}
}
