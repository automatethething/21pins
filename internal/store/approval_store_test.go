package store

import (
	"path/filepath"
	"testing"

	"github.com/petrichor/21pins-cli/internal/policy"
)

func TestApprovalLifecycle(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	grant, err := s.CreateGrant(policy.Grant{
		Sub: "ck_sub_abc",
		Pins: policy.Pins{
			Identity:  policy.IdentityPin{Sub: "ck_sub_abc"},
			Authority: policy.AuthorityPin{Chain: []string{"ck_sub_abc"}},
		},
	})
	if err != nil {
		t.Fatalf("CreateGrant failed: %v", err)
	}

	approval, err := s.CreateApproval(policy.ApprovalRequest{
		GrantID:    grant.ID,
		ReceiptID:  "rcp_x",
		Sub:        "ck_sub_abc",
		Capability: "llm.chat",
		DataClass:  "public",
		Target:     "openrouter",
		CostCents:  500,
	})
	if err != nil {
		t.Fatalf("CreateApproval failed: %v", err)
	}
	if approval.Status != policy.ApprovalPending {
		t.Fatalf("expected pending, got %s", approval.Status)
	}

	resolved, err := s.ResolveApproval(approval.ID, policy.ApprovalApproved, "ck_sub_admin", "ok")
	if err != nil {
		t.Fatalf("ResolveApproval failed: %v", err)
	}
	if resolved.Status != policy.ApprovalApproved {
		t.Fatalf("expected approved, got %s", resolved.Status)
	}
	if resolved.ApproverSub != "ck_sub_admin" {
		t.Fatalf("unexpected approver: %s", resolved.ApproverSub)
	}
}
