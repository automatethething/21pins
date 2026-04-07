package policy

import (
	"testing"
	"time"
)

func TestEvaluateAllow(t *testing.T) {
	now := time.Now().UTC()
	g := Grant{
		ID:     "grt_123",
		Sub:    "ck_sub_abc",
		Status: GrantStatusActive,
		Pins: Pins{
			Identity:         IdentityPin{Sub: "ck_sub_abc"},
			Authority:        AuthorityPin{Chain: []string{"ck_sub_abc"}},
			Capabilities:     CapabilityPin{Allowed: []string{"llm.chat"}},
			DataPolicy:       DataPolicyPin{AllowedClasses: []string{"public"}},
			SpendPolicy:      SpendPolicyPin{LimitCents: 1000, WindowStart: now.Add(-time.Hour), WindowEnd: now.Add(time.Hour), SpentCents: 100},
			ExecutionTargets: ExecutionTargetPin{AllowedTargets: []string{"openrouter"}},
			ApprovalPolicy:   ApprovalPolicyPin{ThresholdCents: 900},
		},
	}

	res := EvaluateAction(g, ActionRequest{
		GrantID:    g.ID,
		Sub:        "ck_sub_abc",
		Capability: "llm.chat",
		DataClass:  "public",
		Target:     "openrouter",
		CostCents:  200,
	}, now)

	if res.Decision != DecisionAllow {
		t.Fatalf("expected allow, got %s", res.Decision)
	}
}

func TestEvaluateRequireApproval(t *testing.T) {
	now := time.Now().UTC()
	g := Grant{
		ID:     "grt_123",
		Sub:    "ck_sub_abc",
		Status: GrantStatusActive,
		Pins: Pins{
			Identity:         IdentityPin{Sub: "ck_sub_abc"},
			Authority:        AuthorityPin{Chain: []string{"ck_sub_abc"}},
			Capabilities:     CapabilityPin{Allowed: []string{"llm.chat"}},
			DataPolicy:       DataPolicyPin{AllowedClasses: []string{"public"}},
			SpendPolicy:      SpendPolicyPin{LimitCents: 1000, WindowStart: now.Add(-time.Hour), WindowEnd: now.Add(time.Hour), SpentCents: 100},
			ExecutionTargets: ExecutionTargetPin{AllowedTargets: []string{"openrouter"}},
			ApprovalPolicy:   ApprovalPolicyPin{ThresholdCents: 250},
		},
	}

	res := EvaluateAction(g, ActionRequest{GrantID: g.ID, Sub: "ck_sub_abc", Capability: "llm.chat", DataClass: "public", Target: "openrouter", CostCents: 300}, now)
	if res.Decision != DecisionRequireApproval {
		t.Fatalf("expected require_approval, got %s", res.Decision)
	}
	if res.PinStates["approval"] != PinRequiresApproval {
		t.Fatalf("expected approval pin requires_approval, got %s", res.PinStates["approval"])
	}
}

func TestEvaluateAllowWithApprovalGrant(t *testing.T) {
	now := time.Now().UTC()
	g := Grant{
		ID:     "grt_123",
		Sub:    "ck_sub_abc",
		Status: GrantStatusActive,
		Pins: Pins{
			Identity:         IdentityPin{Sub: "ck_sub_abc"},
			Authority:        AuthorityPin{Chain: []string{"ck_sub_abc"}},
			Capabilities:     CapabilityPin{Allowed: []string{"llm.chat"}},
			DataPolicy:       DataPolicyPin{AllowedClasses: []string{"public"}},
			SpendPolicy:      SpendPolicyPin{LimitCents: 1000, WindowStart: now.Add(-time.Hour), WindowEnd: now.Add(time.Hour), SpentCents: 100},
			ExecutionTargets: ExecutionTargetPin{AllowedTargets: []string{"openrouter"}},
			ApprovalPolicy:   ApprovalPolicyPin{ThresholdCents: 250},
		},
	}

	res := EvaluateAction(g, ActionRequest{GrantID: g.ID, Sub: "ck_sub_abc", Capability: "llm.chat", DataClass: "public", Target: "openrouter", CostCents: 300, ApprovalGranted: true}, now)
	if res.Decision != DecisionAllow {
		t.Fatalf("expected allow, got %s", res.Decision)
	}
	if res.PinStates["approval"] != PinPass {
		t.Fatalf("expected approval pin pass, got %s", res.PinStates["approval"])
	}
}

func TestEvaluateBlockWhenAuthorityLeafMismatch(t *testing.T) {
	now := time.Now().UTC()
	g := Grant{
		ID:     "grt_123",
		Sub:    "ck_sub_abc",
		Status: GrantStatusActive,
		Pins: Pins{
			Identity:         IdentityPin{Sub: "ck_sub_abc"},
			Authority:        AuthorityPin{Chain: []string{"ck_sub_org", "ck_sub_agent"}},
			Capabilities:     CapabilityPin{Allowed: []string{"llm.chat"}},
			DataPolicy:       DataPolicyPin{AllowedClasses: []string{"public"}},
			SpendPolicy:      SpendPolicyPin{LimitCents: 1000, WindowStart: now.Add(-time.Hour), WindowEnd: now.Add(time.Hour), SpentCents: 0},
			ExecutionTargets: ExecutionTargetPin{AllowedTargets: []string{"openrouter"}},
			ApprovalPolicy:   ApprovalPolicyPin{ThresholdCents: 0},
		},
	}
	res := EvaluateAction(g, ActionRequest{GrantID: g.ID, Sub: "ck_sub_abc", Capability: "llm.chat", DataClass: "public", Target: "openrouter", CostCents: 10}, now)
	if res.Decision != DecisionBlock {
		t.Fatalf("expected block, got %s", res.Decision)
	}
	if res.PinStates["authority_chain"] != PinFail {
		t.Fatalf("expected authority_chain fail, got %s", res.PinStates["authority_chain"])
	}
}

func TestEvaluateBlockOnRevokedGrant(t *testing.T) {
	now := time.Now().UTC()
	g := Grant{ID: "grt_123", Sub: "ck_sub_abc", Status: GrantStatusRevoked}
	res := EvaluateAction(g, ActionRequest{GrantID: g.ID, Sub: "ck_sub_abc"}, now)
	if res.Decision != DecisionBlock {
		t.Fatalf("expected block, got %s", res.Decision)
	}
	if res.PinStates["identity"] != PinFail {
		t.Fatalf("expected identity pin fail, got %s", res.PinStates["identity"])
	}
}
