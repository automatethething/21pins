package policy

import (
	"strings"
	"time"
)

func EvaluateAction(grant Grant, req ActionRequest, now time.Time) EvaluationResult {
	pinStates := map[string]PinStatus{}
	reasons := map[string]string{}

	if grant.Status != GrantStatusActive {
		pinStates["identity"] = PinFail
		reasons["identity"] = "grant is not active"
	} else if req.Sub == "" || req.Sub != grant.Pins.Identity.Sub || req.Sub != grant.Sub {
		pinStates["identity"] = PinFail
		reasons["identity"] = "subject mismatch"
	} else {
		pinStates["identity"] = PinPass
	}

	if len(grant.Pins.Authority.Chain) == 0 {
		pinStates["authority_chain"] = PinFail
		reasons["authority_chain"] = "missing authority chain"
	} else {
		leaf := strings.TrimSpace(grant.Pins.Authority.Chain[len(grant.Pins.Authority.Chain)-1])
		if leaf == "" || !strings.EqualFold(leaf, req.Sub) {
			pinStates["authority_chain"] = PinFail
			reasons["authority_chain"] = "authority leaf does not match acting subject"
		} else {
			pinStates["authority_chain"] = PinPass
		}
	}

	if contains(grant.Pins.Capabilities.Allowed, req.Capability) {
		pinStates["capabilities"] = PinPass
	} else {
		pinStates["capabilities"] = PinFail
		reasons["capabilities"] = "capability not allowed"
	}

	if contains(grant.Pins.DataPolicy.AllowedClasses, req.DataClass) {
		pinStates["data_policy"] = PinPass
	} else {
		pinStates["data_policy"] = PinFail
		reasons["data_policy"] = "data class not allowed"
	}

	sp := grant.Pins.SpendPolicy
	if now.Before(sp.WindowStart) || now.After(sp.WindowEnd) {
		pinStates["spend_policy"] = PinFail
		reasons["spend_policy"] = "outside spend window"
	} else if sp.SpentCents+req.CostCents > sp.LimitCents {
		pinStates["spend_policy"] = PinFail
		reasons["spend_policy"] = "budget exceeded"
	} else {
		pinStates["spend_policy"] = PinPass
	}

	if contains(grant.Pins.ExecutionTargets.AllowedTargets, req.Target) {
		pinStates["execution_targets"] = PinPass
	} else {
		pinStates["execution_targets"] = PinFail
		reasons["execution_targets"] = "target not allowed"
	}

	if grant.Pins.ApprovalPolicy.ThresholdCents > 0 && req.CostCents >= grant.Pins.ApprovalPolicy.ThresholdCents {
		if req.ApprovalGranted {
			pinStates["approval"] = PinPass
		} else {
			pinStates["approval"] = PinRequiresApproval
			reasons["approval"] = "cost crosses approval threshold"
		}
	} else {
		pinStates["approval"] = PinPass
	}

	decision := DecisionAllow
	for _, st := range pinStates {
		if st == PinFail {
			decision = DecisionBlock
			break
		}
	}
	if decision == DecisionAllow {
		for _, st := range pinStates {
			if st == PinRequiresApproval {
				decision = DecisionRequireApproval
				break
			}
		}
	}

	return EvaluationResult{Decision: decision, PinStates: pinStates, Reasons: reasons}
}

func contains(items []string, value string) bool {
	value = strings.TrimSpace(value)
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), value) {
			return true
		}
	}
	return false
}
