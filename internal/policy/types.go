package policy

import "time"

type GrantStatus string

const (
	GrantStatusActive  GrantStatus = "active"
	GrantStatusRevoked GrantStatus = "revoked"
	GrantStatusExpired GrantStatus = "expired"
)

type Grant struct {
	ID          string      `json:"grant_id"`
	Sub         string      `json:"sub"`
	Status      GrantStatus `json:"status"`
	DelegatedBy string      `json:"delegated_by,omitempty"`
	Pins        Pins        `json:"pins"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	RevokedAt   *time.Time  `json:"revoked_at,omitempty"`
}

type Pins struct {
	Identity         IdentityPin        `json:"identity"`
	Authority        AuthorityPin       `json:"authority_chain"`
	Capabilities     CapabilityPin      `json:"capabilities"`
	DataPolicy       DataPolicyPin      `json:"data_policy"`
	SpendPolicy      SpendPolicyPin     `json:"spend_policy"`
	ExecutionTargets ExecutionTargetPin `json:"execution_targets"`
	ApprovalPolicy   ApprovalPolicyPin  `json:"approval_policy"`
}

type IdentityPin struct {
	Sub string `json:"sub"`
}

type AuthorityPin struct {
	Chain []string `json:"chain"`
}

type CapabilityPin struct {
	Allowed []string `json:"allowed"`
}

type DataPolicyPin struct {
	AllowedClasses []string `json:"allowed_classes"`
}

type SpendPolicyPin struct {
	LimitCents  int64     `json:"limit_cents"`
	SpentCents  int64     `json:"spent_cents"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
}

type ExecutionTargetPin struct {
	AllowedTargets []string `json:"allowed_targets"`
}

type ApprovalPolicyPin struct {
	ThresholdCents int64 `json:"threshold_cents"`
}

type PinStatus string

const (
	PinPass             PinStatus = "pass"
	PinFail             PinStatus = "fail"
	PinRequiresApproval PinStatus = "requires_approval"
)

type Decision string

const (
	DecisionAllow           Decision = "allow"
	DecisionBlock           Decision = "block"
	DecisionRequireApproval Decision = "require_approval"
)

type ActionRequest struct {
	GrantID         string `json:"grant_id"`
	Sub             string `json:"sub"`
	Capability      string `json:"capability"`
	DataClass       string `json:"data_class"`
	Target          string `json:"target"`
	CostCents       int64  `json:"cost_cents"`
	ApprovalID      string `json:"approval_id,omitempty"`
	ApprovalGranted bool   `json:"approval_granted,omitempty"`
}

type EvaluationResult struct {
	Decision  Decision             `json:"decision"`
	PinStates map[string]PinStatus `json:"pin_states"`
	Reasons   map[string]string    `json:"reasons,omitempty"`
}

type Receipt struct {
	ID          string               `json:"receipt_id"`
	GrantID     string               `json:"grant_id"`
	Sub         string               `json:"sub"`
	Authority   []string             `json:"authority_chain"`
	PinStates   map[string]PinStatus `json:"pin_states"`
	Decision    Decision             `json:"decision"`
	Capability  string               `json:"capability"`
	DataClass   string               `json:"data_class"`
	Target      string               `json:"target"`
	CostCents   int64                `json:"cost_cents"`
	ApprovalRef string               `json:"approval_ref,omitempty"`
	CreatedAt   time.Time            `json:"created_at"`
	KeyID       string               `json:"key_id,omitempty"`
	Signature   string               `json:"signature,omitempty"`
}

type GrantExportPayload struct {
	GrantID      string    `json:"grant_id"`
	Sub          string    `json:"sub"`
	PinsSnapshot Pins      `json:"pins_snapshot"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	KeyID        string    `json:"key_id"`
}

type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalRejected ApprovalStatus = "rejected"
)

type ApprovalRequest struct {
	ID          string         `json:"approval_id"`
	GrantID     string         `json:"grant_id"`
	ReceiptID   string         `json:"receipt_id"`
	Sub         string         `json:"sub"`
	Capability  string         `json:"capability"`
	DataClass   string         `json:"data_class"`
	Target      string         `json:"target"`
	CostCents   int64          `json:"cost_cents"`
	Status      ApprovalStatus `json:"status"`
	RequestedAt time.Time      `json:"requested_at"`
	ResolvedAt  *time.Time     `json:"resolved_at,omitempty"`
	ApproverSub string         `json:"approver_sub,omitempty"`
	Reason      string         `json:"reason,omitempty"`
}
