package policy

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

func NewReceipt(grant Grant, req ActionRequest, result EvaluationResult, now time.Time) Receipt {
	return Receipt{
		ID:         NewID("rcp"),
		GrantID:    grant.ID,
		Sub:        req.Sub,
		Authority:  grant.Pins.Authority.Chain,
		PinStates:  result.PinStates,
		Decision:   result.Decision,
		Capability: req.Capability,
		DataClass:  req.DataClass,
		Target:     req.Target,
		CostCents:  req.CostCents,
		CreatedAt:  now,
	}
}

type signableReceipt struct {
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
}

func SignReceipt(r Receipt, privateKey ed25519.PrivateKey, keyID string) (Receipt, error) {
	payload, err := receiptPayloadBytes(r)
	if err != nil {
		return Receipt{}, err
	}
	sig := ed25519.Sign(privateKey, payload)
	r.KeyID = keyID
	r.Signature = base64.RawURLEncoding.EncodeToString(sig)
	return r, nil
}

func VerifyReceipt(r Receipt, publicKey ed25519.PublicKey) error {
	if r.Signature == "" {
		return errors.New("missing receipt signature")
	}
	payload, err := receiptPayloadBytes(r)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(r.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return errors.New("invalid receipt signature")
	}
	return nil
}

func receiptPayloadBytes(r Receipt) ([]byte, error) {
	s := signableReceipt{
		ID:          r.ID,
		GrantID:     r.GrantID,
		Sub:         r.Sub,
		Authority:   r.Authority,
		PinStates:   r.PinStates,
		Decision:    r.Decision,
		Capability:  r.Capability,
		DataClass:   r.DataClass,
		Target:      r.Target,
		CostCents:   r.CostCents,
		ApprovalRef: r.ApprovalRef,
		CreatedAt:   r.CreatedAt,
	}
	return json.Marshal(s)
}
