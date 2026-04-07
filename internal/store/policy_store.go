package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/petrichor/21pins-cli/internal/policy"
)

type SigningKeys struct {
	KeyID         string `json:"key_id"`
	PublicKeyB64  string `json:"public_key_b64"`
	PrivateKeyB64 string `json:"private_key_b64"`
}

func (s *Store) ensurePolicyState() {
	if s.state.Grants == nil {
		s.state.Grants = []policy.Grant{}
	}
	if s.state.Receipts == nil {
		s.state.Receipts = []policy.Receipt{}
	}
	if s.state.Approvals == nil {
		s.state.Approvals = []policy.ApprovalRequest{}
	}
}

func (s *Store) EnsureSigningKeys() (SigningKeys, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePolicyState()
	if s.state.SigningKeys.KeyID != "" {
		return s.state.SigningKeys, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SigningKeys{}, err
	}
	s.state.SigningKeys = SigningKeys{
		KeyID:         "local-ed25519-v1",
		PublicKeyB64:  base64.StdEncoding.EncodeToString(pub),
		PrivateKeyB64: base64.StdEncoding.EncodeToString(priv),
	}
	if err := s.saveLocked(); err != nil {
		return SigningKeys{}, err
	}
	return s.state.SigningKeys, nil
}

func (s *Store) SigningKeypair() (ed25519.PublicKey, ed25519.PrivateKey, string, error) {
	keys, err := s.EnsureSigningKeys()
	if err != nil {
		return nil, nil, "", err
	}
	pubRaw, err := base64.StdEncoding.DecodeString(keys.PublicKeyB64)
	if err != nil {
		return nil, nil, "", err
	}
	privRaw, err := base64.StdEncoding.DecodeString(keys.PrivateKeyB64)
	if err != nil {
		return nil, nil, "", err
	}
	return ed25519.PublicKey(pubRaw), ed25519.PrivateKey(privRaw), keys.KeyID, nil
}

func (s *Store) CreateGrant(grant policy.Grant) (policy.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePolicyState()
	now := time.Now().UTC()
	if grant.ID == "" {
		grant.ID = policy.NewID("grt")
	}
	grant.Status = policy.GrantStatusActive
	grant.CreatedAt = now
	grant.UpdatedAt = now
	s.state.Grants = append(s.state.Grants, grant)
	if err := s.saveLocked(); err != nil {
		return policy.Grant{}, err
	}
	return grant, nil
}

func (s *Store) GetGrant(id string) (policy.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePolicyState()
	for _, g := range s.state.Grants {
		if g.ID == id {
			return g, nil
		}
	}
	return policy.Grant{}, errors.New("grant not found")
}

func (s *Store) ListGrants() []policy.Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePolicyState()
	out := make([]policy.Grant, len(s.state.Grants))
	copy(out, s.state.Grants)
	slices.SortFunc(out, func(a, b policy.Grant) int {
		if a.CreatedAt.Before(b.CreatedAt) {
			return -1
		}
		if a.CreatedAt.After(b.CreatedAt) {
			return 1
		}
		return 0
	})
	return out
}

func (s *Store) RevokeGrant(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePolicyState()
	now := time.Now().UTC()
	for i := range s.state.Grants {
		if s.state.Grants[i].ID == id {
			s.state.Grants[i].Status = policy.GrantStatusRevoked
			s.state.Grants[i].UpdatedAt = now
			s.state.Grants[i].RevokedAt = &now
			return s.saveLocked()
		}
	}
	return fmt.Errorf("grant not found: %s", id)
}

func (s *Store) AddGrantSpend(id string, amount int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePolicyState()
	for i := range s.state.Grants {
		if s.state.Grants[i].ID == id {
			s.state.Grants[i].Pins.SpendPolicy.SpentCents += amount
			s.state.Grants[i].UpdatedAt = time.Now().UTC()
			return s.saveLocked()
		}
	}
	return fmt.Errorf("grant not found: %s", id)
}

func (s *Store) AddReceipt(r policy.Receipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePolicyState()
	s.state.Receipts = append(s.state.Receipts, r)
	return s.saveLocked()
}

func (s *Store) GetReceipt(id string) (policy.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePolicyState()
	for _, r := range s.state.Receipts {
		if r.ID == id {
			return r, nil
		}
	}
	return policy.Receipt{}, errors.New("receipt not found")
}

func (s *Store) ListReceipts(grantID string) []policy.Receipt {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePolicyState()
	out := make([]policy.Receipt, 0, len(s.state.Receipts))
	for _, r := range s.state.Receipts {
		if grantID == "" || r.GrantID == grantID {
			out = append(out, r)
		}
	}
	return out
}

func (s *Store) CreateApproval(a policy.ApprovalRequest) (policy.ApprovalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePolicyState()
	if a.ID == "" {
		a.ID = policy.NewID("apr")
	}
	a.Status = policy.ApprovalPending
	a.RequestedAt = time.Now().UTC()
	s.state.Approvals = append(s.state.Approvals, a)
	if err := s.saveLocked(); err != nil {
		return policy.ApprovalRequest{}, err
	}
	return a, nil
}

func (s *Store) GetApproval(id string) (policy.ApprovalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePolicyState()
	for _, a := range s.state.Approvals {
		if a.ID == id {
			return a, nil
		}
	}
	return policy.ApprovalRequest{}, errors.New("approval not found")
}

func (s *Store) ListApprovals(grantID string) []policy.ApprovalRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePolicyState()
	out := make([]policy.ApprovalRequest, 0, len(s.state.Approvals))
	for _, a := range s.state.Approvals {
		if grantID == "" || a.GrantID == grantID {
			out = append(out, a)
		}
	}
	return out
}

func (s *Store) ResolveApproval(id string, status policy.ApprovalStatus, approverSub, reason string) (policy.ApprovalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePolicyState()
	if status != policy.ApprovalApproved && status != policy.ApprovalRejected {
		return policy.ApprovalRequest{}, errors.New("invalid approval status")
	}
	now := time.Now().UTC()
	for i := range s.state.Approvals {
		if s.state.Approvals[i].ID == id {
			if s.state.Approvals[i].Status != policy.ApprovalPending {
				return policy.ApprovalRequest{}, errors.New("approval already resolved")
			}
			s.state.Approvals[i].Status = status
			s.state.Approvals[i].ApproverSub = approverSub
			s.state.Approvals[i].Reason = reason
			s.state.Approvals[i].ResolvedAt = &now
			if err := s.saveLocked(); err != nil {
				return policy.ApprovalRequest{}, err
			}
			return s.state.Approvals[i], nil
		}
	}
	return policy.ApprovalRequest{}, errors.New("approval not found")
}
