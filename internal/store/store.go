package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/petrichor/21pins-cli/internal/policy"
)

type State struct {
	ProviderKeys    map[string]string         `json:"provider_keys"`
	ProviderKeySets map[string]ProviderKeySet `json:"provider_keysets,omitempty"`
	ModelCatalogs   map[string]ModelCatalog   `json:"model_catalogs,omitempty"`
	Tokens          []TokenRecord             `json:"tokens"`
	Grants          []policy.Grant            `json:"grants,omitempty"`
	Receipts        []policy.Receipt          `json:"receipts,omitempty"`
	Approvals       []policy.ApprovalRequest  `json:"approvals,omitempty"`
	SigningKeys     SigningKeys               `json:"signing_keys,omitempty"`
}

type ProviderModel struct {
	ID            string `json:"id"`
	Name          string `json:"name,omitempty"`
	ContextWindow int    `json:"context_window,omitempty"`
}

type ModelCatalog struct {
	Provider string          `json:"provider"`
	SyncedAt string          `json:"synced_at"`
	Models   []ProviderModel `json:"models"`
}

type ProviderKeySet struct {
	ActiveKeyID   string              `json:"active_key_id,omitempty"`
	PendingKeyID  string              `json:"pending_key_id,omitempty"`
	PreviousKeyID string              `json:"previous_key_id,omitempty"`
	Keys          []ProviderKeyRecord `json:"keys,omitempty"`
}

type ProviderKeyRecord struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Secret    string `json:"secret"`
	CreatedAt string `json:"created_at"`
	VerifiedAt string `json:"verified_at,omitempty"`
	RevokedAt string `json:"revoked_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

const (
	KeyStatusActive   = "active"
	KeyStatusPending  = "pending"
	KeyStatusPrevious = "previous"
	KeyStatusRevoked  = "revoked"
)

type TokenRecord struct {
	Name       string   `json:"name"`
	TokenHash  string   `json:"token_hash"`
	Scopes     []string `json:"scopes"`
	CreatedAt  string   `json:"created_at"`
	RevokedAt  string   `json:"revoked_at,omitempty"`
	LastUsedAt string   `json:"last_used_at,omitempty"`
}

type Store struct {
	path  string
	mu    sync.Mutex
	state State
}

func New(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.loadOrInit(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) loadOrInit() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	_, err := os.Stat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.state = State{ProviderKeys: map[string]string{}, ProviderKeySets: map[string]ProviderKeySet{}, ModelCatalogs: map[string]ModelCatalog{}, Tokens: []TokenRecord{}}
		return s.saveLocked()
	}
	if err != nil {
		return err
	}

	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}

	if len(b) == 0 {
		s.state = State{ProviderKeys: map[string]string{}, ProviderKeySets: map[string]ProviderKeySet{}, ModelCatalogs: map[string]ModelCatalog{}, Tokens: []TokenRecord{}}
		return s.saveLocked()
	}

	if err := json.Unmarshal(b, &s.state); err != nil {
		return fmt.Errorf("parse state file: %w", err)
	}
	if s.state.ProviderKeys == nil {
		s.state.ProviderKeys = map[string]string{}
	}
	if s.state.ProviderKeySets == nil {
		s.state.ProviderKeySets = map[string]ProviderKeySet{}
	}
	if s.state.ModelCatalogs == nil {
		s.state.ModelCatalogs = map[string]ModelCatalog{}
	}
	if s.state.Tokens == nil {
		s.state.Tokens = []TokenRecord{}
	}
	if s.state.Grants == nil {
		s.state.Grants = []policy.Grant{}
	}
	if s.state.Receipts == nil {
		s.state.Receipts = []policy.Receipt{}
	}
	if s.state.Approvals == nil {
		s.state.Approvals = []policy.ApprovalRequest{}
	}

	changed := s.migrateProviderKeysLocked()
	if changed {
		return s.saveLocked()
	}
	return nil
}

func (s *Store) migrateProviderKeysLocked() bool {
	changed := false
	for provider, key := range s.state.ProviderKeys {
		if strings.TrimSpace(key) == "" {
			delete(s.state.ProviderKeys, provider)
			changed = true
			continue
		}
		if _, ok := s.state.ProviderKeySets[provider]; ok {
			continue
		}
		now := time.Now().UTC().Format(time.RFC3339)
		rec := ProviderKeyRecord{
			ID:         generateKeyID(),
			Status:     KeyStatusActive,
			Secret:     key,
			CreatedAt:  now,
			VerifiedAt: now,
		}
		s.state.ProviderKeySets[provider] = ProviderKeySet{
			ActiveKeyID: rec.ID,
			Keys:        []ProviderKeyRecord{rec},
		}
		changed = true
	}
	for provider := range s.state.ProviderKeySets {
		s.syncActiveProviderKeyLocked(provider)
	}
	return changed
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.path, b, 0o600); err != nil {
		return err
	}
	return nil
}

func (s *Store) SetProviderKey(provider, key string) error {
	provider = normalizeProvider(provider)
	key = strings.TrimSpace(key)
	if provider == "" || key == "" {
		return errors.New("provider and key are required")
	}
	now := time.Now().UTC().Format(time.RFC3339)

	s.mu.Lock()
	defer s.mu.Unlock()

	ks := s.ensureProviderKeySetLocked(provider)
	for i := range ks.Keys {
		if ks.Keys[i].Status == KeyStatusActive || ks.Keys[i].Status == KeyStatusPending || ks.Keys[i].Status == KeyStatusPrevious {
			ks.Keys[i].Status = KeyStatusRevoked
			if ks.Keys[i].RevokedAt == "" {
				ks.Keys[i].RevokedAt = now
			}
		}
	}
	rec := ProviderKeyRecord{ID: generateKeyID(), Status: KeyStatusActive, Secret: key, CreatedAt: now, VerifiedAt: now}
	ks.Keys = append(ks.Keys, rec)
	ks.ActiveKeyID = rec.ID
	ks.PendingKeyID = ""
	ks.PreviousKeyID = ""
	s.state.ProviderKeySets[provider] = ks
	s.syncActiveProviderKeyLocked(provider)
	return s.saveLocked()
}

func (s *Store) RotateProviderKeyStart(provider, newKey string) (string, error) {
	provider = normalizeProvider(provider)
	newKey = strings.TrimSpace(newKey)
	if provider == "" || newKey == "" {
		return "", errors.New("provider and key are required")
	}
	now := time.Now().UTC().Format(time.RFC3339)

	s.mu.Lock()
	defer s.mu.Unlock()
	ks := s.ensureProviderKeySetLocked(provider)
	if ks.PendingKeyID != "" {
		return "", errors.New("rotation already in progress; commit or rollback first")
	}
	rec := ProviderKeyRecord{ID: generateKeyID(), Status: KeyStatusPending, Secret: newKey, CreatedAt: now}
	ks.Keys = append(ks.Keys, rec)
	ks.PendingKeyID = rec.ID
	s.state.ProviderKeySets[provider] = ks
	return rec.ID, s.saveLocked()
}

func (s *Store) RotateProviderKeyVerify(provider string) (string, error) {
	provider = normalizeProvider(provider)
	if provider == "" {
		return "", errors.New("provider is required")
	}
	now := time.Now().UTC().Format(time.RFC3339)

	s.mu.Lock()
	defer s.mu.Unlock()
	ks, ok := s.state.ProviderKeySets[provider]
	if !ok || ks.PendingKeyID == "" {
		return "", errors.New("no pending key rotation for provider")
	}
	idx := findProviderKeyIndex(ks.Keys, ks.PendingKeyID)
	if idx < 0 {
		return "", errors.New("pending key not found")
	}
	ks.Keys[idx].VerifiedAt = now
	s.state.ProviderKeySets[provider] = ks
	return ks.PendingKeyID, s.saveLocked()
}

func (s *Store) RotateProviderKeyCommit(provider string, keepPreviousHours int) error {
	provider = normalizeProvider(provider)
	if provider == "" {
		return errors.New("provider is required")
	}
	if keepPreviousHours < 0 {
		return errors.New("keep-previous-hours must be >= 0")
	}
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()
	ks, ok := s.state.ProviderKeySets[provider]
	if !ok || ks.PendingKeyID == "" {
		return errors.New("no pending key rotation for provider")
	}
	pendingIdx := findProviderKeyIndex(ks.Keys, ks.PendingKeyID)
	if pendingIdx < 0 {
		return errors.New("pending key not found")
	}
	if strings.TrimSpace(ks.Keys[pendingIdx].VerifiedAt) == "" {
		return errors.New("pending key must be verified before commit")
	}

	if ks.ActiveKeyID != "" {
		activeIdx := findProviderKeyIndex(ks.Keys, ks.ActiveKeyID)
		if activeIdx >= 0 {
			if keepPreviousHours == 0 {
				ks.Keys[activeIdx].Status = KeyStatusRevoked
				ks.Keys[activeIdx].RevokedAt = now.Format(time.RFC3339)
				ks.Keys[activeIdx].ExpiresAt = ""
				ks.PreviousKeyID = ""
			} else {
				ks.Keys[activeIdx].Status = KeyStatusPrevious
				ks.Keys[activeIdx].ExpiresAt = now.Add(time.Duration(keepPreviousHours) * time.Hour).Format(time.RFC3339)
				ks.PreviousKeyID = ks.Keys[activeIdx].ID
			}
		}
	}

	ks.Keys[pendingIdx].Status = KeyStatusActive
	ks.Keys[pendingIdx].ExpiresAt = ""
	ks.Keys[pendingIdx].RevokedAt = ""
	ks.ActiveKeyID = ks.Keys[pendingIdx].ID
	ks.PendingKeyID = ""

	s.state.ProviderKeySets[provider] = ks
	s.syncActiveProviderKeyLocked(provider)
	return s.saveLocked()
}

func (s *Store) RotateProviderKeyRollback(provider string) error {
	provider = normalizeProvider(provider)
	if provider == "" {
		return errors.New("provider is required")
	}
	now := time.Now().UTC().Format(time.RFC3339)

	s.mu.Lock()
	defer s.mu.Unlock()
	ks, ok := s.state.ProviderKeySets[provider]
	if !ok || ks.PreviousKeyID == "" {
		return errors.New("no previous key available for rollback")
	}
	prevIdx := findProviderKeyIndex(ks.Keys, ks.PreviousKeyID)
	activeIdx := findProviderKeyIndex(ks.Keys, ks.ActiveKeyID)
	if prevIdx < 0 || activeIdx < 0 {
		return errors.New("rollback keys not found")
	}
	ks.Keys[activeIdx].Status = KeyStatusPrevious
	ks.Keys[activeIdx].ExpiresAt = now
	ks.Keys[prevIdx].Status = KeyStatusActive
	ks.Keys[prevIdx].ExpiresAt = ""

	ks.ActiveKeyID, ks.PreviousKeyID = ks.PreviousKeyID, ks.ActiveKeyID
	s.state.ProviderKeySets[provider] = ks
	s.syncActiveProviderKeyLocked(provider)
	return s.saveLocked()
}

func (s *Store) RevokePreviousProviderKey(provider string) error {
	provider = normalizeProvider(provider)
	if provider == "" {
		return errors.New("provider is required")
	}
	now := time.Now().UTC().Format(time.RFC3339)

	s.mu.Lock()
	defer s.mu.Unlock()
	ks, ok := s.state.ProviderKeySets[provider]
	if !ok || ks.PreviousKeyID == "" {
		return errors.New("no previous key to revoke")
	}
	idx := findProviderKeyIndex(ks.Keys, ks.PreviousKeyID)
	if idx < 0 {
		return errors.New("previous key not found")
	}
	ks.Keys[idx].Status = KeyStatusRevoked
	ks.Keys[idx].RevokedAt = now
	ks.Keys[idx].ExpiresAt = ""
	ks.PreviousKeyID = ""
	s.state.ProviderKeySets[provider] = ks
	return s.saveLocked()
}

func (s *Store) RevokeProviderKey(provider, keyID string) error {
	provider = normalizeProvider(provider)
	keyID = strings.TrimSpace(keyID)
	if provider == "" || keyID == "" {
		return errors.New("provider and key-id are required")
	}
	now := time.Now().UTC().Format(time.RFC3339)

	s.mu.Lock()
	defer s.mu.Unlock()
	ks, ok := s.state.ProviderKeySets[provider]
	if !ok {
		return errors.New("provider not found")
	}
	if ks.ActiveKeyID == keyID {
		return errors.New("cannot revoke active key")
	}
	idx := findProviderKeyIndex(ks.Keys, keyID)
	if idx < 0 {
		return errors.New("key-id not found")
	}
	ks.Keys[idx].Status = KeyStatusRevoked
	ks.Keys[idx].RevokedAt = now
	ks.Keys[idx].ExpiresAt = ""
	if ks.PendingKeyID == keyID {
		ks.PendingKeyID = ""
	}
	if ks.PreviousKeyID == keyID {
		ks.PreviousKeyID = ""
	}
	s.state.ProviderKeySets[provider] = ks
	return s.saveLocked()
}

func (s *Store) ProviderKeyHistory(provider string) []ProviderKeyRecord {
	provider = normalizeProvider(provider)
	s.mu.Lock()
	defer s.mu.Unlock()
	ks, ok := s.state.ProviderKeySets[provider]
	if !ok {
		return []ProviderKeyRecord{}
	}
	out := make([]ProviderKeyRecord, len(ks.Keys))
	copy(out, ks.Keys)
	slices.SortFunc(out, func(a, b ProviderKeyRecord) int {
		return strings.Compare(b.CreatedAt, a.CreatedAt)
	})
	return out
}

func (s *Store) GetProviderKey(provider string) string {
	provider = normalizeProvider(provider)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ks, ok := s.state.ProviderKeySets[provider]; ok && ks.ActiveKeyID != "" {
		if idx := findProviderKeyIndex(ks.Keys, ks.ActiveKeyID); idx >= 0 {
			return ks.Keys[idx].Secret
		}
	}
	return s.state.ProviderKeys[provider]
}

func (s *Store) ListProviders() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := map[string]struct{}{}
	for p := range s.state.ProviderKeys {
		set[p] = struct{}{}
	}
	for p, ks := range s.state.ProviderKeySets {
		if ks.ActiveKeyID != "" {
			set[p] = struct{}{}
		}
	}
	providers := make([]string, 0, len(set))
	for p := range set {
		providers = append(providers, p)
	}
	slices.Sort(providers)
	return providers
}

func (s *Store) SaveModelCatalog(provider string, models []ProviderModel) error {
	provider = normalizeProvider(provider)
	if provider == "" {
		return errors.New("provider is required")
	}
	out := make([]ProviderModel, len(models))
	copy(out, models)
	slices.SortFunc(out, func(a, b ProviderModel) int {
		return strings.Compare(a.ID, b.ID)
	})

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.ModelCatalogs == nil {
		s.state.ModelCatalogs = map[string]ModelCatalog{}
	}
	s.state.ModelCatalogs[provider] = ModelCatalog{
		Provider: provider,
		SyncedAt: time.Now().UTC().Format(time.RFC3339),
		Models:   out,
	}
	return s.saveLocked()
}

func (s *Store) GetModelCatalog(provider string) (ModelCatalog, bool) {
	provider = normalizeProvider(provider)
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.state.ModelCatalogs[provider]
	if !ok {
		return ModelCatalog{}, false
	}
	models := make([]ProviderModel, len(c.Models))
	copy(models, c.Models)
	c.Models = models
	return c, true
}

func (s *Store) ListModelCatalogs() map[string]ModelCatalog {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]ModelCatalog, len(s.state.ModelCatalogs))
	for k, c := range s.state.ModelCatalogs {
		models := make([]ProviderModel, len(c.Models))
		copy(models, c.Models)
		c.Models = models
		out[k] = c
	}
	return out
}

func (s *Store) ensureProviderKeySetLocked(provider string) ProviderKeySet {
	if ks, ok := s.state.ProviderKeySets[provider]; ok {
		if ks.Keys == nil {
			ks.Keys = []ProviderKeyRecord{}
		}
		return ks
	}
	return ProviderKeySet{Keys: []ProviderKeyRecord{}}
}

func (s *Store) syncActiveProviderKeyLocked(provider string) {
	ks, ok := s.state.ProviderKeySets[provider]
	if !ok {
		delete(s.state.ProviderKeys, provider)
		return
	}
	if ks.ActiveKeyID == "" {
		delete(s.state.ProviderKeys, provider)
		return
	}
	idx := findProviderKeyIndex(ks.Keys, ks.ActiveKeyID)
	if idx < 0 {
		delete(s.state.ProviderKeys, provider)
		return
	}
	s.state.ProviderKeys[provider] = ks.Keys[idx].Secret
}

func findProviderKeyIndex(keys []ProviderKeyRecord, id string) int {
	for i := range keys {
		if keys[i].ID == id {
			return i
		}
	}
	return -1
}

func generateKeyID() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return "key_" + hex.EncodeToString(buf)
}

func (s *Store) CreateToken(name string, scopes []string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("name is required")
	}
	if len(scopes) == 0 {
		scopes = []string{"proxy:*"}
	}
	raw, hash, err := generateTokenAndHash()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Tokens = append(s.state.Tokens, TokenRecord{
		Name:      name,
		TokenHash: hash,
		Scopes:    scopes,
		CreatedAt: now,
	})
	if err := s.saveLocked(); err != nil {
		return "", err
	}
	return raw, nil
}

func (s *Store) ListTokens() []TokenRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TokenRecord, len(s.state.Tokens))
	copy(out, s.state.Tokens)
	return out
}

func (s *Store) RevokeToken(raw string) error {
	h := tokenHash(raw)
	if h == "" {
		return errors.New("token required")
	}
	now := time.Now().UTC().Format(time.RFC3339)

	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Tokens {
		if s.state.Tokens[i].TokenHash == h {
			s.state.Tokens[i].RevokedAt = now
			return s.saveLocked()
		}
	}
	return errors.New("token not found")
}

func (s *Store) ValidateToken(raw, requiredScope string) bool {
	h := tokenHash(raw)
	if h == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Tokens {
		t := &s.state.Tokens[i]
		if t.TokenHash != h || t.RevokedAt != "" {
			continue
		}
		if !tokenAllowsScope(t.Scopes, requiredScope) {
			return false
		}
		t.LastUsedAt = time.Now().UTC().Format(time.RFC3339)
		_ = s.saveLocked()
		return true
	}
	return false
}

func tokenAllowsScope(scopes []string, required string) bool {
	if required == "" {
		return true
	}
	for _, s := range scopes {
		if s == "proxy:*" || s == required {
			return true
		}
		if strings.HasSuffix(s, "*") {
			prefix := strings.TrimSuffix(s, "*")
			if strings.HasPrefix(required, prefix) {
				return true
			}
		}
	}
	return false
}

func generateTokenAndHash() (raw, hash string, err error) {
	buf := make([]byte, 24)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	raw = "p21_" + hex.EncodeToString(buf)
	hash = tokenHash(raw)
	return raw, hash, nil
}

func tokenHash(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

var supportedProviders = []string{"anthropic", "gemini", "ollama", "openai", "openrouter"}

var providerAliases = map[string]string{
	"openrouter.ai":      "openrouter",
	"google":             "gemini",
	"google-ai-studio":   "gemini",
	"googleaistudio":     "gemini",
	"generativelanguage": "gemini",
}

func SupportedProviders() []string {
	out := make([]string, len(supportedProviders))
	copy(out, supportedProviders)
	slices.Sort(out)
	return out
}

func ProviderAliases() map[string]string {
	out := make(map[string]string, len(providerAliases))
	for k, v := range providerAliases {
		out[k] = v
	}
	return out
}

func CanonicalProvider(provider string) (canonical string, aliasUsed bool) {
	normalized := strings.ToLower(strings.TrimSpace(provider))
	if normalized == "" {
		return "", false
	}
	if c, ok := providerAliases[normalized]; ok {
		return c, true
	}
	return normalized, false
}

func normalizeProvider(provider string) string {
	canonical, _ := CanonicalProvider(provider)
	return canonical
}
