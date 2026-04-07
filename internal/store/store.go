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
	ProviderKeys map[string]string        `json:"provider_keys"`
	Tokens       []TokenRecord            `json:"tokens"`
	Grants       []policy.Grant           `json:"grants,omitempty"`
	Receipts     []policy.Receipt         `json:"receipts,omitempty"`
	Approvals    []policy.ApprovalRequest `json:"approvals,omitempty"`
	SigningKeys  SigningKeys              `json:"signing_keys,omitempty"`
}

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
		s.state = State{ProviderKeys: map[string]string{}, Tokens: []TokenRecord{}}
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
		s.state = State{ProviderKeys: map[string]string{}, Tokens: []TokenRecord{}}
		return s.saveLocked()
	}

	if err := json.Unmarshal(b, &s.state); err != nil {
		return fmt.Errorf("parse state file: %w", err)
	}
	if s.state.ProviderKeys == nil {
		s.state.ProviderKeys = map[string]string{}
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
	return nil
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
	if provider == "" || strings.TrimSpace(key) == "" {
		return errors.New("provider and key are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.ProviderKeys[provider] = strings.TrimSpace(key)
	return s.saveLocked()
}

func (s *Store) GetProviderKey(provider string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.ProviderKeys[normalizeProvider(provider)]
}

func (s *Store) ListProviders() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	providers := make([]string, 0, len(s.state.ProviderKeys))
	for p := range s.state.ProviderKeys {
		providers = append(providers, p)
	}
	slices.Sort(providers)
	return providers
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
