package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStorePersistsUsageEvents(t *testing.T) {
	tempDir := t.TempDir()
	s, err := New(filepath.Join(tempDir, "state.json"))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	event := UsageEvent{
		ID:                  "use_123",
		CreatedAt:           time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC),
		Source:              "pi",
		Provider:            "openrouter",
		Model:               "openai/gpt-4o-mini",
		RequestedModel:      "openrouter/openai/gpt-4o-mini",
		AppTokenName:        "pi",
		BillingMode:         "api",
		PromptTokens:        10,
		CompletionTokens:    5,
		TotalTokens:         15,
		EstimatedCostMicros: 6,
		Currency:            "USD",
		PricingSource:       "static",
	}
	if err := s.AddUsageEvent(event); err != nil {
		t.Fatalf("AddUsageEvent failed: %v", err)
	}
	reopened, err := New(filepath.Join(tempDir, "state.json"))
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	events := reopened.ListUsageEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Model != "openai/gpt-4o-mini" {
		t.Fatalf("unexpected event: %+v", events[0])
	}
}

func TestStoreAtomicallyReplacesStateFile(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	s, err := New(statePath)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetProviderKey("openai", "test-key"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("state save replaced file contents in place instead of atomically replacing it")
	}
}

func TestStoreTightensExistingStateFilePermissions(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(statePath, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(statePath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected existing state file to be tightened to 0600, got %o", info.Mode().Perm())
	}
}

func TestStoreRollsBackMemoryAfterFailedSave(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "state.json")
	s, err := New(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tempDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(tempDir, 0o700) })
	if err := s.SetProviderKey("openai", "must-not-stick"); err == nil {
		t.Fatal("expected save to fail in read-only directory")
	}
	if got := s.GetProviderKey("openai"); got != "" {
		t.Fatalf("failed save remained in memory: %q", got)
	}
}

func TestStoreRollsBackMemoryAfterMarshalFailure(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	event := UsageEvent{ID: "invalid-time", CreatedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}
	if err := s.AddUsageEvent(event); err == nil {
		t.Fatal("expected JSON marshal failure")
	}
	if events := s.ListUsageEvents(); len(events) != 0 {
		t.Fatalf("failed save left %d usage events in memory", len(events))
	}
}

func TestStoreRejectsSymlinkStatePath(t *testing.T) {
	tempDir := t.TempDir()
	target := filepath.Join(tempDir, "target.json")
	statePath := filepath.Join(tempDir, "state.json")
	const original = `{"provider_keys":{"openai":"do-not-overwrite"}}`
	if err := os.WriteFile(target, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, statePath); err != nil {
		t.Fatal(err)
	}
	if _, err := New(statePath); err == nil {
		t.Fatal("expected symlink state path to be rejected")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatal("symlink target was modified")
	}
}

func TestValidateTokenRecordReturnsTokenName(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	raw, err := s.CreateToken("pi", []string{"proxy:chat", "usage:read"})
	if err != nil {
		t.Fatal(err)
	}
	record, ok := s.ValidateTokenRecord(raw, "proxy:chat")
	if !ok {
		t.Fatal("expected token to validate")
	}
	if record.Name != "pi" {
		t.Fatalf("expected pi token, got %q", record.Name)
	}
}

func TestTokenLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "state.json")

	s, err := New(statePath)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	rawToken, err := s.CreateToken("test-app", []string{"proxy:chat"})
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}

	if rawToken == "" {
		t.Fatal("expected non-empty raw token")
	}

	if ok := s.ValidateToken(rawToken, "proxy:chat"); !ok {
		t.Fatal("expected token to validate for granted scope")
	}

	if ok := s.ValidateToken(rawToken, "proxy:admin"); ok {
		t.Fatal("expected token to fail for non-granted scope")
	}

	if err := s.RevokeToken(rawToken); err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	if ok := s.ValidateToken(rawToken, "proxy:chat"); ok {
		t.Fatal("expected revoked token to fail validation")
	}

	st, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("expected state file: %v", err)
	}

	if st.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", st.Mode().Perm())
	}
}
