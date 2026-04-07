package store

import (
	"os"
	"path/filepath"
	"testing"
)

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
