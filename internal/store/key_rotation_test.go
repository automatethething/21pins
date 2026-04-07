package store

import (
	"path/filepath"
	"testing"
)

func TestProviderKeyRotationLifecycle(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if err := s.SetProviderKey("openai", "old-key"); err != nil {
		t.Fatalf("SetProviderKey failed: %v", err)
	}
	if got := s.GetProviderKey("openai"); got != "old-key" {
		t.Fatalf("expected old active key, got %q", got)
	}

	if _, err := s.RotateProviderKeyStart("openai", "new-key"); err != nil {
		t.Fatalf("RotateProviderKeyStart failed: %v", err)
	}
	if _, err := s.RotateProviderKeyVerify("openai"); err != nil {
		t.Fatalf("RotateProviderKeyVerify failed: %v", err)
	}
	if err := s.RotateProviderKeyCommit("openai", 24); err != nil {
		t.Fatalf("RotateProviderKeyCommit failed: %v", err)
	}

	if got := s.GetProviderKey("openai"); got != "new-key" {
		t.Fatalf("expected rotated active key, got %q", got)
	}

	history := s.ProviderKeyHistory("openai")
	if len(history) < 2 {
		t.Fatalf("expected at least 2 keys in history, got %d", len(history))
	}

	foundPrevious := false
	for _, rec := range history {
		if rec.Status == KeyStatusPrevious {
			foundPrevious = true
			break
		}
	}
	if !foundPrevious {
		t.Fatal("expected previous key after commit with grace window")
	}

	if err := s.RevokePreviousProviderKey("openai"); err != nil {
		t.Fatalf("RevokePreviousProviderKey failed: %v", err)
	}

	history = s.ProviderKeyHistory("openai")
	foundRevoked := false
	for _, rec := range history {
		if rec.Status == KeyStatusRevoked {
			foundRevoked = true
			break
		}
	}
	if !foundRevoked {
		t.Fatal("expected revoked key after revoking previous key")
	}
}

func TestRotateCommitRequiresVerify(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if err := s.SetProviderKey("anthropic", "old"); err != nil {
		t.Fatalf("SetProviderKey failed: %v", err)
	}
	if _, err := s.RotateProviderKeyStart("anthropic", "new"); err != nil {
		t.Fatalf("RotateProviderKeyStart failed: %v", err)
	}
	if err := s.RotateProviderKeyCommit("anthropic", 24); err == nil {
		t.Fatal("expected commit to fail without verify")
	}
}
