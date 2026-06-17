package identity

import "testing"

func TestResolveSubjectUsesExplicitSubject(t *testing.T) {
	got, err := ResolveSubject("ck_sub_explicit", false, nil)
	if err != nil {
		t.Fatalf("ResolveSubject failed: %v", err)
	}
	if got != "ck_sub_explicit" {
		t.Fatalf("expected explicit subject, got %q", got)
	}
}

func TestResolveSubjectParsesConsentKeysWhoami(t *testing.T) {
	got, err := ResolveSubject("", true, func() ([]byte, error) {
		return []byte("Authenticated as founder\nsubject: ck_sub_abc123\n"), nil
	})
	if err != nil {
		t.Fatalf("ResolveSubject failed: %v", err)
	}
	if got != "ck_sub_abc123" {
		t.Fatalf("expected parsed ck subject, got %q", got)
	}
}

func TestResolveSubjectRequiresSubjectWhenCKDisabled(t *testing.T) {
	_, err := ResolveSubject("", false, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
}
