package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSSHScopesDoNotInheritProxyWildcards(t *testing.T) {
	s, e := New(filepath.Join(t.TempDir(), "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	for _, scope := range []string{"proxy:*", "*", "ssh:*", "ssh:approve"} {
		raw, e := s.CreateToken("app-"+scope, []string{scope})
		if e != nil {
			t.Fatal(e)
		}
		if _, ok := s.ValidateSSHToken(raw, "ssh:use"); ok {
			t.Fatal("implicit SSH use scope")
		}
	}
	raw, e := s.CreateToken("pi", []string{"ssh:use"})
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := s.ValidateSSHToken(raw, "ssh:use"); !ok {
		t.Fatal("explicit scope rejected")
	}
	if _, e = s.CreateToken("pi", []string{"ssh:use"}); e != nil {
		t.Fatal(e)
	}
	if _, ok := s.ValidateSSHToken(raw, "ssh:use"); ok {
		t.Fatal("ambiguous app accepted")
	}
}
func TestSSHAuthFailsClosedOnCorruptState(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	s, e := New(p)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := s.CreateToken("pi", []string{"ssh:use"})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(p, []byte("bad-json"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, ok := s.ValidateSSHToken(raw, "ssh:use"); ok {
		t.Fatal("cached token after reload failure")
	}
}
