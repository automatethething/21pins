package sshaccess

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestEveryTerminalStateAndPolicyCeiling(t *testing.T) {
	for _, state := range []Status{Completed, Cancelled, Revoked} {
		s, _, a, q, _ := fixture(t, false)
		l, e := s.Open(a, q)
		if e != nil {
			t.Fatal(e)
		}
		closer := a
		reason := "complete"
		if state == Cancelled {
			reason = "cancelled"
		}
		if state == Revoked {
			closer = Actor{ID: "owner", Name: "owner", CanApprove: true}
			reason = "revoked"
		}
		if _, e = s.Close(closer, l.ID, state, reason); e != nil {
			t.Fatal(e)
		}
		if _, e = s.Issue(a, l.ID, q.PublicKey); e == nil {
			t.Fatal("terminal renewed", state)
		}
	}
}
func TestUniqueSerialsAcrossServiceInstances(t *testing.T) {
	s, _, a, q, _ := fixture(t, false)
	l, e := s.Open(a, q)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	serials := make(chan uint64, 12)
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			other, e := New(s.Dir, s.Config, &fakeSigner{})
			if e != nil {
				errs <- e
				return
			}
			r, e := other.Issue(a, l.ID, q.PublicKey)
			if e != nil {
				errs <- e
				return
			}
			serials <- r.Issuance.Serial
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	close(serials)
	seen := map[uint64]bool{}
	for id := range serials {
		if seen[id] {
			t.Fatal("serial reused")
		}
		seen[id] = true
	}
	if len(seen) != 12 {
		t.Fatal("missing serials")
	}
}
func TestSymlinksAndPersistenceFailureFailClosed(t *testing.T) {
	s, f, a, q, _ := fixture(t, false)
	l, e := s.Open(a, q)
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(s.Dir, "leases.json")
	if e = os.Remove(p); e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(target, []byte("synthetic"), 0600)
	if e = os.Symlink(target, p); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Issue(a, l.ID, q.PublicKey); e == nil {
		t.Fatal("symlink issued")
	}
	if len(f.calls) != 0 {
		t.Fatal("signer called before safe state")
	}
}
func TestSignerFailureNeverReusesSerial(t *testing.T) {
	s, f, a, q, _ := fixture(t, false)
	l, e := s.Open(a, q)
	if e != nil {
		t.Fatal(e)
	}
	f.fail = true
	if _, e = s.Issue(a, l.ID, q.PublicKey); e == nil {
		t.Fatal("failed signer accepted")
	}
	f.fail = false
	r, e := s.Issue(a, l.ID, q.PublicKey)
	if e != nil || r.Issuance.Serial != 2 {
		t.Fatal("serial not reserved", e)
	}
}
func TestRenewalCannotChangeAnyAuthorizationDimension(t *testing.T) {
	changes := []func(*Config){func(c *Config) { c.Workspace = "other" }, func(c *Config) { h := c.Hosts["alpha"]; h.Alias = "other"; c.Hosts["alpha"] = h }, func(c *Config) {
		h := c.Hosts["alpha"]
		r := h.Roles["observe"]
		r.PermitAgentForwarding = true
		h.Roles["observe"] = r
		c.Hosts["alpha"] = h
	}, func(c *Config) {
		h := c.Hosts["alpha"]
		r := h.Roles["observe"]
		r.MaxLease = "24h"
		h.Roles["observe"] = r
		c.Hosts["alpha"] = h
	}}
	for _, change := range changes {
		s, _, a, q, _ := fixture(t, false)
		l, e := s.Open(a, q)
		if e != nil {
			t.Fatal(e)
		}
		change(&s.Config)
		if _, e = s.Issue(a, l.ID, q.PublicKey); e == nil {
			t.Fatal("scope change renewed")
		}
	}
}
func TestMalformedCertificateCannotPassVerifier(t *testing.T) {
	r := SignRequest{PublicKey: testPublic(t), Principal: "21pins:test:alpha:observe", ValidAfter: time.Now(), ValidBefore: time.Now().Add(time.Minute)}
	for _, v := range []string{"", "ssh-ed25519-cert-v01@openssh.com AAAA", "-----BEGIN OPENSSH PRIVATE KEY-----"} {
		if verifyCertificate(v, testPublic(t), r) == nil {
			t.Fatal("malformed cert accepted")
		}
	}
}
func TestAuditIsMetadataOnly(t *testing.T) {
	s, _, a, q, _ := fixture(t, false)
	l, e := s.Open(a, q)
	if e != nil {
		t.Fatal(e)
	}
	s.Issue(a, l.ID, q.PublicKey)
	b, e := os.ReadFile(filepath.Join(s.Dir, "leases.json"))
	if e != nil {
		t.Fatal(e)
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(b, &obj) != nil {
		t.Fatal("audit JSON")
	}
	if len(obj) != 3 {
		t.Fatal("unexpected state field")
	}
	for _, field := range []string{"private_key", "certificate", "commands", "environment", "terminal"} {
		if _, ok := obj[field]; ok {
			t.Fatal("sensitive audit")
		}
	}
}
