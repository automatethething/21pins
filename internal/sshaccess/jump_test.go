package sshaccess

import "testing"

func TestBastionScopeCannotChangeDuringLease(t *testing.T) {
	s, _, a, q, _ := fixture(t, false)
	h := s.Config.Hosts[q.HostID]
	h.JumpAlias = "management"
	s.Config.Hosts[q.HostID] = h
	l, e := s.Open(a, q)
	if e != nil || l.SSHJumpAlias != "management" {
		t.Fatal("immutable jump not bound")
	}
	h.JumpAlias = "other"
	s.Config.Hosts[q.HostID] = h
	if r, e := s.Issue(a, l.ID, q.PublicKey); e == nil || r.Certificate != "" {
		t.Fatal("changed transport scope signed")
	}
	h.JumpAlias = "management,other"
	s.Config.Hosts[q.HostID] = h
	if validateConfig(s.Config) == nil {
		t.Fatal("proxy grammar accepted as alias")
	}
}
