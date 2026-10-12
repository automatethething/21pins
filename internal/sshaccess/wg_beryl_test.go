package sshaccess

import (
	"strings"
	"testing"
)

func TestWGBerylPolicyIsSeparateApprovedScope(t *testing.T) {
	h, e := WGBerylHost(strings.Repeat("a", 64), "pins-vm205", "fipi")
	if e != nil {
		t.Fatal(e)
	}
	r := h.Roles["wg-beryl"]
	if r.SSHUser != "pins-wg-agent" || !r.ExplicitApproval || r.PermitPTY || r.PermitPortForwarding || r.PermitAgentForwarding || r.PermitX11 || len(r.CommandAuthority.Rules) != 2 || r.MaxCertTTL != "5m" {
		t.Fatal("scope")
	}
	s, _, a, q, _ := fixture(t, false)
	s.Config.Hosts = map[string]Host{"wg-gateway": h}
	q.HostID = "wg-gateway"
	q.RoleID = "wg-beryl"
	q.MaxDuration = "31m"
	if _, e = s.Open(a, q); e == nil {
		t.Fatal("deadline")
	}
	q.MaxDuration = "15m"
	l, e := s.Open(a, q)
	if e != nil || l.Status != PendingApproval {
		t.Fatal("approval")
	}
	if _, e = s.Issue(a, l.ID, q.PublicKey); e == nil {
		t.Fatal("unapproved gateway issuance")
	}
	if _, e = s.Approve(Actor{ID: a.ID, Name: a.Name, CanApprove: true}, l.ID); e == nil {
		t.Fatal("self approval")
	}
	q.RoleID = "dns-admin"
	if _, e = s.Open(a, q); e == nil {
		t.Fatal("wrong role")
	}
}
