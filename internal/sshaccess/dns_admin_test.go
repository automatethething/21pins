package sshaccess

import (
	"strings"
	"testing"
	"time"
)

func TestDNSAdminReviewPolicyRequiresNarrowApprovalAndCeilings(t *testing.T) {
	h, e := DNSAdminHost(strings.Repeat("a", 64), "dns-primary", "management")
	if e != nil {
		t.Fatal(e)
	}
	r := h.Roles["dns-admin"]
	if r.SSHUser != "pins-dns-agent" || !r.ExplicitApproval || r.PermitPTY || r.PermitPortForwarding || r.PermitAgentForwarding || r.PermitX11 || r.MaxLease != "30m" || r.DefaultLease != "15m" || r.MaxCertTTL != "5m" || len(r.CommandAuthority.Rules) != 5 || r.CommandAuthority.Fixture {
		t.Fatal("privileged policy expanded")
	}
	s, _, a, q, _ := fixture(t, false)
	s.Config.Hosts = map[string]Host{"dns-primary": h}
	s.Config.CertTTL, s.Config.RenewBefore = "15m", "5m"
	q.HostID = "dns-primary"
	q.RoleID = "dns-admin"
	q.MaxDuration = "31m"
	if _, e = s.Open(a, q); e == nil {
		t.Fatal("hard ceiling")
	}
	q.MaxDuration = "30m"
	l, e := s.Open(a, q)
	if e != nil || l.Status != PendingApproval || l.SSHUser != "pins-dns-agent" || l.SSHJumpAlias != "management" || l.HardExpiresAt.Sub(l.OpenedAt) > 30*time.Minute || l.RenewBefore != "1m40s" {
		t.Fatal("approval scope")
	}
	if _, e = s.Issue(a, l.ID, q.PublicKey); e == nil {
		t.Fatal("unapproved privileged signing")
	}
	if _, e = s.Approve(Actor{ID: a.ID, Name: a.Name, CanApprove: true}, l.ID); e == nil {
		t.Fatal("self approval")
	}
	if _, e = DNSAdminHost(strings.Repeat("a", 64), "dns-primary", "management,other"); e == nil {
		t.Fatal("jump scope")
	}
}
