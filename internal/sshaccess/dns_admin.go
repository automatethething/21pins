package sshaccess

import (
	"github.com/petrichor/21pins-cli/internal/dnsadmin"
	"github.com/petrichor/21pins-cli/internal/sshcommand"
)

// DNSAdminHost builds review-only immutable policy; it never registers or installs a host.
// The manifest must have real reviewed pins before an owner activates this policy.
func DNSAdminHost(manifestDigest, alias, jump string) (Host, error) {
	if !identifier.MatchString(alias) || !identifier.MatchString(jump) {
		return Host{}, ErrDenied
	}
	rules, e := dnsadmin.Rules(manifestDigest)
	if e != nil {
		return Host{}, ErrDenied
	}
	return Host{Alias: alias, JumpAlias: jump, Roles: map[string]Role{"dns-admin": {
		SSHUser: "pins-dns-agent", DefaultLease: "15m", MaxLease: "30m", MaxCertTTL: "5m", ExplicitApproval: true,
		Requesters:       map[string]string{"pi": "approval"},
		CommandAuthority: &sshcommand.Authority{Binary: "/usr/local/bin/21pins", PolicyFile: "/etc/ssh/21pins/commands.json", Rules: rules},
	}}}, nil
}
