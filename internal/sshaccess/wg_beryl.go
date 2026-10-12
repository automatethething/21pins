package sshaccess

import (
	"github.com/petrichor/21pins-cli/internal/dnsadmin"
	"github.com/petrichor/21pins-cli/internal/sshcommand"
)

// Review-only policy; this never registers or installs gateway authority.
func WGBerylHost(manifestDigest, alias, jump string) (Host, error) {
	if !identifier.MatchString(alias) || !identifier.MatchString(jump) {
		return Host{}, ErrDenied
	}
	r, e := dnsadmin.WireGuardRules(manifestDigest)
	if e != nil {
		return Host{}, ErrDenied
	}
	return Host{Alias: alias, JumpAlias: jump, Roles: map[string]Role{"wg-beryl": {SSHUser: "pins-wg-agent", DefaultLease: "15m", MaxLease: "30m", MaxCertTTL: "5m", ExplicitApproval: true, Requesters: map[string]string{"pi": "approval"}, CommandAuthority: &sshcommand.Authority{Binary: "/usr/local/bin/21pins", PolicyFile: "/etc/ssh/21pins/commands.json", Rules: r}}}}, nil
}
