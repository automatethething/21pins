package dnsadmin

import (
	"github.com/petrichor/21pins-cli/internal/sshcommand"
	"strings"
	"testing"
)

func TestExactManifestBoundRulesAndSudoers(t *testing.T) {
	h := strings.Repeat("a", 64)
	rules, e := Rules(h)
	if e != nil || len(rules) != 5 {
		t.Fatal("rules")
	}
	a := sshcommand.Authority{Binary: "/usr/local/bin/21pins", PolicyFile: "/etc/ssh/21pins/commands.json", Rules: rules}
	if a.Validate() != nil {
		t.Fatal("native gate authority")
	}
	p := sshcommand.Policy{Workspace: "local", Host: "dns-primary", Roles: map[string]sshcommand.RolePolicy{"dns-admin": {User: "pins-dns-agent", Rules: rules}}}
	if p.Validate() != nil {
		t.Fatal("role policy")
	}
	sudo, e := Sudoers(h)
	if e != nil || strings.Contains(sudo, "*") || !strings.Contains(sudo, "NOSETENV:") {
		t.Fatal("sudo expansion")
	}
	for i, r := range rules {
		v, e := sshcommand.Authorize(p.Roles["dns-admin"], r.Command)
		if e != nil || strings.Join(v, " ") != "/usr/bin/sudo -n /usr/local/bin/21pins dns-admin "+Operations[i]+" "+h {
			t.Fatal("exact fixed dispatch")
		}
		if !strings.Contains(sudo, strings.Join(r.Exec[2:], " ")) {
			t.Fatal("sudo exact args")
		}
		if _, e = sshcommand.Authorize(p.Roles["dns-admin"], append(append([]string{}, r.Command...), "altered")); e == nil {
			t.Fatal("altered arguments")
		}
	}
	for _, s := range []string{"beryl enroll", "beryl verify", "wireguard state", "wireguard handshake", "adguard status", "adguard filtering", "beryl enroll; id", "beryl enroll $(id)", "sudo /bin/sh", "wg set wg0", "dns query changed", "beryl enroll\nsh"} {
		v, e := sshcommand.Parse(s)
		if e == nil {
			_, e = sshcommand.Authorize(p.Roles["dns-admin"], v)
		}
		if e == nil {
			t.Fatal("shell or generic command")
		}
	}
	if _, e = p.Role("local", "wrong-host", "dns-admin", "pins-dns-agent"); e == nil {
		t.Fatal("wrong host")
	}
	if _, e = p.Role("local", "dns-primary", "observe", "pins-dns-agent"); e == nil {
		t.Fatal("wrong role")
	}
	if _, e = p.Role("local", "dns-primary", "dns-admin", "root"); e == nil {
		t.Fatal("wrong user")
	}
	b, _ := Rules(strings.Repeat("b", 64))
	if sshcommand.RulesDigest(b) == sshcommand.RulesDigest(rules) {
		t.Fatal("manifest not signed-bound")
	}
}
