package sshaccess

import (
	"encoding/json"
	"github.com/petrichor/21pins-cli/internal/sshcommand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReviewedDogfoodTemplatesMatchGeneratedAuthority(t *testing.T) {
	b, e := os.ReadFile("../../docs/ssh-pins-agent-commands.json")
	if e != nil {
		t.Fatal(e)
	}
	var p sshcommand.Policy
	if json.Unmarshal(b, &p) != nil || p.Validate() != nil {
		t.Fatal("review policy")
	}
	r := p.Roles["observe"]
	a := sshcommand.Authority{Binary: "/usr/local/bin/21pins", PolicyFile: "/etc/ssh/21pins/commands.json", Rules: r.Rules}
	force, e := a.ForcedCommand(p.Workspace, p.Host, "observe", r.User)
	if e != nil {
		t.Fatal(e)
	}
	principal, _ := os.ReadFile("../../docs/ssh-pins-agent-principals")
	fragment, _ := os.ReadFile("../../docs/ssh-pins-agent-match.conf")
	if !strings.Contains(string(principal), `command="`+force+`",restrict 21pins:`+p.Workspace+":"+p.Host+":observe") || !strings.Contains(string(fragment), "ForceCommand "+force) || !strings.Contains(string(fragment), "AcceptEnv 21PINS_UNUSED") {
		t.Fatal("review bundle drift")
	}
}

func TestGatedBootstrapBindsSameForcedCommand(t *testing.T) {
	dir := t.TempDir()
	ca := nativeKey(t, dir, "ca")
	gate := sshcommand.Authority{Binary: "/usr/local/bin/21pins", PolicyFile: "/etc/ssh/21pins/commands.json", Rules: []sshcommand.Rule{{Command: []string{"status"}, Exec: []string{"/usr/bin/uptime"}}}}
	c := Config{Workspace: "local", CA: CA{Mode: "dev", PublicKeyFile: ca + ".pub"}, Hosts: map[string]Host{"alpha": {Roles: map[string]Role{"observe": {SSHUser: "pins-agent", CommandAuthority: &gate}}}}}
	out := filepath.Join(dir, "bundle")
	if e := BootstrapBundle(c, "alpha", out); e != nil {
		t.Fatal(e)
	}
	principal, _ := os.ReadFile(filepath.Join(out, "principals-pins-agent"))
	fragment, _ := os.ReadFile(filepath.Join(out, "sshd_config.fragment"))
	force, _ := gate.ForcedCommand("local", "alpha", "observe", "pins-agent")
	if !strings.Contains(string(principal), `command="`+force+`",restrict 21pins:local:alpha:observe`) || !strings.Contains(string(fragment), "ForceCommand "+force) || !strings.Contains(string(fragment), "Match User pins-agent") {
		t.Fatal("role gate not bound")
	}
	data, e := os.ReadFile(filepath.Join(out, "commands.json"))
	if e != nil || !strings.Contains(string(data), "/usr/bin/uptime") {
		t.Fatal("policy bundle missing")
	}
}
