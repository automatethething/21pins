package main

import (
	"github.com/petrichor/21pins-cli/internal/sshaccess"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTransportEnvironmentContainsNoControlCredentials(t *testing.T) {
	got := strings.Join(sshTransportEnv([]string{"PATH=/bin", "HOME=/synthetic", "PINS21_TOKEN=synthetic", "SSH_AUTH_SOCK=/synthetic/ca", "UNRELATED_SECRET=synthetic"}), " ")
	if got != "PATH=/bin HOME=/synthetic" {
		t.Fatal("transport environment not minimized")
	}
}
func TestKnownHostsFilenameWithSpaces(t *testing.T) {
	p := filepath.Join(t.TempDir(), "known hosts")
	if os.WriteFile(p, nil, 0600) != nil {
		t.Fatal("fixture")
	}
	a, e := sshArgs(sshaccess.Lease{SSHUser: "test"}, "/synthetic", map[string]string{"hostname": "localhost", "port": "22", "userknownhostsfile": p}, false, []string{"platform"})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(strings.Join(a, " "), "UserKnownHostsFile=\""+p+"\"") {
		t.Fatal("single path lost SSH option quoting")
	}
}
func TestExplicitLeaseBastionKeepsFinalCredentialsLocal(t *testing.T) {
	l := sshaccess.Lease{SSHUser: "pins-agent", SSHJumpAlias: "management", EffectivePolicy: sshaccess.Role{SSHUser: "pins-agent"}}
	r := map[string]string{"hostname": "target.example", "port": "22", "userknownhostsfile": "/synthetic/known_hosts"}
	args, e := sshArgs(l, "/synthetic/client", r, false, []string{"platform"})
	if e != nil {
		t.Fatal(e)
	}
	s := strings.Join(args, " ")
	for _, want := range []string{"ProxyCommand=", "'-W' 'target.example:22' 'management'", "StrictHostKeyChecking=yes", "IdentityAgent=none", "ForwardAgent=no", "ProxyJump=none", "ControlPath=none"} {
		if !strings.Contains(s, want) {
			t.Fatal("missing bastion defense", want)
		}
	}
	var proxy string
	for _, arg := range args {
		if strings.HasPrefix(arg, "ProxyCommand=") {
			proxy = arg
		}
	}
	if strings.Contains(proxy, "id_ed25519") || strings.Contains(proxy, "CertificateFile=") || strings.Contains(proxy, "ca-agent") {
		t.Fatal("final credentials passed to management hop")
	}
	for _, bad := range []string{"a,b", "x;id", "root@jump", "-jump"} {
		l.SSHJumpAlias = bad
		if _, e = sshArgs(l, "/synthetic/client", r, false, []string{"platform"}); e == nil {
			t.Fatal("bad hop")
		}
	}
	l.SSHJumpAlias = "management"
	r["hostname"] = "host%h"
	if _, e = sshArgs(l, "/synthetic/client", r, false, []string{"platform"}); e == nil {
		t.Fatal("proxy percent expansion")
	}
	l.SSHJumpAlias = ""
	r["hostname"] = "localhost"
	r["proxycommand"] = "untrusted"
	r["proxyjump"] = "untrusted"
	args, e = sshArgs(l, "/synthetic/client", r, false, []string{"platform"})
	if e != nil || strings.Contains(strings.Join(args, " "), "ProxyCommand=") {
		t.Fatal("inherited proxy not ignored")
	}
}
