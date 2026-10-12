package sshaccess

import (
	"github.com/petrichor/21pins-cli/internal/sshcommand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeSignedForceCommandAndExactVerifier(t *testing.T) {
	dir := t.TempDir()
	ca := nativeKey(t, dir, "ca")
	key := nativeKey(t, dir, "key")
	pub, _ := os.ReadFile(key + ".pub")
	now := time.Now().UTC().Truncate(time.Second)
	gate := sshcommand.Authority{Binary: "/usr/local/bin/21pins", PolicyFile: "/etc/ssh/21pins/commands.json", Rules: []sshcommand.Rule{{Command: []string{"status"}, Exec: []string{"/usr/bin/uptime"}}}}
	force, e := gate.ForcedCommand("local", "alpha", "observe", "pins-agent")
	if e != nil {
		t.Fatal(e)
	}
	r := SignRequest{PublicKey: strings.TrimSpace(string(pub)), Serial: 1, Principal: "21pins:local:alpha:observe", KeyID: "synthetic", ValidAfter: now.Add(-time.Second), ValidBefore: now.Add(time.Minute), ForceCommand: force}
	n := NativeSigner{CA: CA{Mode: "dev", PublicKeyFile: ca + ".pub", SecretRef: ca}}
	cert, e := n.Sign(r)
	if e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(dir, "cert.pub")
	os.WriteFile(file, []byte(cert), 0600)
	out, e := exec.Command("ssh-keygen", "-L", "-f", file).Output()
	if e != nil || !strings.Contains(string(out), "force-command "+force) || !strings.Contains(string(out), "Extensions: (none)") {
		t.Fatal("signed gate absent")
	}
	capub, _ := os.ReadFile(ca + ".pub")
	r.ForceCommand += " --role altered"
	if verifyCertificate(cert, strings.TrimSpace(string(capub)), r) == nil {
		t.Fatal("altered force command accepted")
	}
	r.ForceCommand = ""
	if verifyCertificate(cert, strings.TrimSpace(string(capub)), r) == nil {
		t.Fatal("unexpected critical option accepted")
	}
}
func TestProductionRolesRequireCommandAuthority(t *testing.T) {
	s, _, _, _, _ := fixture(t, false)
	s.Config.CA.Mode = "agent"
	if validateConfig(s.Config) == nil {
		t.Fatal("production role without gate")
	}
	h := s.Config.Hosts["alpha"]
	r := h.Roles["observe"]
	r.CommandAuthority = &sshcommand.Authority{Binary: "/usr/local/bin/21pins", PolicyFile: "/etc/ssh/21pins/commands.json", Rules: []sshcommand.Rule{{Command: []string{"status"}, Exec: []string{"/usr/bin/uptime"}}}}
	h.Roles["observe"] = r
	s.Config.Hosts = map[string]Host{"alpha": h}
	if validateConfig(s.Config) != nil {
		t.Fatal("valid production gate")
	}
	r.CommandAuthority.Fixture = true
	if validateConfig(s.Config) == nil {
		t.Fatal("production fixture gate")
	}
}
