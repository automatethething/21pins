package main

import (
	"github.com/petrichor/21pins-cli/internal/sshaccess"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSSHArgumentsAndLocalKeyLifecycle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "client")
	if e := sshaccess.PrivateDir(dir); e != nil {
		t.Fatal(e)
	}
	p, e := generateLeaseKey(dir)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = sshaccess.PublicFingerprint(p); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(filepath.Join(dir, "id_ed25519"))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private mode")
	}
	l := sshaccess.Lease{ID: "lease123", SSHUser: "dev", EffectivePolicy: sshaccess.Role{SSHUser: "dev"}}
	args, e := sshArgs(l, dir, map[string]string{"hostname": "localhost", "port": "2222", "userknownhostsfile": "/synthetic/known_hosts"}, false, []string{"printf", "a b"})
	if e != nil {
		t.Fatal(e)
	}
	s := strings.Join(args, " ")
	for _, v := range []string{"StrictHostKeyChecking=yes", "ControlMaster=no", "ControlPersist=no", "IdentityAgent=none", "ForwardAgent=no", "ClearAllForwardings=yes", "-T"} {
		if !strings.Contains(s, v) {
			t.Fatal("missing restriction", v)
		}
	}
	if strings.Contains(s, "StrictHostKeyChecking=no") {
		t.Fatal("insecure")
	}
	if _, e = sshArgs(l, dir, map[string]string{"hostname": "localhost", "port": "22"}, true, nil); e == nil {
		t.Fatal("pty not approved")
	}
	if args[len(args)-1] != "'printf' 'a b'" {
		t.Fatal("remote quoting")
	}
}
func TestClientDeletesTerminalAndExpiredKeys(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runtime")
	if e := sshaccess.PrivateDir(root); e != nil {
		t.Fatal(e)
	}
	d := filepath.Join(root, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if e := sshaccess.PrivateDir(d); e != nil {
		t.Fatal(e)
	}
	if _, e := generateLeaseKey(d); e != nil {
		t.Fatal(e)
	}
	m := clientLease{Lease: sshaccess.Lease{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", HardExpiresAt: time.Now().Add(-time.Second), Status: sshaccess.Active}}
	if e := saveClient(d, m); e != nil {
		t.Fatal(e)
	}
	if e := sweepClient(root, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(d, "id_ed25519")); !os.IsNotExist(e) {
		t.Fatal("expired key not deleted")
	}
}
