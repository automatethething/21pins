package sshcommand

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyOwnershipSymlinksAndWritableFilesFailClosed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "commands.json")
	policy := Policy{Workspace: "local", Host: "alpha", Roles: map[string]RolePolicy{"observe": {User: "pins-agent", Rules: []Rule{{Command: []string{"status"}, Exec: []string{"/usr/bin/uptime"}}}}}}
	b, _ := json.Marshal(policy)
	os.WriteFile(p, b, 0600)
	if _, e := Load(p, true); e != nil {
		t.Fatal(e)
	}
	if os.Getuid() != 0 {
		if _, e := Load(p, false); e == nil {
			t.Fatal("nonroot production policy")
		}
	}
	os.Chmod(p, 0666)
	if _, e := Load(p, true); e == nil {
		t.Fatal("writable policy")
	}
	os.Chmod(p, 0600)
	link := filepath.Join(dir, "alias.json")
	os.Symlink(p, link)
	if _, e := Load(link, true); e == nil {
		t.Fatal("policy symlink")
	}
	if ParseAndDigestSmoke(policy) != nil {
		t.Fatal("digest unstable")
	}
}
func ParseAndDigestSmoke(p Policy) error {
	r := p.Roles["observe"].Rules
	if len(RulesDigest(r)) != 64 {
		return Denied
	}
	copy := append([]Rule{}, r...)
	if RulesDigest(r) != RulesDigest(copy) {
		return Denied
	}
	copy[0].Exec = []string{"/usr/bin/id", "-u"}
	if RulesDigest(r) == RulesDigest(copy) {
		return Denied
	}
	return nil
}
