package sshaccess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/petrichor/21pins-cli/internal/dnsadmin"
	"os"
	"path/filepath"
	"testing"
)

func TestApprovedVM220LocalRegistration(t *testing.T) {
	if os.Getenv("PINS21_VM220_REGISTER") != "1" {
		t.Skip("explicit approved post-install scope registration")
	}
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, "Library/Application Support/21pins/ssh")
	svc, e := Load(dir)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("../../docs/ssh-technitium-manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	s := sha256.Sum256(raw)
	h, e := DNSAdminHost(hex.EncodeToString(s[:]), "pins-vm220", "fipi")
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := svc.Config.Hosts["dns-primary"]; ok {
		t.Fatal("existing registration must be reconciled")
	}
	known := filepath.Join(dir, "known_hosts-vm220")
	if _, e = ReadPrivate(known); e != nil {
		t.Fatal("trusted management host pin missing")
	}
	if _, e = os.Stat(filepath.Join(dir, "ssh_config_vm220")); !os.IsNotExist(e) {
		t.Fatal("existing target profile")
	}
	backup := filepath.Join(dir, "config.before-vm220-technitium.json")
	if _, e = os.Stat(backup); !os.IsNotExist(e) {
		t.Fatal("backup exists")
	}
	before, e := ReadPrivate(filepath.Join(dir, "config.json"))
	if e != nil || AtomicPrivate(backup, before) != nil {
		t.Fatal("private scope backup")
	}
	svc.Config.Hosts["dns-primary"] = h
	if validateConfig(svc.Config) != nil {
		t.Fatal("reviewed scope")
	}
	b, _ := json.MarshalIndent(svc.Config, "", "  ")
	if AtomicPrivate(filepath.Join(dir, "config.json"), b) != nil {
		t.Fatal("atomic registration")
	}
	config := fmt.Sprintf("Host pins-vm220\n HostName 10.77.0.53\n User pins-dns-agent\n Port 22\n StrictHostKeyChecking yes\n UserKnownHostsFile %q\n GlobalKnownHostsFile /dev/null\n IdentityAgent none\n IdentitiesOnly yes\n ForwardAgent no\n ProxyCommand none\n ProxyJump none\n", known)
	if AtomicPrivate(filepath.Join(dir, "ssh_config_vm220"), []byte(config)) != nil {
		AtomicPrivate(filepath.Join(dir, "config.json"), before)
		t.Fatal("local pinned profile; scope restored")
	}
	t.Log("PASS: only reviewed DNS-only issuer host/role and pinned local target config registered; previous host scope backed up/preserved")
}

// Owner-approved local public installation artifacts only; never signs or copies private custody.
func TestApprovedVM220Artifacts(t *testing.T) {
	out := os.Getenv("PINS21_VM220_ARTIFACT_DIR")
	if out == "" {
		t.Skip("explicit approved installation artifact directory")
	}
	if !filepath.IsAbs(out) {
		t.Fatal("private stage must be absolute")
	}
	home, _ := os.UserHomeDir()
	issuer := filepath.Join(home, "Library/Application Support/21pins/ssh")
	svc, e := Load(issuer)
	if e != nil || svc.Config.CA.Mode != "agent" || svc.Config.CA.SecretRef != "" {
		t.Fatal("real local agent custody")
	}
	raw, e := os.ReadFile("../../docs/ssh-technitium-manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	s := sha256.Sum256(raw)
	digest := hex.EncodeToString(s[:])
	h, e := DNSAdminHost(digest, "pins-vm220", "fipi")
	if e != nil {
		t.Fatal(e)
	}
	cfg := svc.Config
	cfg.Hosts = map[string]Host{"dns-primary": h}
	if validateConfig(cfg) != nil {
		t.Fatal("real scope validation")
	}
	if BootstrapBundle(cfg, "dns-primary", out) != nil {
		t.Fatal("public bundle")
	}
	sudo, e := dnsadmin.Sudoers(digest)
	if e != nil {
		t.Fatal(e)
	}
	if AtomicPrivate(filepath.Join(out, "dns-admin.json"), raw) != nil || AtomicPrivate(filepath.Join(out, "sudoers"), []byte(sudo)) != nil {
		t.Fatal("private public-artifact stage")
	}
	t.Log("PASS: actual public CA / five-rule bundle / root manifest / exact sudoers staged locally; no private material or issuer registration")
}
