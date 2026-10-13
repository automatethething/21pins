package sshaccess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestApprovedVM205LocalRegistration(t *testing.T) {
	if os.Getenv("PINS21_VM205_REGISTER") != "1" {
		t.Skip("explicit approved post-install registration")
	}
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, "Library/Application Support/21pins/ssh")
	svc, e := Load(dir)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := svc.Config.Hosts["wg-gateway"]; ok {
		t.Fatal("existing registration")
	}
	raw, e := ReadPrivate(filepath.Join(dir, "wg-beryl-manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	h, e := WGBerylHost(hex.EncodeToString(sum[:]), "pins-vm205", "fipi")
	if e != nil {
		t.Fatal(e)
	}
	known := filepath.Join(dir, "known_hosts-vm205")
	if _, e = ReadPrivate(known); e != nil {
		t.Fatal("trusted pin")
	}
	raw, e = ReadPrivate(filepath.Join(dir, "target-vm205.json"))
	var target struct {
		Hostname string `json:"hostname"`
	}
	if e != nil || json.Unmarshal(raw, &target) != nil || target.Hostname == "" {
		t.Fatal("target")
	}
	backup := filepath.Join(dir, "config.before-vm205-beryl.json")
	if _, e = os.Stat(backup); !os.IsNotExist(e) {
		t.Fatal("existing backup")
	}
	profile := filepath.Join(dir, "ssh_config_vm205")
	if _, e = os.Stat(profile); !os.IsNotExist(e) {
		t.Fatal("existing profile")
	}
	before, e := ReadPrivate(filepath.Join(dir, "config.json"))
	if e != nil || AtomicPrivate(backup, before) != nil {
		t.Fatal("backup")
	}
	svc.Config.Hosts["wg-gateway"] = h
	if validateConfig(svc.Config) != nil {
		t.Fatal("scope")
	}
	b, _ := json.MarshalIndent(svc.Config, "", "  ")
	if AtomicPrivate(filepath.Join(dir, "config.json"), b) != nil {
		t.Fatal("scope save")
	}
	config := fmt.Sprintf("Host pins-vm205\n HostName %s\n User pins-wg-agent\n Port 22\n StrictHostKeyChecking yes\n UserKnownHostsFile %q\n GlobalKnownHostsFile /dev/null\n IdentityAgent none\n IdentitiesOnly yes\n ForwardAgent no\n ProxyCommand none\n ProxyJump none\n", target.Hostname, known)
	if AtomicPrivate(profile, []byte(config)) != nil {
		AtomicPrivate(filepath.Join(dir, "config.json"), before)
		t.Fatal("profile; config restored")
	}
	t.Log("PASS: only reviewed WG host/role/profile registered; original DNS/observe issuer scopes preserved")
}
