package sshaccess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/petrichor/21pins-cli/internal/dnsadmin"
	"github.com/petrichor/21pins-cli/internal/sshcommand"
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareVM205BerylPublicArtifacts(t *testing.T) {
	dir := os.Getenv("PINS21_PREPARE_VM205_ARTIFACTS")
	if dir == "" {
		t.Skip("opt-in local public-only review bundle; never installs/registers")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("absolute private review directory")
	}
	home, e := os.UserHomeDir()
	if e != nil {
		t.Fatal("home")
	}
	custody := filepath.Join(home, "Library/Application Support/21pins/ssh")
	m, e := ReadPrivate(filepath.Join(custody, "wg-beryl-manifest.json"))
	if e != nil {
		t.Fatal("owner identity manifest")
	}
	sum := sha256.Sum256(m)
	hash := hex.EncodeToString(sum[:])
	h, e := WGBerylHost(hash, "pins-vm205", "fipi")
	if e != nil {
		t.Fatal(e)
	}
	svc, e := Load(custody)
	if e != nil || svc.Config.CA.Mode != "agent" || svc.Config.CA.SecretRef != "" {
		t.Fatal("real local agent custody")
	}
	cfg := svc.Config
	cfg.Hosts = map[string]Host{"wg-gateway": h}
	if validateConfig(cfg) != nil || BootstrapBundle(cfg, "wg-gateway", dir) != nil {
		t.Fatal("public bundle")
	}
	sudo, e := dnsadmin.WireGuardSudoers(hash)
	if e != nil {
		t.Fatal(e)
	}
	for n, raw := range map[string][]byte{"wg-beryl.json": m, "sudoers": []byte(sudo)} {
		if AtomicPrivate(filepath.Join(dir, n), raw) != nil {
			t.Fatal("private public artifacts")
		}
	}
	proof := struct {
		ManifestDigest, RulesDigest string
		PublicOnly                  bool
	}{hash, sshcommand.RulesDigest(h.Roles["wg-beryl"].CommandAuthority.Rules), true}
	raw, _ := json.Marshal(proof)
	if AtomicPrivate(filepath.Join(dir, "review-proof.json"), raw) != nil {
		t.Fatal("proof")
	}
	t.Log("PASS: exact owner-pinned public-only VM205 review bundle prepared locally; issuer/target untouched")
}
