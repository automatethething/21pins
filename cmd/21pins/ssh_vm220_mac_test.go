package main

import (
	"context"
	"encoding/json"
	"github.com/petrichor/21pins-cli/internal/gateway"
	"github.com/petrichor/21pins-cli/internal/sshaccess"
	"github.com/petrichor/21pins-cli/internal/store"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Owner-approved real Mac→existing bastion→VM220 test; no remote credentials or network/service mutations.
func TestApprovedVM220MacTechnitiumCLI(t *testing.T) {
	if os.Getenv("PINS21_VM220_MAC_DOGFOOD") != "1" {
		t.Skip("explicit approved VM220 installation smoke")
	}
	home, _ := os.UserHomeDir()
	issuer := filepath.Join(home, "Library/Application Support/21pins/ssh")
	svc, e := sshaccess.Load(issuer)
	if e != nil || svc.Config.Hosts["dns-primary"].JumpAlias != "fipi" {
		t.Fatal("reviewed issuer scope missing")
	}
	t.Setenv("PINS21_SSH_CONFIG_FILE", filepath.Join(issuer, "ssh_config_vm220"))
	dir := t.TempDir()
	st, e := store.New(filepath.Join(dir, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	use, e := st.CreateToken("pi", []string{"ssh:use"})
	if e != nil {
		t.Fatal("requester fixture")
	}
	owner, e := st.CreateToken("owner", []string{"ssh:approve"})
	if e != nil {
		t.Fatal("approver fixture")
	}
	uf := filepath.Join(dir, "requester")
	of := filepath.Join(dir, "approver")
	if sshaccess.AtomicPrivate(uf, []byte(use)) != nil || sshaccess.AtomicPrivate(of, []byte(owner)) != nil {
		t.Fatal("private local API fixture")
	}
	server := httptest.NewServer(gateway.NewServer(st, gateway.Config{SSHDir: issuer}).Handler())
	defer server.Close()
	binary, _ := filepath.Abs("../../21pins")
	env := sshTransportEnv(os.Environ())
	env = append(env, "PINS21_SSH_API_URL="+server.URL, "PINS21_SSH_RUNTIME_DIR="+filepath.Join(dir, "runtime"), "PINS21_SSH_CONFIG_FILE="+filepath.Join(issuer, "ssh_config_vm220"))
	cli := func(token string, args ...string) ([]byte, error) {
		ctx, c := context.WithTimeout(context.Background(), 15*time.Second)
		defer c()
		cmd := exec.CommandContext(ctx, binary, append([]string{"ssh"}, args...)...)
		cmd.Env = append(env, "PINS21_SSH_TOKEN_FILE="+token)
		return cmd.Output()
	}
	b, e := cli(uf, "open", "--host", "dns-primary", "--role", "dns-admin", "--objective", "vm220-technitium-dogfood", "--purpose", "approved DNS-only installation verification", "--max-lease", "5m", "--json")
	var lease sshaccess.Lease
	if e != nil || json.Unmarshal(b, &lease) != nil || lease.Status != sshaccess.PendingApproval || lease.SSHUser != "pins-dns-agent" || lease.SSHJumpAlias != "fipi" {
		t.Fatal("approved immutable lease")
	}
	closed := false
	defer func() {
		if !closed {
			cli(uf, "cancel", lease.ID)
		}
	}()
	if _, e = cli(of, "approve", lease.ID, "--yes"); e != nil {
		t.Fatal("actual independent API approval")
	}
	for _, op := range [][]string{{"dns", "query"}, {"dns", "test"}, {"technitium", "status"}} {
		b, e = cli(uf, append([]string{"exec", lease.ID, "--"}, op...)...)
		var r struct {
			Verified bool `json:"verified"`
		}
		if e != nil || json.Unmarshal(b, &r) != nil || !r.Verified {
			t.Fatal("actual certified baseline denied", op)
		}
	}
	for _, op := range [][]string{{"technitium", "filtering"}, {"guest", "isolation"}, {"beryl", "enroll"}, {"wireguard", "state"}, {"adguard", "status"}, {"sh", "-c", "id"}, {"dns", "query", "altered"}, {"dns query;id"}, {"sudo", "/bin/sh"}} {
		if _, e = cli(uf, append([]string{"exec", lease.ID, "--"}, op...)...); e == nil {
			t.Fatal("unexpected authority/evidence", op)
		}
	}
	cache := filepath.Join(dir, "runtime", lease.ID)
	m, e := loadClient(cache)
	if e != nil {
		t.Fatal("client metadata")
	}
	fp := m.Lease.PublicKeyFingerprint
	m.ValidBefore = time.Now().Add(-time.Second)
	if saveClient(cache, m) != nil {
		t.Fatal("renewal test")
	}
	if _, e = cli(uf, "exec", lease.ID, "--", "dns", "query"); e != nil {
		t.Fatal("actual same-key API renewal")
	}
	m, e = loadClient(cache)
	if e != nil || m.Lease.PublicKeyFingerprint != fp || !m.ValidBefore.After(time.Now()) {
		t.Fatal("renewal scope")
	}
	resolved, e := resolveAlias(lease.SSHAlias)
	if e != nil {
		t.Fatal("target alias")
	}
	wrong := lease
	wrong.SSHUser = "root"
	args, e := sshArgs(wrong, cache, resolved, false, []string{"dns", "query"})
	if e != nil {
		t.Fatal(e)
	}
	ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Env = sshTransportEnv(os.Environ())
	e = cmd.Run()
	c()
	if e == nil {
		t.Fatal("wrong target Unix user")
	}
	badPin := filepath.Join(dir, "wrong-host")
	pub, e := generateLeaseKey(filepath.Join(dir, "wrong-host-source"))
	if e != nil {
		t.Fatal("pin fixture")
	}
	if os.WriteFile(badPin, []byte("10.77.0.53 "+pub+"\n"), 0600) != nil {
		t.Fatal("pin fixture file")
	}
	args, e = sshArgs(lease, cache, resolved, false, []string{"dns", "query"})
	if e != nil {
		t.Fatal(e)
	}
	args = append([]string{"-o", "UserKnownHostsFile=" + badPin, "-o", "GlobalKnownHostsFile=/dev/null"}, args...)
	ctx, c = context.WithTimeout(context.Background(), 10*time.Second)
	cmd = exec.CommandContext(ctx, "ssh", args...)
	cmd.Env = sshTransportEnv(os.Environ())
	e = cmd.Run()
	c()
	if e == nil {
		t.Fatal("changed target host key accepted")
	}
	if _, e = cli(uf, "complete", lease.ID); e != nil {
		t.Fatal("terminal close")
	}
	closed = true
	if _, e = os.Stat(filepath.Join(cache, "id_ed25519")); !os.IsNotExist(e) {
		t.Fatal("local key cleanup")
	}
	if _, e = cli(uf, "exec", lease.ID, "--", "dns", "query"); e == nil {
		t.Fatal("completed lease reuse")
	}
	t.Log("PASS: actual Mac API-only certificate via existing bastion, DNS UDP+TCP and Technitium status, unavailable filter/guest and old WG/AdGuard/shell/argv/sudo/user negatives, same-key renewal/completion/cleanup; no remote credentials or DNS/network/peer writes")
}
