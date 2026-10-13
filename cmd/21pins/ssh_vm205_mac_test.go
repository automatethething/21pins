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

// Owner-approved real Mac→existing bastion→VM205 test; no remote credentials or network/service mutations.
func TestApprovedVM205MacBerylCLI(t *testing.T) {
	if os.Getenv("PINS21_VM205_MAC_DOGFOOD") != "1" {
		t.Skip("explicit approved VM205 installation smoke")
	}
	home, _ := os.UserHomeDir()
	issuer := filepath.Join(home, "Library/Application Support/21pins/ssh")
	svc, e := sshaccess.Load(issuer)
	if e != nil || svc.Config.Hosts["wg-gateway"].JumpAlias != "fipi" {
		t.Fatal("reviewed issuer scope missing")
	}
	t.Setenv("PINS21_SSH_CONFIG_FILE", filepath.Join(issuer, "ssh_config_vm205"))
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
	env = append(env, "PINS21_SSH_API_URL="+server.URL, "PINS21_SSH_RUNTIME_DIR="+filepath.Join(dir, "runtime"), "PINS21_SSH_CONFIG_FILE="+filepath.Join(issuer, "ssh_config_vm205"))
	cli := func(token string, args ...string) ([]byte, error) {
		ctx, c := context.WithTimeout(context.Background(), 15*time.Second)
		defer c()
		cmd := exec.CommandContext(ctx, binary, append([]string{"ssh"}, args...)...)
		cmd.Env = append(env, "PINS21_SSH_TOKEN_FILE="+token)
		return cmd.Output()
	}
	b, e := cli(uf, "open", "--host", "wg-gateway", "--role", "wg-beryl", "--objective", "vm205-beryl-dogfood", "--purpose", "approved Beryl-only installation verification", "--max-lease", "5m", "--json")
	var lease sshaccess.Lease
	if e != nil || json.Unmarshal(b, &lease) != nil || lease.Status != sshaccess.PendingApproval || lease.SSHUser != "pins-wg-agent" || lease.SSHJumpAlias != "fipi" {
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
	for _, op := range [][]string{{"beryl", "enroll"}} {
		b, e = cli(uf, append([]string{"exec", lease.ID, "--"}, op...)...)
		var r struct {
			Verified bool `json:"verified"`
		}
		if e != nil || json.Unmarshal(b, &r) != nil || !r.Verified {
			t.Fatal("actual certified baseline denied", op)
		}
	}
	for _, op := range [][]string{{"dns", "query"}, {"technitium", "status"}, {"guest", "isolation"}, {"beryl", "verify"}, {"wireguard", "state"}, {"wireguard", "handshake"}, {"sh", "-c", "id"}, {"beryl", "enroll", "altered"}, {"beryl enroll;id"}, {"sudo", "/bin/sh"}} {
		if _, e = cli(uf, append([]string{"exec", lease.ID, "--"}, op...)...); e == nil {
			t.Fatal("unexpected authority/evidence", op)
		}
	}
	b, e = cli(uf, "exec", lease.ID, "--", "beryl", "inspect")
	var inspection struct {
		Operation   string `json:"operation"`
		PeerCount   int    `json:"peer_count"`
		Verified    bool   `json:"verified"`
		HandshakeAt int64  `json:"handshake_at"`
	}
	if json.Unmarshal(b, &inspection) != nil || inspection.Operation != "peer-inspect" || inspection.PeerCount != 4 {
		t.Fatal("certified inspection/config denied")
	}
	if e == nil && !inspection.Verified {
		t.Fatal("false inspection success")
	}
	t.Logf("Server inspection recent=%t; server-only timestamp is NOT fresh Beryl-origin E2E evidence", inspection.Verified)
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
	if _, e = cli(uf, "exec", lease.ID, "--", "beryl", "enroll"); e != nil {
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
	args, e := sshArgs(wrong, cache, resolved, false, []string{"beryl", "enroll"})
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
	if os.WriteFile(badPin, []byte(resolved["hostname"]+" "+pub+"\n"), 0600) != nil {
		t.Fatal("pin fixture file")
	}
	args, e = sshArgs(lease, cache, resolved, false, []string{"beryl", "enroll"})
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
	if _, e = cli(uf, "exec", lease.ID, "--", "beryl", "enroll"); e == nil {
		t.Fatal("completed lease reuse")
	}
	t.Log("PASS: actual Mac API-only certificate via existing bastion, fixed Beryl enrollment/inspection, cross-DNS/obsolete/shell/argv/sudo/user/host-key negatives, same-key renewal/completion/cleanup; no remote credentials or network/peer writes; NOT client-origin E2E proof")
}
