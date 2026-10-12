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

// Explicit owner-authorized real target test: all requester keys and API tokens stay on Mac.
func TestApprovedVM221MacBastionCLI(t *testing.T) {
	if os.Getenv("PINS21_VM221_MAC_DOGFOOD") != "1" {
		t.Skip("explicit approved Mac bastion dogfood")
	}
	home, _ := os.UserHomeDir()
	issuer := filepath.Join(home, "Library/Application Support/21pins/ssh")
	svc, e := sshaccess.Load(issuer)
	if e != nil || svc.Config.Hosts["finland-staging-221"].JumpAlias != "fipi" {
		t.Fatal("explicit real issuer bastion scope missing")
	}
	dir := t.TempDir()
	st, e := store.New(filepath.Join(dir, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	use, e := st.CreateToken("pi", []string{"ssh:use"})
	if e != nil {
		t.Fatal("synthetic local requester")
	}
	owner, e := st.CreateToken("owner", []string{"ssh:approve"})
	if e != nil {
		t.Fatal("synthetic local approver")
	}
	useFile := filepath.Join(dir, "requester")
	ownerFile := filepath.Join(dir, "approver")
	if sshaccess.AtomicPrivate(useFile, []byte(use)) != nil || sshaccess.AtomicPrivate(ownerFile, []byte(owner)) != nil {
		t.Fatal("private local API credential fixture")
	}
	server := httptest.NewServer(gateway.NewServer(st, gateway.Config{SSHDir: issuer}).Handler())
	defer server.Close()
	binary := filepath.Join(dir, "21pins")
	build := exec.Command("go", "build", "-o", binary, ".")
	if build.Run() != nil {
		t.Fatal("native CLI build")
	}
	env := sshTransportEnv(os.Environ())
	env = append(env, "PINS21_SSH_API_URL="+server.URL, "PINS21_SSH_RUNTIME_DIR="+filepath.Join(dir, "runtime"), "PINS21_SSH_CONFIG_FILE="+filepath.Join(issuer, "ssh_config_vm221"))
	cli := func(tokenFile string, args ...string) ([]byte, error) {
		ctx, c := context.WithTimeout(context.Background(), 25*time.Second)
		defer c()
		cmd := exec.CommandContext(ctx, binary, append([]string{"ssh"}, args...)...)
		cmd.Env = append(env, "PINS21_SSH_TOKEN_FILE="+tokenFile)
		return cmd.Output()
	}
	b, e := cli(useFile, "open", "--host", "finland-staging-221", "--role", "observe", "--objective", "vm221-mac-bastion-dogfood", "--purpose", "owner-approved Mac execution verification", "--max-lease", "5m", "--json")
	if e != nil {
		t.Fatal("actual API CLI open")
	}
	var lease sshaccess.Lease
	if json.Unmarshal(b, &lease) != nil || lease.Status != sshaccess.PendingApproval || lease.SSHJumpAlias != "fipi" {
		t.Fatal("immutable approved scope")
	}
	closed := false
	defer func() {
		if !closed {
			cli(useFile, "cancel", lease.ID)
		}
	}()
	if _, e = cli(ownerFile, "approve", lease.ID, "--yes"); e != nil {
		t.Fatal("actual API approver")
	}
	for _, op := range []string{"platform", "status", "identity"} {
		b, e = cli(useFile, "exec", lease.ID, "--", op)
		if e != nil || len(b) == 0 {
			t.Fatal("actual Mac final certified operation denied", op)
		}
	}
	for _, op := range [][]string{{"sh", "-c", "id"}, {"platform;id"}, {"platform", "-a"}, {"/usr/bin/uname", "-s"}, {"$(id)"}, {"/usr/local/bin/21pins", "ssh", "gate"}} {
		if _, e = cli(useFile, append([]string{"exec", lease.ID, "--"}, op...)...); e == nil {
			t.Fatal("actual arbitrary command accepted")
		}
	}
	cache := filepath.Join(dir, "runtime", lease.ID)
	m, e := loadClient(cache)
	if e != nil {
		t.Fatal("private client metadata")
	}
	fp := m.Lease.PublicKeyFingerprint
	m.ValidBefore = time.Now().Add(-time.Second)
	if saveClient(cache, m) != nil {
		t.Fatal("force on-demand renewal")
	}
	if _, e = cli(useFile, "exec", lease.ID, "--", "platform"); e != nil {
		t.Fatal("real API renewal execution")
	}
	m, e = loadClient(cache)
	if e != nil || m.Lease.PublicKeyFingerprint != fp || !m.ValidBefore.After(time.Now()) {
		t.Fatal("same-key short certificate renewal")
	}
	resolved, e := resolveAlias(lease.SSHAlias)
	if e != nil {
		t.Fatal("alias")
	}
	args, e := sshArgs(lease, cache, resolved, false, []string{"platform"})
	if e != nil {
		t.Fatal(e)
	}
	known := filepath.Join(dir, "wrong-host-key")
	keyDir := filepath.Join(dir, "wrong-host-key-source")
	pub, e := generateLeaseKey(keyDir)
	if e != nil {
		t.Fatal("host pin negative")
	}
	os.WriteFile(known, []byte(resolved["hostname"]+" "+pub+"\n"), 0600)
	// Also override global trust to ensure the negative is independent of other known-host sources.
	args = append([]string{"-o", "UserKnownHostsFile=" + known, "-o", "GlobalKnownHostsFile=/dev/null"}, args...)
	ctx, c := context.WithTimeout(context.Background(), 20*time.Second)
	defer c()
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Env = sshTransportEnv(os.Environ())
	if cmd.Run() == nil {
		t.Fatal("changed final host key accepted")
	}
	if _, e = cli(useFile, "complete", lease.ID); e != nil {
		t.Fatal("actual API terminal close")
	}
	closed = true
	if _, e = os.Stat(filepath.Join(cache, "id_ed25519")); !os.IsNotExist(e) {
		t.Fatal("terminal local key cleanup")
	}
	if _, e = cli(useFile, "exec", lease.ID, "--", "platform"); e == nil {
		t.Fatal("terminal CLI execution")
	}
	t.Log("PASS: Mac API-only CLI, real local agent CA, existing native bastion -W, final target pinned key/certificate, 3 observe commands, arbitrary-command and changed-host-key negatives, same-key renewal and terminal local credential cleanup; zero remote key/token writes")
}
