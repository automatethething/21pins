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

// Verification ONLY: no enrollment, no guest-agent/root bypass, no role/config changes.
func TestApprovedBerylTrustedCorrelationReadOnly(t *testing.T) {
	if os.Getenv("PINS21_BERYL_CORRELATION_READONLY") != "1" {
		t.Skip("owner-requested scoped read-only correlation")
	}
	home, _ := os.UserHomeDir()
	issuer := filepath.Join(home, "Library/Application Support/21pins/ssh")
	svc, e := sshaccess.Load(issuer)
	if e != nil {
		t.Fatal("existing issuer unavailable")
	}
	dir := t.TempDir()
	st, e := store.New(filepath.Join(dir, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	use, e := st.CreateToken("pi", []string{"ssh:use"})
	if e != nil {
		t.Fatal("requester")
	}
	owner, e := st.CreateToken("owner", []string{"ssh:approve"})
	if e != nil {
		t.Fatal("approver")
	}
	uf := filepath.Join(dir, "requester")
	of := filepath.Join(dir, "approver")
	if sshaccess.AtomicPrivate(uf, []byte(use)) != nil || sshaccess.AtomicPrivate(of, []byte(owner)) != nil {
		t.Fatal("private temporary credentials")
	}
	server := httptest.NewServer(gateway.NewServer(st, gateway.Config{SSHDir: issuer}).Handler())
	defer server.Close()
	binary, _ := filepath.Abs("../../21pins")
	for _, scope := range []struct {
		host, role, profile string
		ops                 [][]string
	}{{"wg-gateway", "wg-beryl", "ssh_config_vm205", [][]string{{"beryl", "inspect"}}}, {"dns-primary", "dns-admin", "ssh_config_vm220", [][]string{{"dns", "test"}, {"technitium", "status"}, {"technitium", "filtering"}}}} {
		h, ok := svc.Config.Hosts[scope.host]
		if !ok || h.JumpAlias != "fipi" {
			t.Fatal("reviewed host missing")
		}
		env := append(sshTransportEnv(os.Environ()), "PINS21_SSH_API_URL="+server.URL, "PINS21_SSH_RUNTIME_DIR="+filepath.Join(dir, "runtime"), "PINS21_SSH_CONFIG_FILE="+filepath.Join(issuer, scope.profile))
		cli := func(token string, args ...string) ([]byte, error) {
			ctx, c := context.WithTimeout(context.Background(), 15*time.Second)
			defer c()
			cmd := exec.CommandContext(ctx, binary, append([]string{"ssh"}, args...)...)
			cmd.Env = append(env, "PINS21_SSH_TOKEN_FILE="+token)
			return cmd.Output()
		}
		b, e := cli(uf, "open", "--host", scope.host, "--role", scope.role, "--objective", "beryl-trusted-historical-correlation", "--purpose", "owner requested read-only historical correlation", "--max-lease", "5m", "--json")
		var l sshaccess.Lease
		if e != nil || json.Unmarshal(b, &l) != nil || l.Status != sshaccess.PendingApproval {
			t.Fatal("read-only work lease")
		}
		func() {
			closed := false
			defer func() {
				if !closed {
					cli(uf, "cancel", l.ID)
				}
			}()
			if _, e = cli(of, "approve", l.ID, "--yes"); e != nil {
				t.Fatal("existing agent approval/signing unavailable")
			}
			for _, op := range scope.ops {
				b, e = cli(uf, append([]string{"exec", l.ID, "--"}, op...)...)
				var r struct {
					Operation       string `json:"operation"`
					Verified        bool   `json:"verified"`
					State           string `json:"state"`
					HandshakeRecent bool   `json:"handshake_recent"`
					HandshakeAt     int64  `json:"handshake_at"`
					PeerCount       int    `json:"peer_count"`
				}
				if json.Unmarshal(b, &r) != nil {
					t.Fatal("bounded helper output unavailable", scope.role, op)
				}
				t.Logf("scope=%s operation=%s success=%t verified=%t state=%s handshake_recent=%t handshake_at=%d peer_count=%d", scope.role, r.Operation, e == nil, r.Verified, r.State, r.HandshakeRecent, r.HandshakeAt, r.PeerCount)
				if (r.Operation == "dns-test" || r.Operation == "technitium-status") && (e != nil || !r.Verified) {
					t.Fatal("current DNS baseline failure")
				}
			}
			if _, e = cli(uf, "complete", l.ID); e != nil {
				t.Fatal("terminal cleanup")
			}
			closed = true
			if _, e = os.Stat(filepath.Join(dir, "runtime", l.ID, "id_ed25519")); !os.IsNotExist(e) {
				t.Fatal("requester key residue")
			}
		}()
	}
	t.Log("Read-only scopes executed and credentials cleaned; current helper results are NOT historical nonce/query/filter proof")
}
