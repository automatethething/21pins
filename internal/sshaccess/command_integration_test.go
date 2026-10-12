package sshaccess

import (
	"context"
	"fmt"
	"github.com/petrichor/21pins-cli/internal/dnsadmin"
	"github.com/petrichor/21pins-cli/internal/sshcommand"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestIsolatedCommandAuthority(t *testing.T) {
	runIsolatedRoleGate(t, "observe", []sshcommand.Rule{{Command: []string{"platform"}, Exec: []string{"/usr/bin/uname", "-s"}}})
}
func TestIsolatedDNSAdminAuthority(t *testing.T) {
	rules, e := dnsadmin.Rules(strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	// Native SSH fixture proves literal operation dispatch, not production sudo/kernel WG.
	for i := range rules {
		rules[i].Exec = []string{"/usr/bin/printf", "fixture-" + dnsadmin.Operations[i]}
		if i >= 3 {
			rules[i].Exec = []string{"/usr/bin/false"}
		} // Missing proof must propagate nonzero through the actual SSH gate.
	}
	runIsolatedRoleGate(t, "dns-admin", rules)
}
func runIsolatedRoleGate(t *testing.T, role string, rules []sshcommand.Rule) {
	allowed := strings.Join(rules[0].Command, " ")
	if os.Getenv("PINS21_SSH_INTEGRATION") != "1" {
		t.Skip("isolated native SSH opt-in")
	}
	sshd, e := exec.LookPath("sshd")
	if e != nil {
		t.Fatal("sshd required")
	}
	who, e := user.Current()
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	binary := filepath.Join(dir, "21pins")
	repo, _ := filepath.Abs("../..")
	build := exec.Command("go", "build", "-o", binary, "./cmd/21pins")
	build.Dir = repo
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if build.Run() != nil {
		t.Fatal("gate build")
	}
	ca := nativeKey(t, dir, "ca")
	key := nativeKey(t, dir, "client")
	hostkey := nativeKey(t, dir, "host")
	pub, _ := os.ReadFile(key + ".pub")
	gate := sshcommand.Authority{Binary: binary, PolicyFile: filepath.Join(dir, "bundle", "commands.json"), Fixture: true, Rules: rules}
	cfg := Config{Workspace: "fixture", CA: CA{Mode: "dev", PublicKeyFile: ca + ".pub", SecretRef: ca}, CertTTL: "20s", RenewBefore: "5s", ClockSkew: "1s", Hosts: map[string]Host{"alpha": {Alias: "alpha", Roles: map[string]Role{role: {SSHUser: who.Username, DefaultLease: "1m", MaxLease: "2m", MaxCertTTL: "20s", Requesters: map[string]string{"pi": "preapproved"}, CommandAuthority: &gate}}}}}
	svc, e := New(filepath.Join(dir, "state"), cfg, NativeSigner{CA: cfg.CA})
	if e != nil {
		t.Fatal(e)
	}
	bundle := filepath.Join(dir, "bundle")
	if BootstrapBundle(cfg, "alpha", bundle) != nil {
		t.Fatal("gated bundle")
	}
	force, _ := gate.ForcedCommand("fixture", "alpha", role, who.Username)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	serverConfig := filepath.Join(dir, "sshd_config")
	text := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nAuthorizedKeysFile none\nAuthorizedKeysCommand none\nTrustedUserCAKeys %s\nAuthorizedPrincipalsFile %s\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nPerSourcePenalties no\nPermitRootLogin no\nAllowUsers %s\nPermitTTY no\nDisableForwarding yes\nPermitUserRC no\nForceCommand %s\nSubsystem sftp internal-sftp\nLogLevel ERROR\n", port, hostkey, filepath.Join(dir, "sshd.pid"), filepath.Join(bundle, "21pins-ca.pub"), filepath.Join(bundle, "principals-"+who.Username), who.Username, force)
	text += "AcceptEnv LANG LC_* BASH_ENV LD_PRELOAD\nMatch User " + who.Username + "\n    AcceptEnv 21PINS_UNUSED\n"
	os.WriteFile(serverConfig, []byte(text), 0600)
	validation, err := exec.Command(sshd, "-t", "-f", serverConfig).CombinedOutput()
	if err != nil && strings.Contains(strings.ToLower(string(validation)), "bad configuration option: persourcepenalties") {
		text = strings.ReplaceAll(text, "PerSourcePenalties no\n", "")
		os.WriteFile(serverConfig, []byte(text), 0600)
		err = exec.Command(sshd, "-t", "-f", serverConfig).Run()
	}
	if err != nil {
		t.Fatal("gated sshd syntax")
	}
	effective, e := exec.Command(sshd, "-T", "-f", serverConfig, "-C", "user="+who.Username+",host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport="+strconv.Itoa(port)).Output()
	if e != nil {
		t.Fatal("native environment preflight")
	}
	accept := []string{}
	for _, line := range strings.Split(string(effective), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && strings.EqualFold(fields[0], "AcceptEnv") {
			accept = append(accept, fields[1:]...)
		}
	}
	if len(accept) != 1 || accept[0] != "21PINS_UNUSED" {
		t.Fatal("account AcceptEnv failed to replace unsafe global patterns")
	}
	server := exec.Command(sshd, "-D", "-e", "-f", serverConfig)
	if server.Start() != nil {
		t.Fatal("gated sshd start")
	}
	defer func() { server.Process.Kill(); server.Wait() }()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ready := false
	for i := 0; i < 40; i++ {
		conn, e := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if e == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatal("gated server unavailable")
	}
	hp, _ := os.ReadFile(hostkey + ".pub")
	known := filepath.Join(dir, "known_hosts")
	os.WriteFile(known, []byte("[127.0.0.1]:"+strconv.Itoa(port)+" "+strings.TrimSpace(string(hp))+"\n"), 0600)
	actor := Actor{ID: "fixture", Name: "pi"}
	q := OpenRequest{HostID: "alpha", RoleID: role, AgentClass: "pi", ObjectiveID: "command-check", Purpose: "synthetic", PublicKey: strings.TrimSpace(string(pub))}
	lease, e := svc.Open(actor, q)
	if e != nil {
		t.Fatal(e)
	}
	install := func(cert string) {
		t.Helper()
		if os.WriteFile(key+"-cert.pub", []byte(cert), 0600) != nil {
			t.Fatal("fixture certificate")
		}
	}
	issued, e := svc.Issue(actor, lease.ID, q.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	install(issued.Certificate)
	base := []string{"-F", "/dev/null", "-p", strconv.Itoa(port), "-l", who.Username, "-i", key, "-o", "CertificateFile=" + key + "-cert.pub", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + known, "-o", "ControlMaster=no", "-o", "ConnectTimeout=2"}
	run := func(command string, extra ...string) ([]byte, error) {
		if command == "platform" {
			command = allowed
		}
		ctx, c := context.WithTimeout(context.Background(), 8*time.Second)
		defer c()
		args := append(append([]string{}, base...), extra...)
		args = append(args, "127.0.0.1", command)
		cmd := exec.CommandContext(ctx, "ssh", args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir}
		return cmd.Output()
	}
	for _, r := range rules {
		out, e := run(strings.Join(r.Command, " "))
		if r.Exec[0] == "/usr/bin/false" {
			if e == nil || len(out) != 0 {
				t.Fatal("unavailable proof claimed success through SSH gate")
			}
			continue
		}
		if e != nil || strings.TrimSpace(string(out)) == "" {
			t.Fatal("allowed operation denied")
		}
	}
	for _, s := range []string{allowed + " extra", allowed + ";id", allowed + " $(id)", "sudo /bin/sh", "dns query altered", "beryl enroll", "beryl verify", "wireguard state", "wireguard handshake", "adguard status", "adguard filtering"} {
		if _, e := run(s); e == nil {
			t.Fatal("dns/root argument bypass")
		}
	}
	for _, cmd := range []string{"", "sh -c id", "platform; id", "platform && id", "platform | id", "$(id)", "`id`", "platform > /tmp/escape", "'platform' '-a'", "/usr/bin/uname -s", force, "sftp", "platform\nid"} {
		if _, e := run(cmd); e == nil {
			t.Fatal("command gate bypass", cmd)
		}
	}
	base[5] = "synthetic-no-such-user"
	if _, e := run("platform"); e == nil {
		t.Fatal("wrong Unix user")
	}
	base[5] = who.Username
	if _, e := run("sftp", "-s"); e == nil {
		t.Fatal("subsystem bypass")
	}
	if _, e := run("platform", "-tt"); e == nil {
		t.Fatal("PTY bypass")
	}
	if _, e := run("platform", "-o", "ExitOnForwardFailure=yes", "-R", "127.0.0.1:0:127.0.0.1:1"); e == nil {
		t.Fatal("forwarding bypass")
	}
	native := NativeSigner{CA: cfg.CA}
	now := time.Now().UTC().Truncate(time.Second)
	bad := SignRequest{PublicKey: q.PublicKey, Serial: 900, Principal: lease.Principal, KeyID: "synthetic-bad", ValidAfter: now.Add(-time.Second), ValidBefore: now.Add(30 * time.Second), ForceCommand: "/bin/sh"}
	badCert, e := native.Sign(bad)
	if e != nil {
		t.Fatal(e)
	}
	install(badCert)
	if _, e := run("platform"); e == nil {
		t.Fatal("certificate forced command mismatch accepted")
	}
	bad.ForceCommand = force
	bad.Principal = "21pins:fixture:alpha:wrong-role"
	badCert, e = native.Sign(bad)
	if e != nil {
		t.Fatal(e)
	}
	install(badCert)
	if _, e := run("platform"); e == nil {
		t.Fatal("wrong role")
	}
	bad.Principal = "21pins:fixture:beta:observe"
	badCert, e = native.Sign(bad)
	if e != nil {
		t.Fatal(e)
	}
	install(badCert)
	if _, e := run("platform"); e == nil {
		t.Fatal("wrong host")
	}
	// Missing signed force-command cannot bypass server principal/ForceCommand enforcement.
	bad.Principal = lease.Principal
	bad.ForceCommand = ""
	badCert, e = native.Sign(bad)
	if e != nil {
		t.Fatal(e)
	}
	install(badCert)
	if _, e := run("sh -c id"); e == nil {
		t.Fatal("missing cert gate bypasses server")
	}
	// A root-side allowlist change cannot silently broaden an already signed role version.
	policyPath := filepath.Join(bundle, "commands.json")
	originalPolicy, _ := os.ReadFile(policyPath)
	altered := strings.Replace(string(originalPolicy), rules[0].Exec[len(rules[0].Exec)-1], "altered-exec", 1)
	os.WriteFile(policyPath, []byte(altered), 0600)
	if _, e := run("platform"); e == nil {
		t.Fatal("policy digest mismatch bypass")
	}
	os.WriteFile(policyPath, originalPolicy, 0600)
	renewed, e := svc.Issue(actor, lease.ID, q.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	install(renewed.Certificate)
	if _, e := run(allowed); e != nil {
		t.Fatal("same-key renewal gate failed")
	}
	if _, e = svc.Close(actor, lease.ID, Completed, "complete"); e != nil {
		t.Fatal(e)
	}
	if _, e = svc.Issue(actor, lease.ID, q.PublicKey); e == nil {
		t.Fatal("completed lease renewed")
	}
	os.Remove(key + "-cert.pub")
	if _, e := run("platform"); e == nil {
		t.Fatal("raw key auth")
	}
	t.Log("PASS: actual certificate/principal/server forced-command gate; allowed literal operation; shell/chaining/altered-argv/wrapper/role/host/subsystem/PTY/forward/raw-key denials; renewal/close")
}
