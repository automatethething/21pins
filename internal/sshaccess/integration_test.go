package sshaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/petrichor/21pins-cli/internal/store"
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

func nativeKey(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	cmd := exec.CommandContext(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", p)
	if cmd.Run() != nil {
		t.Fatal("synthetic key generation failed")
	}
	os.Chmod(p, 0600)
	os.Chmod(p+".pub", 0600)
	return p
}
func TestNativeSignerOptions(t *testing.T) {
	dir := t.TempDir()
	ca := nativeKey(t, dir, "ca")
	key := nativeKey(t, dir, "agent")
	b, e := os.ReadFile(key + ".pub")
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	n := NativeSigner{CA: CA{Mode: "dev", PublicKeyFile: ca + ".pub", SecretRef: ca}}
	r := SignRequest{PublicKey: strings.TrimSpace(string(b)), LeaseID: "synthetic", Serial: 42, Principal: "21pins:test:alpha:observe", KeyID: "21pins:synthetic:pi:task", ValidAfter: now.Add(-30 * time.Second), ValidBefore: now.Add(15 * time.Minute)}
	cert, e := n.Sign(r)
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, "cert.pub")
	os.WriteFile(p, []byte(cert), 0600)
	cmd := exec.Command("ssh-keygen", "-L", "-f", p)
	out, e := cmd.Output()
	if e != nil {
		t.Fatal("certificate inspection failed")
	}
	s := string(out)
	if !strings.Contains(s, "Serial: 42") || !strings.Contains(s, r.Principal) || strings.Contains(s, "permit-") {
		t.Fatal("certificate metadata/restrictions")
	}
	r.PermitPTY = true
	cert, e = n.Sign(r)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(p, []byte(cert), 0600)
	out, e = exec.Command("ssh-keygen", "-L", "-f", p).Output()
	if e != nil || !strings.Contains(string(out), "permit-pty") || strings.Contains(string(out), "permit-agent-forwarding") {
		t.Fatal("explicit PTY option")
	}
}

func TestIsolatedOpenSSH(t *testing.T) {
	if os.Getenv("PINS21_SSH_INTEGRATION") != "1" {
		t.Skip("set PINS21_SSH_INTEGRATION=1 for isolated loopback sshd")
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
	ca := nativeKey(t, dir, "ca")
	key := nativeKey(t, dir, "agent")
	hostkey := nativeKey(t, dir, "host")
	pub, _ := os.ReadFile(key + ".pub")
	config := Config{Workspace: "fixture", CA: CA{Mode: "dev", PublicKeyFile: ca + ".pub", SecretRef: ca}, CertTTL: "3s", RenewBefore: "1s", ClockSkew: "1s", Hosts: map[string]Host{"alpha": {Alias: "alpha", Roles: map[string]Role{"observe": {SSHUser: who.Username, DefaultLease: "30s", MaxLease: "1m", MaxCertTTL: "3s", Requesters: map[string]string{"pi": "preapproved"}}}}, "beta": {Alias: "beta", Roles: map[string]Role{"observe": {SSHUser: who.Username, DefaultLease: "30s", MaxLease: "1m", MaxCertTTL: "3s", Requesters: map[string]string{"pi": "preapproved"}}}}}}
	svc, e := New(filepath.Join(dir, "state"), config, NativeSigner{CA: config.CA})
	if e != nil {
		t.Fatal(e)
	}
	bundle := filepath.Join(dir, "bundle")
	if e = BootstrapBundle(config, "alpha", bundle); e != nil {
		t.Fatal(e)
	}
	principals := filepath.Join(bundle, "principals-"+who.Username)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	script := filepath.Join(dir, "command.sh")
	os.WriteFile(script, []byte("#!/bin/sh\ncase \"$SSH_ORIGINAL_COMMAND\" in\n 'echo synthetic'|\"'echo' 'synthetic'\") echo synthetic;;\n 'probe-agent') if test -z \"$SSH_AUTH_SOCK\"; then echo no-agent; else echo forwarded-agent; fi;;\n 'sleep 6') sleep 6; echo session-survived;;\n *) exit 1;;\nesac\n"), 0700)
	cfg := filepath.Join(dir, "sshd_config")
	text := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nAuthorizedKeysFile none\nTrustedUserCAKeys %s\nAuthorizedPrincipalsFile %s\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nPerSourcePenalties no\nPermitRootLogin no\nAllowUsers %s\nAllowAgentForwarding yes\nAllowTcpForwarding yes\nX11Forwarding yes\nPermitUserRC yes\nForceCommand /bin/sh %s\nLogLevel ERROR\n", port, hostkey, filepath.Join(dir, "sshd.pid"), filepath.Join(bundle, "21pins-ca.pub"), principals, who.Username, script)
	os.WriteFile(cfg, []byte(text), 0600)
	check := exec.Command(sshd, "-t", "-f", cfg)
	validation, err := check.CombinedOutput()
	if err != nil && strings.Contains(strings.ToLower(string(validation)), "bad configuration option: persourcepenalties") {
		text = strings.ReplaceAll(text, "PerSourcePenalties no\n", "")
		os.WriteFile(cfg, []byte(text), 0600)
		err = exec.Command(sshd, "-t", "-f", cfg).Run()
	}
	if err != nil {
		t.Fatal("isolated sshd configuration validation failed")
	}
	server := exec.Command(sshd, "-D", "-e", "-f", cfg)
	if e = server.Start(); e != nil {
		t.Fatal("isolated sshd start failed")
	}
	defer func() {
		if server.Process != nil {
			server.Process.Kill()
		}
		server.Wait()
	}()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ready := false
	for i := 0; i < 30; i++ {
		c, e := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if e == nil {
			c.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("isolated nonprivileged sshd unavailable")
	}
	hostpub, _ := os.ReadFile(hostkey + ".pub")
	known := filepath.Join(dir, "known_hosts")
	os.WriteFile(known, []byte("[127.0.0.1]:"+strconv.Itoa(port)+" "+strings.TrimSpace(string(hostpub))+"\n"), 0600)
	args := []string{"-F", "/dev/null", "-p", strconv.Itoa(port), "-l", who.Username, "-i", key, "-o", "CertificateFile=" + key + "-cert.pub", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + known, "-o", "BatchMode=yes", "-o", "ControlMaster=no", "-o", "ControlPersist=no", "-o", "ConnectTimeout=2"}
	run := func(extra []string, command string) (string, error) {
		ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		base := append([]string{}, args...)
		for _, option := range extra {
			if strings.HasPrefix(option, "IdentityAgent=") {
				for i := 0; i < len(base)-1; i++ {
					if base[i] == "-o" && base[i+1] == "IdentityAgent=none" {
						base = append(base[:i], base[i+2:]...)
						break
					}
				}
			}
		}
		a := append(base, extra...)
		a = append(a, "127.0.0.1", command)
		cmd := exec.CommandContext(ctx, "ssh", a...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		b, e := cmd.Output()
		if e != nil && len(extra) > 0 {
			diagnostic := strings.ToLower(stderr.String())
			exitCode := -1
			if exit, ok := e.(*exec.ExitError); ok {
				exitCode = exit.ExitCode()
			}
			e = fmt.Errorf("synthetic SSH failure exit=%d stderr_bytes=%d permission=%t agent=%t forwarding=%t badconfig=%t", exitCode, len(diagnostic), strings.Contains(diagnostic, "permission denied"), strings.Contains(diagnostic, "agent"), strings.Contains(diagnostic, "forward"), strings.Contains(diagnostic, "bad configuration") || strings.Contains(diagnostic, "command-line"))
		}
		return string(b), e
	}
	actor := Actor{ID: "synthetic-actor", Name: "pi"}
	q := OpenRequest{HostID: "alpha", RoleID: "observe", AgentClass: "pi", ObjectiveID: "task", Purpose: "synthetic smoke", PublicKey: strings.TrimSpace(string(pub))}
	lease, e := svc.Open(actor, q)
	if e != nil {
		t.Fatal(e)
	}
	issue := func(id string) {
		t.Helper()
		r, e := svc.Issue(actor, id, q.PublicKey)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(key+"-cert.pub", []byte(r.Certificate+"\n"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	issue(lease.ID)
	if out, e := run(nil, "echo synthetic"); e != nil || strings.TrimSpace(out) != "synthetic" {
		t.Fatal("correct host/role SSH failed")
	}
	issue(lease.ID)
	now := time.Now().UTC().Truncate(time.Second)
	wrongCert, e := (NativeSigner{CA: config.CA}).Sign(SignRequest{PublicKey: q.PublicKey, Serial: 999, Principal: "21pins:fixture:beta:observe", KeyID: "synthetic-wrong-host", ValidAfter: now.Add(-time.Second), ValidBefore: now.Add(3 * time.Second)})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(key+"-cert.pub", []byte(wrongCert+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = run(nil, "echo synthetic"); e == nil {
		t.Fatal("wrong host principal accepted")
	}
	issue(lease.ID)
	originalPrincipals, e := os.ReadFile(principals)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(principals, []byte("21pins:fixture:alpha:deploy\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = run(nil, "echo synthetic"); e == nil {
		t.Fatal("wrong role principal accepted")
	}
	if e = os.WriteFile(principals, originalPrincipals, 0600); e != nil {
		t.Fatal(e)
	}
	wrongargs := append([]string{}, args...)
	for i := range wrongargs {
		if wrongargs[i] == "-l" {
			wrongargs[i+1] = "synthetic-no-such-user"
		}
	}
	ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
	cmd := exec.CommandContext(ctx, "ssh", append(wrongargs, "127.0.0.1", "echo synthetic")...)
	if cmd.Run() == nil {
		t.Fatal("wrong user accepted")
	}
	c()
	issue(lease.ID)
	if _, e = run([]string{"-o", "ExitOnForwardFailure=yes", "-R", "0:127.0.0.1:1"}, "echo synthetic"); e == nil {
		t.Fatal("certificate permitted TCP forwarding")
	}
	socketDir, e := os.MkdirTemp("", "p21agent-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(socketDir)
	agentSocket := filepath.Join(socketDir, "agent.sock")
	agent := exec.Command("ssh-agent", "-D", "-a", agentSocket)
	if e = agent.Start(); e != nil {
		t.Fatal("synthetic agent start")
	}
	defer func() { agent.Process.Kill(); agent.Wait() }()
	for i := 0; i < 30; i++ {
		if _, e = os.Stat(agentSocket); e == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, e = os.Stat(agentSocket); e != nil {
		t.Fatal("synthetic agent socket unavailable")
	}
	issue(lease.ID)
	if out, e := run([]string{"-A", "-o", "IdentityAgent=" + agentSocket}, "probe-agent"); e != nil || strings.TrimSpace(out) != "no-agent" {
		t.Fatalf("agent forwarding probe: no_agent=%t forwarded=%t error=%v", strings.TrimSpace(out) == "no-agent", strings.TrimSpace(out) == "forwarded-agent", e)
	}
	issue(lease.ID)
	// An already-authenticated connection is intentionally NOT killed by expiry.
	session := exec.Command("ssh", append(append([]string{}, args...), "127.0.0.1", "sleep 6")...)
	if e = session.Start(); e != nil {
		t.Fatal(e)
	}
	time.Sleep(1500 * time.Millisecond)
	if _, e = svc.Close(actor, lease.ID, Completed, "complete"); e != nil {
		t.Fatal(e)
	}
	if _, e = svc.Issue(actor, lease.ID, q.PublicKey); e == nil {
		t.Fatal("closed lease renewed")
	}
	if e = session.Wait(); e != nil {
		t.Fatal("session-survival check failed")
	}
	if _, e = run(nil, "echo synthetic"); e == nil {
		t.Fatal("expired cert reconnected")
	}
	// Full CLI and real Node harness use a distinct ephemeral key and CA init/bootstrap.
	repo, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(dir, "21pins")
	build := exec.Command("go", "build", "-o", binary, "./cmd/21pins")
	build.Dir = repo
	if build.Run() != nil {
		t.Fatal("CLI fixture build")
	}
	statePath := filepath.Join(dir, "cli-state.json")
	st, e := store.New(statePath)
	if e != nil {
		t.Fatal(e)
	}
	use, e := st.CreateToken("pi", []string{"ssh:use"})
	if e != nil {
		t.Fatal(e)
	}
	admin, e := st.CreateToken("owner", []string{"ssh:approve"})
	if e != nil {
		t.Fatal(e)
	}
	tokenFile := filepath.Join(dir, "client-token")
	os.WriteFile(tokenFile, []byte(admin), 0600)
	cliDir := filepath.Join(dir, "cli-control")
	clientDir := filepath.Join(dir, "client-runtime")
	aliasConfig := filepath.Join(dir, "client-ssh-config")
	os.WriteFile(aliasConfig, []byte(fmt.Sprintf("Host alpha\n HostName 127.0.0.1\n Port %d\n UserKnownHostsFile %s\n", port, known)), 0600)
	env := append(os.Environ(), "PINS21_STATE_PATH="+statePath, "PINS21_SSH_DIR="+cliDir, "PINS21_SSH_RUNTIME_DIR="+clientDir, "PINS21_SSH_TOKEN_FILE="+tokenFile, "PINS21_SSH_CONFIG_FILE="+aliasConfig)
	cli := func(args ...string) {
		t.Helper()
		c := exec.Command(binary, args...)
		c.Env = env
		if c.Run() != nil {
			t.Fatal("CLI bootstrap operation failed")
		}
	}
	cli("ssh", "ca", "init", "--dev")
	cli("ssh", "host", "add", "alpha", "--role", "observe", "--user", who.Username, "--requester", "pi", "--max-lease", "1m", "--default-lease", "30s", "--max-cert-ttl", "3s", "--preapproved")
	cliBundle := filepath.Join(dir, "cli-bundle")
	cli("ssh", "host", "bootstrap", "alpha", "--out", cliBundle, "--dry-run")
	caBundle, _ := os.ReadFile(filepath.Join(cliBundle, "21pins-ca.pub"))
	principalsBundle, _ := os.ReadFile(filepath.Join(cliBundle, "principals-"+who.Username))
	os.WriteFile(filepath.Join(bundle, "21pins-ca.pub"), caBundle, 0600)
	os.WriteFile(principals, principalsBundle, 0600)
	os.WriteFile(tokenFile, []byte(use), 0600)
	apiListener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	apiPort := apiListener.Addr().(*net.TCPAddr).Port
	apiListener.Close()
	gateway := exec.Command(binary, "serve", "--host", "127.0.0.1", "--port", strconv.Itoa(apiPort), "--ssh-dir", cliDir)
	gateway.Env = env
	if gateway.Start() != nil {
		t.Fatal("synthetic control API start")
	}
	defer func() { gateway.Process.Kill(); gateway.Wait() }()
	apiAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(apiPort))
	apiReady := false
	for i := 0; i < 50; i++ {
		conn, e := net.DialTimeout("tcp", apiAddress, 50*time.Millisecond)
		if e == nil {
			conn.Close()
			apiReady = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !apiReady {
		t.Fatal("synthetic control API unavailable")
	}
	env = append(env, "PINS21_SSH_API_URL=http://"+apiAddress)
	// The requester must not load issuer/provider files, even on the same machine.
	for i, v := range env {
		if strings.HasPrefix(v, "PINS21_STATE_PATH=") {
			env[i] = "PINS21_STATE_PATH=" + filepath.Join(dir, "must-not-read-provider-state", "state.json")
		}
		if strings.HasPrefix(v, "PINS21_SSH_DIR=") {
			env[i] = "PINS21_SSH_DIR=" + filepath.Join(dir, "must-not-read-issuer")
		}
	}
	moduleJSON, _ := json.Marshal(filepath.Join(repo, "npm/lib/ssh-harness.mjs"))
	binJSON, _ := json.Marshal(binary)
	runtimeJSON, _ := json.Marshal(clientDir)
	program := fmt.Sprintf(`import assert from 'node:assert/strict';import fs from 'node:fs';import {SSHObjectiveHarness} from %s;const h=new SSHObjectiveHarness({binary:%s});const q={type:'ssh',host:'alpha',role:'observe',objective:'cli-task',purpose:'synthetic CLI smoke'};const lease=await h.ensureCapability(q);const p=%s+'/'+lease.leaseId+'/id_ed25519';assert.equal(fs.statSync(p).mode&0o777,0o600);const publicKey=fs.readFileSync(p+'.pub');assert.equal((await h.exec(lease,['echo','synthetic'])).exitCode,0);await new Promise(r=>setTimeout(r,2200));assert.equal((await h.exec(lease,['echo','synthetic'])).exitCode,0);assert.deepEqual(fs.readFileSync(p+'.pub'),publicKey);await h.onObjectiveStatus('cli-task','COMPLETE');assert.equal(fs.existsSync(p),false);console.log('harness-lifecycle-pass');`, string(moduleJSON), string(binJSON), string(runtimeJSON))
	ctx2, c2 := context.WithTimeout(context.Background(), 25*time.Second)
	defer c2()
	node := exec.CommandContext(ctx2, "node", "--input-type=module", "-e", program)
	node.Env = env
	if output, e := node.Output(); e != nil || !strings.Contains(string(output), "harness-lifecycle-pass") {
		t.Fatal("real CLI/harness renewal or completion cleanup failed")
	}
	if _, e = os.Stat(filepath.Join(dir, "must-not-read-provider-state")); !os.IsNotExist(e) {
		t.Fatal("requester touched issuer/provider state")
	}
	t.Log("PASS: native certificates, CA/host bootstrap, host/role/user rejection, forwarding denied, renewal, close, expiry, surviving established session, real API-only CLI/Node objective lifecycle and key deletion")
}
