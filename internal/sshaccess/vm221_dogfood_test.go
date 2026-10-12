package sshaccess

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Explicit approved target test. SSH client is the existing reachable management host,
// not a proxy: its native SSH connects directly to the VM. No CA private data leaves issuer.
func TestApprovedVM221Dogfood(t *testing.T) {
	if os.Getenv("PINS21_VM221_DOGFOOD") != "1" {
		t.Skip("explicit approved VM 221 dogfood")
	}
	home, _ := os.UserHomeDir()
	root := filepath.Join(home, "Library/Application Support/21pins/ssh")
	svc, e := Load(root)
	if e != nil {
		t.Fatal("real agent issuer unavailable")
	}
	var target struct {
		Address    string `json:"address"`
		HostPublic string `json:"host_public"`
	}
	b, e := ReadPrivate(filepath.Join(root, "target-connection.json"))
	if e != nil || json.Unmarshal(b, &target) != nil {
		t.Fatal("target reference")
	}
	remote := func(code string) map[string]json.RawMessage {
		t.Helper()
		ctx, c := context.WithTimeout(context.Background(), 35*time.Second)
		defer c()
		cmd := exec.CommandContext(ctx, "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no", "-o", "ConnectTimeout=10", "fipi", "python3 -")
		cmd.Stdin = strings.NewReader(code)
		out, e := cmd.Output()
		if e != nil {
			t.Fatal("bounded management client operation failed")
		}
		var v map[string]json.RawMessage
		if json.Unmarshal(out, &v) != nil {
			t.Fatal("filtered client result")
		}
		return v
	}
	literal := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	init := remote("import tempfile,subprocess,pathlib,json,os\np=pathlib.Path(tempfile.mkdtemp(prefix='21pins-vm221-',dir='/tmp'));p.chmod(0o700)\nsubprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(p/'key')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\nprint(json.dumps({'dir':str(p),'public':' '.join((p/'key.pub').read_text().split()[:2])}))\n")
	var dir, pub string
	json.Unmarshal(init["dir"], &dir)
	json.Unmarshal(init["public"], &pub)
	if !strings.HasPrefix(dir, "/tmp/21pins-vm221-") {
		t.Fatal("client directory scope")
	}
	defer remote("import pathlib,shutil,json\np=pathlib.Path(" + literal(dir) + ");assert p.parent==pathlib.Path('/tmp') and p.name.startswith('21pins-vm221-');shutil.rmtree(p);print(json.dumps({'cleaned':not p.exists()}))\n")
	actor := Actor{ID: "vm221-dogfood", Name: "pi"}
	owner := Actor{ID: "vm221-owner", Name: "owner", CanApprove: true}
	lease, e := svc.Open(actor, OpenRequest{HostID: "finland-staging-221", RoleID: "observe", AgentClass: "pi", ObjectiveID: "vm221-approved-observe-dogfood", Purpose: "owner-approved installation verification", PublicKey: pub, MaxDuration: "5m"})
	if e != nil {
		t.Fatal("open real lease")
	}
	if _, e = svc.Approve(owner, lease.ID); e != nil {
		t.Fatal("approve exact dogfood lease")
	}
	closed := false
	defer func() {
		if !closed {
			svc.Close(actor, lease.ID, Cancelled, "cancelled")
		}
	}()
	issue, e := svc.Issue(actor, lease.ID, pub)
	if e != nil {
		t.Fatal("dedicated native-agent signing")
	}
	install := func(cert string) {
		t.Helper()
		remote("import pathlib,json,os\np=pathlib.Path(" + literal(dir) + ");(p/'cert.pub').write_text(" + literal(cert) + ");(p/'cert.pub').chmod(0o600);(p/'known_hosts').write_text(" + literal(target.Address+" "+target.HostPublic+"\n") + ");(p/'known_hosts').chmod(0o600);print(json.dumps({'installed':True}))\n")
	}
	run := func(command string, extra []string) int {
		t.Helper()
		v := remote("import subprocess,pathlib,json\np=pathlib.Path(" + literal(dir) + ")\na=['ssh','-F','/dev/null','-o','StrictHostKeyChecking=yes','-o','BatchMode=yes','-o','IdentityAgent=none','-o','IdentitiesOnly=yes','-o','ControlMaster=no','-o','ControlPath=none','-o','ConnectTimeout=5','-o','UserKnownHostsFile='+str(p/'known_hosts'),'-i',str(p/'key'),'-o','CertificateFile='+str(p/'cert.pub'),'-l','pins-agent']\na+=" + literal(extra) + "\na+=[" + literal(target.Address) + "," + literal(command) + "]\nr=subprocess.run(a,capture_output=True,timeout=12);print(json.dumps({'exit':r.returncode,'output_present':bool(r.stdout)}))\n")
		var code int
		json.Unmarshal(v["exit"], &code)
		return code
	}
	install(issue.Certificate)
	for _, op := range []string{"platform", "status", "identity"} {
		if run(op, []string{}) != 0 {
			t.Fatal("fresh signed allowed operation denied", op)
		}
	}
	for _, op := range []string{"sh -c id", "platform;id", "platform -a", "/usr/bin/uname -s", "sftp", "/usr/local/bin/21pins ssh gate"} {
		if run(op, []string{}) == 0 {
			t.Fatal("command escape accepted")
		}
	}
	if run("sftp", []string{"-s"}) == 0 {
		t.Fatal("subsystem")
	}
	if run("platform", []string{"-tt"}) == 0 {
		t.Fatal("PTY")
	}
	if run("platform", []string{"-o", "ExitOnForwardFailure=yes", "-R", "0:127.0.0.1:1"}) == 0 {
		t.Fatal("forwarding")
	}
	renewed, e := svc.Issue(actor, lease.ID, pub)
	if e != nil || renewed.Lease.PublicKeyFingerprint != lease.PublicKeyFingerprint {
		t.Fatal("same key renewal")
	}
	install(renewed.Certificate)
	if run("platform", []string{}) != 0 {
		t.Fatal("renewed target auth")
	}
	force, e := lease.EffectivePolicy.CommandAuthority.ForcedCommand(lease.Workspace, lease.HostID, lease.RoleID, lease.SSHUser)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	signer := NativeSigner{CA: svc.Config.CA}
	reserve := func() uint64 {
		var serial uint64
		if svc.transaction(func(d *diskState) error { d.NextSerial++; serial = d.NextSerial; return nil }) != nil {
			t.Fatal("negative serial reservation")
		}
		return serial
	}
	for _, principal := range []string{"21pins:local:other-host:observe", "21pins:local:finland-staging-221:dns-admin"} {
		cert, e := signer.Sign(SignRequest{PublicKey: pub, Serial: reserve(), Principal: principal, KeyID: "negative-scope", ForceCommand: force, ValidAfter: now.Add(-time.Second), ValidBefore: now.Add(time.Minute)})
		if e != nil {
			t.Fatal("negative signing")
		}
		install(cert)
		if run("platform", []string{}) == 0 {
			t.Fatal("principal replay")
		}
	}
	cert, e := signer.Sign(SignRequest{PublicKey: pub, Serial: reserve(), Principal: lease.Principal, KeyID: "negative-force", ForceCommand: "/bin/sh", ValidAfter: now.Add(-time.Second), ValidBefore: now.Add(time.Minute)})
	if e != nil {
		t.Fatal("force negative signing")
	}
	install(cert)
	if run("platform", []string{}) == 0 {
		t.Fatal("force mismatch")
	}
	cert, e = signer.Sign(SignRequest{PublicKey: pub, Serial: reserve(), Principal: lease.Principal, KeyID: "expired-reconnect", ForceCommand: force, ValidAfter: now.Add(-time.Minute), ValidBefore: now.Add(-time.Second)})
	if e != nil {
		t.Fatal("expired signing")
	}
	install(cert)
	if run("platform", []string{}) == 0 {
		t.Fatal("expired target reconnect")
	}
	install(renewed.Certificate)
	if _, e = svc.Close(actor, lease.ID, Completed, "complete"); e != nil {
		t.Fatal("terminal close")
	}
	closed = true
	if _, e = svc.Issue(actor, lease.ID, pub); e == nil {
		t.Fatal("terminal renewal")
	}
	remote("import pathlib,json\n(pathlib.Path(" + literal(dir) + ")/'cert.pub').unlink();print(json.dumps({'removed':True}))\n")
	if run("platform", []string{}) == 0 {
		t.Fatal("raw key login")
	}
	t.Log("PASS: real agent CA/approved lease; fresh direct management-client to VM221 SSH; all 3 operations; escape/subsystem/PTY/forward/host/role/force/expiry/raw-key negatives; same-key renewal and terminal issuance denial; ephemeral client cleanup")
}
