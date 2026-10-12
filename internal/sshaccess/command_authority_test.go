package sshaccess

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Observe names login scope, not a command whitelist. Guard against false RBAC claims.
func TestObserveNativeCertificateHasNoCommandRestriction(t *testing.T) {
	if _, e := exec.LookPath("ssh-keygen"); e != nil {
		t.Skip("native OpenSSH required")
	}
	dir := t.TempDir()
	ca := nativeKey(t, dir, "ca")
	key := nativeKey(t, dir, "client")
	public, e := os.ReadFile(key + ".pub")
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	request := SignRequest{PublicKey: strings.TrimSpace(string(public)), LeaseID: strings.Repeat("a", 32), Serial: 1, Principal: "21pins:local:finland-staging-221:observe", KeyID: "21pins:synthetic:pi:observe-check", ValidAfter: now.Add(-30 * time.Second), ValidBefore: now.Add(15 * time.Minute)}
	signer := NativeSigner{CA: CA{Mode: "dev", PublicKeyFile: ca + ".pub", SecretRef: ca}}
	cert, e := signer.Sign(request)
	if e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(dir, "certificate.pub")
	if os.WriteFile(file, []byte(cert), 0600) != nil {
		t.Fatal("certificate fixture write")
	}
	result, e := exec.Command("ssh-keygen", "-L", "-f", file).Output()
	if e != nil {
		t.Fatal("native certificate inspection")
	}
	text := string(result)
	if !strings.Contains(text, request.Principal) || !strings.Contains(text, "Critical Options: (none)") || !strings.Contains(text, "Extensions: (none)") || strings.Contains(text, "force-command") {
		t.Fatal("observe certificate authority changed")
	}
	t.Log("native inspection: exact observe principal, critical options none, extensions none; no command restriction")
}
