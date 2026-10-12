package sshaccess

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProductionNativeAgentSigner(t *testing.T) {
	if _, e := exec.LookPath("ssh-agent"); e != nil {
		t.Skip("native ssh-agent unavailable")
	}
	dir := t.TempDir()
	ca := nativeKey(t, dir, "ca")
	caPublic, _ := os.ReadFile(ca + ".pub")
	os.WriteFile(ca+".pub", []byte(strings.TrimSpace(string(caPublic))+" synthetic-comment\n"), 0600)
	key := nativeKey(t, dir, "client")
	socketDir, e := os.MkdirTemp("", "p21ca-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(socketDir)
	socket := filepath.Join(socketDir, "signer.sock")
	agent := exec.Command("ssh-agent", "-D", "-a", socket)
	if agent.Start() != nil {
		t.Fatal("synthetic signing agent")
	}
	defer func() { agent.Process.Kill(); agent.Wait() }()
	for i := 0; i < 50; i++ {
		if _, e := os.Stat(socket); e == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	add := exec.CommandContext(ctx, "ssh-add", ca)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "SSH_AUTH_SOCK=") {
			add.Env = append(add.Env, entry)
		}
	}
	add.Env = append(add.Env, "SSH_AUTH_SOCK="+socket)
	if add.Run() != nil {
		t.Fatal("synthetic CA load")
	}
	pub, _ := os.ReadFile(key + ".pub")
	now := time.Now().UTC().Truncate(time.Second)
	r := SignRequest{PublicKey: strings.TrimSpace(string(pub)), Serial: 1, Principal: "21pins:test:alpha:observe", KeyID: "synthetic", ValidAfter: now.Add(-time.Second), ValidBefore: now.Add(time.Minute)}
	n := NativeSigner{CA: CA{Mode: "agent", PublicKeyFile: ca + ".pub", AgentSocket: socket}}
	if _, e := n.Sign(r); e != nil {
		t.Fatal(e)
	}
	n.CA.SecretRef = ca
	if _, e := n.Sign(r); e == nil {
		t.Fatal("production mode read private file")
	}
}
