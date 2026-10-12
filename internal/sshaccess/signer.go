package sshaccess

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type NativeSigner struct{ CA CA }

func (n NativeSigner) Sign(r SignRequest) (string, error) {
	if _, e := PublicFingerprint(r.PublicKey); e != nil {
		return "", e
	}
	if n.CA.Mode != "dev" && n.CA.Mode != "agent" {
		return "", errors.New("explicit dev or native-agent CA required")
	}
	public, e := os.ReadFile(n.CA.PublicKeyFile)
	if e != nil {
		return "", errors.New("CA public key unavailable")
	}
	canonical, e := CAPublic(string(public))
	if e != nil {
		return "", e
	}
	fingerprint, e := PublicFingerprint(canonical)
	if e != nil || (n.CA.Fingerprint != "" && n.CA.Fingerprint != fingerprint) {
		return "", errors.New("invalid or changed CA public key")
	}
	dir, e := os.MkdirTemp("", "21pins-sign-")
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "lease.pub")
	if e = os.WriteFile(p, []byte(r.PublicKey+"\n"), 0600); e != nil {
		return "", e
	}
	signingKey := n.CA.PublicKeyFile
	args := []string{}
	if n.CA.Mode == "dev" {
		f, e := privateOpen(n.CA.SecretRef, os.O_RDONLY)
		if e != nil {
			return "", errors.New("explicit development CA must be a private regular file")
		}
		f.Close()
		signingKey = n.CA.SecretRef
	} else {
		if n.CA.SecretRef != "" {
			return "", errors.New("native-agent mode accepts no private-key reference")
		}
		args = append(args, "-U")
	}
	args = append(args, "-s", signingKey, "-I", r.KeyID, "-z", fmt.Sprint(r.Serial), "-n", r.Principal, "-V", r.ValidAfter.UTC().Format("20060102150405")+":"+r.ValidBefore.UTC().Format("20060102150405"), "-O", "clear")
	if r.PermitPTY {
		args = append(args, "-O", "permit-pty")
	}
	if r.PermitPortForwarding {
		args = append(args, "-O", "permit-port-forwarding")
	}
	if r.PermitAgentForwarding {
		args = append(args, "-O", "permit-agent-forwarding")
	}
	if r.PermitX11 {
		args = append(args, "-O", "permit-X11-forwarding")
	}
	args = append(args, p)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh-keygen", args...)
	cmd.Env = []string{}
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "SSH_AUTH_SOCK=") && !strings.HasPrefix(v, "SSH_AGENT_PID=") && !strings.HasPrefix(v, "TZ=") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	cmd.Env = append(cmd.Env, "TZ=UTC")
	if n.CA.Mode == "agent" {
		if n.CA.AgentSocket == "" {
			return "", errors.New("dedicated CA agent socket required")
		}
		cmd.Env = append(cmd.Env, "SSH_AUTH_SOCK="+n.CA.AgentSocket)
	}
	if cmd.Run() != nil {
		return "", errors.New("native SSH signing failed")
	}
	b, e := os.ReadFile(filepath.Join(dir, "lease-cert.pub"))
	if e != nil || !strings.HasPrefix(string(b), "ssh-ed25519-cert-v01@openssh.com ") {
		return "", errors.New("native SSH certificate unavailable")
	}
	certificate := strings.TrimSpace(string(b))
	if verifyCertificate(certificate, canonical, r) != nil {
		return "", errors.New("native certificate verification failed")
	}
	return certificate, nil
}

// BootstrapBundle never connects to a target or changes its trust.
func BootstrapBundle(c Config, hostID, out string) error {
	h, ok := c.Hosts[hostID]
	if !ok {
		return ErrDenied
	}
	pub, e := os.ReadFile(c.CA.PublicKeyFile)
	if e != nil {
		return errors.New("CA public key unavailable")
	}
	key, e := CAPublic(string(pub))
	if e != nil {
		return e
	}
	if e = PrivateDir(out); e != nil {
		return e
	}
	if len(h.Roles) == 0 {
		return errors.New("no host roles")
	}
	files := map[string][]byte{"21pins-ca.pub": []byte(key + "\n"), "sshd_config.fragment": []byte("# Review paths/accounts; do not overwrite an existing TrustedUserCAKeys directive.\nTrustedUserCAKeys /etc/ssh/21pins/ca.pub\nAuthorizedPrincipalsFile /etc/ssh/21pins/principals/%u\n")}
	accounts := map[string]string{}
	for role, r := range h.Roles {
		principal := "21pins:" + c.Workspace + ":" + hostID + ":" + role
		if prior, ok := accounts[r.SSHUser]; ok {
			accounts[r.SSHUser] = prior + principal + "\n"
		} else {
			accounts[r.SSHUser] = principal + "\n"
		}
	}
	for user, v := range accounts {
		files["principals-"+user] = []byte(v)
	}
	for name, data := range files {
		p := filepath.Join(out, name)
		if _, e = os.Lstat(p); e == nil {
			return errors.New("bootstrap output exists; review before replacing")
		}
		if e = AtomicPrivate(p, data); e != nil {
			return e
		}
	}
	return nil
}
