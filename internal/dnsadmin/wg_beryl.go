package dnsadmin

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/petrichor/21pins-cli/internal/sshcommand"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
)

const WireGuardManifestPath = "/etc/21pins/wg-beryl.json"
const wireGuardState = "/var/lib/21pins/wg-beryl"

var WireGuardOperations = []string{"peer-enroll", "peer-inspect"}

type WireGuardManifest struct {
	Workspace string `json:"workspace"`
	Host      string `json:"host"`
	Interface string `json:"interface"`
	Peer      string `json:"peer_public_key"`
	Config    string `json:"wireguard_config"`
	AllowedIP string `json:"allowed_ip"`
}

func (m WireGuardManifest) valid() bool {
	b, e := base64.StdEncoding.DecodeString(m.Peer)
	return e == nil && len(b) == 32 && base64.StdEncoding.EncodeToString(b) == m.Peer && m.Workspace == "local" && m.Host == "wg-gateway" && m.Interface == "wg0" && m.Config == "/etc/wireguard/wg0.conf" && m.AllowedIP == cidr
}
func WireGuardRules(hash string) ([]sshcommand.Rule, error) {
	b, e := hex.DecodeString(hash)
	if e != nil || len(b) != 32 || strings.ToLower(hash) != hash {
		return nil, Denied
	}
	words := [][]string{{"beryl", "enroll"}, {"beryl", "inspect"}}
	r := make([]sshcommand.Rule, 2)
	for i, op := range WireGuardOperations {
		r[i] = sshcommand.Rule{Command: words[i], Exec: []string{"/usr/bin/sudo", "-n", "/usr/local/bin/21pins", "wg-beryl", op, hash}}
	}
	return r, nil
}
func WireGuardSudoers(hash string) (string, error) {
	r, e := WireGuardRules(hash)
	if e != nil {
		return "", e
	}
	a := []string{}
	for _, v := range r {
		a = append(a, strings.Join(v.Exec[2:], " "))
	}
	return "Defaults:pins-wg-agent env_reset, !setenv, !requiretty, secure_path=/usr/sbin:/usr/bin\npins-wg-agent ALL=(root) NOPASSWD: NOSETENV: " + strings.Join(a, ", ") + "\n", nil
}
func RunWireGuard(args []string) (Result, error) {
	denied := Result{State: "denied"}
	if os.Geteuid() != 0 || len(args) != 2 {
		return denied, Denied
	}
	ok := false
	for _, v := range WireGuardOperations {
		ok = ok || args[0] == v
	}
	if !ok {
		return denied, Denied
	}
	b, e := trusted(WireGuardManifestPath, true)
	if e != nil || digest(b) != args[1] {
		return denied, Denied
	}
	var m WireGuardManifest
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || !m.valid() {
		return denied, Denied
	}
	var tail any
	if d.Decode(&tail) != io.EOF {
		return denied, Denied
	}
	s, e := os.Lstat(wireGuardState)
	if e != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm()&0077 != 0 || s.Sys().(*syscall.Stat_t).Uid != 0 {
		return denied, Denied
	}
	lock := wireGuardState + "/lock"
	if _, e = trusted(lock, true); e != nil {
		return denied, Denied
	}
	fd, e := syscall.Open(lock, syscall.O_RDWR|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return denied, Denied
	}
	defer syscall.Close(fd)
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return denied, Denied
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	x := engine{m: Manifest{Workspace: m.Workspace, Host: m.Host, Interface: m.Interface, Peer: m.Peer, Config: m.Config}, dir: wireGuardState, run: native, read: func(p string) ([]byte, error) { return trusted(p, true) }, now: time.Now}
	if args[0] == "peer-enroll" {
		return x.operation(args[0])
	}
	v, e := x.verify()
	if e != nil {
		return denied, e
	}
	r, e := x.operation("wg-handshake")
	r.Operation = args[0]
	r.PeerCount = v.PeerCount
	return r, e
}
