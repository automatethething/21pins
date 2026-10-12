package dnsadmin

import (
	"github.com/petrichor/21pins-cli/internal/sshcommand"
	"os"
	"strings"
	"testing"
)

func TestWireGuardOnlyManifestAndRules(t *testing.T) {
	m := WireGuardManifest{Workspace: "local", Host: "wg-gateway", Interface: "wg0", Peer: key(1), Config: "/etc/wireguard/wg0.conf", AllowedIP: cidr}
	if !m.valid() {
		t.Fatal("fixed WG profile")
	}
	for _, change := range []func(*WireGuardManifest){func(m *WireGuardManifest) { m.Host = "dns-primary" }, func(m *WireGuardManifest) { m.Interface = "wg1" }, func(m *WireGuardManifest) { m.AllowedIP = "10.66.66.6/32" }, func(m *WireGuardManifest) { m.Config = "/etc/other" }, func(m *WireGuardManifest) { m.Peer = "invalid" }} {
		v := m
		change(&v)
		if v.valid() {
			t.Fatal("selector drift")
		}
	}
	h := strings.Repeat("a", 64)
	r, e := WireGuardRules(h)
	if e != nil || len(r) != 2 {
		t.Fatal("two exact operations")
	}
	policy := sshcommand.RolePolicy{User: "pins-wg-agent", Rules: r}
	for _, w := range [][]string{{"dns", "query"}, {"sudo", "sh"}, {"beryl", "enroll", "altered"}, {"wireguard", "handshake", "other"}} {
		if _, e = sshcommand.Authorize(policy, w); e == nil {
			t.Fatal("expanded scope")
		}
	}
	for _, v := range r {
		if v.Exec[3] != "wg-beryl" || v.Exec[5] != h {
			t.Fatal("namespace/digest")
		}
	}
	s, e := WireGuardSudoers(h)
	if e != nil || strings.Contains(s, "*") || !strings.Contains(s, "pins-wg-agent") {
		t.Fatal("sudo scope")
	}
	if _, e = RunWireGuard([]string{"peer-enroll", h, "extra"}); e == nil {
		t.Fatal("root argv")
	}
}

func TestBerylIdempotenceAndUnrelatedPersistentDrift(t *testing.T) {
	f := setup(t)
	if _, e := f.x.enroll(); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(f.x.m.Config)
	calls := len(f.calls)
	if _, e := f.x.enroll(); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(f.x.m.Config)
	if string(before) != string(after) {
		t.Fatal("idempotent persistence changed")
	}
	for _, c := range f.calls[calls:] {
		if strings.Contains(c, " set ") {
			t.Fatal("idempotent live write")
		}
	}
	f = setup(t)
	f.peers[key(3)] = f.peers[key(2)]
	if _, e := f.x.enroll(); e == nil {
		t.Fatal("unrelated persistent/live drift")
	}
}
