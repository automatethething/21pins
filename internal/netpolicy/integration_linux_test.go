//go:build linux && netpolicy_integration

package netpolicy

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/petrichor/21pins-cli/internal/policy"
)

func requireIsolatedNetworkRunner(t *testing.T) {
	t.Helper()
	if os.Getenv("PINS21_ISOLATED_NETWORK_TEST") != "1" {
		t.Skip("requires explicitly isolated disposable Linux runner with private mount namespace and writable proc sys")
	}
}

func TestLinuxWGDNSE2E(t *testing.T) {
	requireIsolatedNetworkRunner(t)
	if os.Geteuid() != 0 {
		t.Skip("requires authorized isolated Linux runner with namespace capabilities")
	}
	for _, tool := range []string{"ip", "wg", "nft"} {
		if _, e := exec.LookPath(tool); e != nil {
			t.Skip("missing isolated-runner prerequisite")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	run := func(namespace, tool string, args ...string) []byte {
		t.Helper()
		command := tool
		if namespace != "" {
			args = append([]string{"netns", "exec", namespace, tool}, args...)
			command = "ip"
		}
		cctx, done := context.WithTimeout(ctx, 5*time.Second)
		defer done()
		cmd := exec.CommandContext(cctx, command, args...)
		data, e := cmd.Output()
		if e != nil {
			t.Fatalf("isolated fixture command failed (%s)", tool)
		}
		return data
	}
	prefix := "np" + strings.TrimPrefix(policy.NewID("x"), "x_")[:8]
	gateway, trusted, guest, server := prefix+"g", prefix+"t", prefix+"u", prefix+"s"
	namespaces := []string{gateway, trusted, guest, server}
	for _, name := range namespaces {
		run("", "ip", "netns", "add", name)
		run("", "ip", "-n", name, "link", "set", "lo", "up")
	}
	t.Cleanup(func() {
		for _, name := range namespaces {
			cctx, done := context.WithTimeout(context.Background(), 3*time.Second)
			e := exec.CommandContext(cctx, "ip", "netns", "del", name).Run()
			done()
			if e != nil {
				t.Error("fixture namespace cleanup failed")
			}
			if _, e = namespaceIdentity(name); e == nil {
				t.Error("fixture namespace retained")
			}
		}
	})
	ip := func(a, b, c, d byte) string { return netip.AddrFrom4([4]byte{a, b, c, d}).String() }
	trGW, trIP := ip(192, 0, 2, 1), ip(192, 0, 2, 2)
	guGW, guIP := ip(198, 51, 100, 1), ip(198, 51, 100, 2)
	underGW, underServer := ip(203, 0, 113, 1), ip(203, 0, 113, 2)
	privateGW, privateServer := ip(198, 18, 0, 1), ip(198, 18, 0, 53)
	connect := func(a, b, an, bn, aa, ba string) {
		run("", "ip", "-n", a, "link", "add", an, "type", "veth", "peer", "name", bn, "netns", b)
		run("", "ip", "-n", a, "addr", "add", aa+"/24", "dev", an)
		run("", "ip", "-n", b, "addr", "add", ba+"/24", "dev", bn)
		run("", "ip", "-n", a, "link", "set", an, "up")
		run("", "ip", "-n", b, "link", "set", bn, "up")
	}
	connect(gateway, trusted, "gtr", "eth0", trGW, trIP)
	connect(gateway, guest, "ggu", "eth0", guGW, guIP)
	connect(gateway, server, "gup", "eth0", underGW, underServer)
	for _, pair := range [][2]string{{trusted, trGW}, {guest, guGW}, {server, underGW}} {
		run("", "ip", "-n", pair[0], "route", "add", "default", "via", pair[1])
	}
	// Writable proc sys is supplied by the isolated runner; this test never changes mount state.
	gwContext, _ := namespaceIdentity(gateway)
	if e := withinNamespace(ctx, Binding{Namespace: gateway, Context: gwContext}, func() error { return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0600) }); e != nil {
		t.Fatal("isolated namespace forwarding unavailable")
	}
	keyDir := filepath.Join(t.TempDir(), "keys")
	if os.Mkdir(keyDir, 0700) != nil {
		t.Fatal("key fixture directory")
	}
	key := func(name string) (string, string) {
		private := bytes.TrimSpace(run("", "wg", "genkey"))
		path := filepath.Join(keyDir, name)
		if os.WriteFile(path, private, 0600) != nil {
			t.Fatal("synthetic key fixture")
		}
		cmd := exec.CommandContext(ctx, "wg", "pubkey")
		cmd.Stdin = bytes.NewReader(private)
		public, e := cmd.Output()
		if e != nil {
			t.Fatal("synthetic public identity")
		}
		return path, strings.TrimSpace(string(public))
	}
	gwKey, gwPublic := key("gateway")
	serverKey, serverPublic := key("server")
	for _, name := range []string{gateway, server} {
		run("", "ip", "-n", name, "link", "add", "wg0", "type", "wireguard")
	}
	run(gateway, "wg", "set", "wg0", "private-key", gwKey, "listen-port", "51821", "peer", serverPublic, "allowed-ips", privateServer+"/32", "endpoint", net.JoinHostPort(underServer, "51822"), "persistent-keepalive", "1")
	run(server, "wg", "set", "wg0", "private-key", serverKey, "listen-port", "51822", "peer", gwPublic, "allowed-ips", privateGW+"/32", "endpoint", net.JoinHostPort(underGW, "51821"), "persistent-keepalive", "1")
	run("", "ip", "-n", gateway, "addr", "add", privateGW+"/24", "dev", "wg0")
	run("", "ip", "-n", server, "addr", "add", privateServer+"/24", "dev", "wg0")
	for _, name := range []string{gateway, server} {
		run("", "ip", "-n", name, "link", "set", "wg0", "up")
	}
	run(gateway, "nft", "add", "table", "inet", "np")
	run(gateway, "nft", "add", "chain", "inet", "np", "guard", "{", "type", "filter", "hook", "forward", "priority", "0", ";", "policy", "accept", ";", "}")
	addGuard := func() {
		run(gateway, "nft", "add", "rule", "inet", "np", "guard", "ip", "saddr", trIP, "ip", "daddr", privateServer, "oifname", "!=", "wg0", "drop")
	}
	run(gateway, "nft", "add", "rule", "inet", "np", "guard", "ip", "saddr", guIP, "ip", "daddr", privateServer, "drop")
	addGuard()
	run(gateway, "nft", "add", "table", "ip", "npnat")
	run(gateway, "nft", "add", "chain", "ip", "npnat", "post", "{", "type", "nat", "hook", "postrouting", "priority", "100", ";", "policy", "accept", ";", "}")
	run(gateway, "nft", "add", "rule", "ip", "npnat", "post", "ip", "daddr", privateServer, "oifname", "wg0", "snat", "to", privateGW)
	contexts := map[string]string{}
	for _, name := range namespaces {
		contexts[name], _ = namespaceIdentity(name)
	}
	stopDNS, stopAddress := startFixtureDNS(t, ctx, Binding{Namespace: server, Context: contexts[server]}, []string{privateServer, underServer})
	defer stopDNS()
	objects := []Object{
		{Kind: Gateway, Alias: "router", Binding: Binding{Namespace: gateway, Context: contexts[gateway], Interface: "gtr", Address: trGW, Target: privateServer, NftFamily: "inet", NftTable: "np", NftChain: "guard"}},
		{Kind: Network, Alias: "trusted", Binding: Binding{Namespace: trusted, Context: contexts[trusted], Interface: "eth0", Ingress: "gtr", Address: trIP, Gateway: Ref{ID: "router"}}},
		{Kind: Network, Alias: "guest", Binding: Binding{Namespace: guest, Context: contexts[guest], Interface: "eth0", Ingress: "ggu", Address: guIP, Gateway: Ref{ID: "router"}}},
		{Kind: VPN, Alias: "tunnel", Binding: Binding{Namespace: gateway, Context: contexts[gateway], Interface: "wg0", Address: privateGW, Target: privateServer, Peer: serverPublic, Protocol: "wireguard", Gateway: Ref{ID: "router"}, Source: Ref{ID: "trusted"}, RequirePath: true, FailClosed: true}},
		{Kind: Service, Alias: "public-control", Binding: Binding{Namespace: server, Context: contexts[server], Interface: "eth0", Address: underServer, Target: underServer, Port: 53, Protocol: "dns", Transports: []string{"udp", "tcp"}, AccessModes: []string{"direct"}, Realm: "public"}},
		{Kind: Service, Alias: "private-dns", Binding: Binding{Namespace: server, Context: contexts[server], Interface: "wg0", Address: privateServer, Target: privateServer, Port: 53, Protocol: "dns", Transports: []string{"udp", "tcp"}, AccessModes: []string{"direct"}, Realm: "protected", Gateway: Ref{ID: "router"}, VPN: Ref{ID: "tunnel"}, Source: Ref{ID: "trusted"}, Control: Ref{ID: "public-control"}}},
	}
	rules := []Rule{}
	for _, source := range []string{"trusted", "guest"} {
		decision := "allow"
		if source == "guest" {
			decision = "deny"
		}
		rule := Rule{Alias: source + "-dns", Decision: decision, Path: Ref{ID: "tunnel"}, FailClosed: true}
		for _, transport := range []string{"udp", "tcp"} {
			rule.Tuples = append(rule.Tuples, Tuple{Source: Ref{ID: source}, Endpoint: Ref{ID: "private-dns"}, Realm: "protected", Family: "ipv4", Transport: transport, Port: 53, Mode: "direct"})
		}
		rules = append(rules, rule)
	}
	dir := t.TempDir()
	env := CLIEnv{RegistryPath: filepath.Join(dir, "private", "network-state.json"), StatePath: filepath.Join(dir, "legacy.json"), ReceiptDir: filepath.Join(dir, "receipts"), Fixture: true, Actor: func(context.Context) ([]byte, error) { return []byte("ck_sub_fixture"), nil }}
	closed := true
	missingTool := false
	denyProbe := false
	env.Collect = func(c context.Context, q Question, permit func(context.Context, string) error) Collection {
		native := newCollector(permit)
		native.fixture = true
		if closed {
			native.closed = map[string]bool{contexts[gateway]: true}
		}
		if missingTool {
			native.run = func(context.Context, string, string, ...string) ([]byte, error) { return nil, ErrUnsupported }
		}
		return native.collect(c, q)
	}
	cli := func(args ...string) (int, []byte) {
		t.Helper()
		var out, errout bytes.Buffer
		code := Run(ctx, args, env, &out, &errout)
		if errout.Len() > 0 {
			t.Logf("CLI operational error (%d sanitized bytes)", errout.Len())
		}
		return code, out.Bytes()
	}
	manifest, _ := json.Marshal(struct {
		Objects  []Object `json:"objects"`
		Policies []Rule   `json:"policies"`
	}{objects, rules})
	manifestPath := filepath.Join(dir, "manifest.json")
	os.WriteFile(manifestPath, manifest, 0600)
	if code, _ := cli("registry", "import", manifestPath); code != 0 {
		t.Fatal("real metadata import failed")
	}
	for _, args := range [][]string{{"discover"}, {"inspect", "gateway", "router"}, {"inspect", "wireguard", "tunnel"}, {"inspect", "service", "private-dns", "--details"}} {
		code, data := cli(args...)
		if code != 0 {
			t.Fatal("metadata path failed")
		}
		if bytes.Contains(data, []byte(privateServer)) || bytes.Contains(data, []byte(serverPublic)) {
			t.Fatal("default metadata exposes protected values")
		}
	}
	var grants []policy.Grant
	state := func() {
		data, _ := json.Marshal(map[string]any{"grants": grants, "provider_keys": []int{1}, "signing_keys": "SENSITIVE_SENTINEL"})
		os.WriteFile(env.StatePath, data, 0600)
	}
	state()
	verify := func(want int, args ...string) Assessment {
		t.Helper()
		requestArgs := append(append([]string(nil), args...), "--request")
		code, data := cli(requestArgs...)
		if code != 0 {
			t.Fatalf("offline request failed for %s", args[1])
		}
		var descriptor RequestDescriptor
		if json.Unmarshal(data, &descriptor) != nil {
			t.Fatal("request descriptor")
		}
		grant := fixtureGrant(descriptor.Request, time.Now())
		if denyProbe {
			grant.Pins.Capabilities.Allowed = []string{"network.read"}
		}
		grant.ID = fmt.Sprintf("grant-fixture-%d", len(grants))
		grants = append(grants, grant)
		state()
		before, _ := os.ReadFile(env.StatePath)
		execution := append(append([]string(nil), args...), "--grant", grant.ID)
		code, data = cli(execution...)
		var a Assessment
		json.Unmarshal(data, &a)
		if code != want {
			for _, p := range a.Properties {
				t.Logf("property %s: %s", p.Property, p.State)
			}
			t.Logf("missing: %v", a.Missing)
			t.Fatalf("%s: got exit%d want%d", args[1], code, want)
		}
		after, _ := os.ReadFile(env.StatePath)
		if !bytes.Equal(before, after) {
			t.Fatal("verification changed legacy state")
		}
		if !a.Cleanup || !a.Synthetic {
			t.Fatal("cleanup/provenance missing")
		}
		return a
	}
	// Existing keepalive establishes a real authenticated session; do not manufacture timestamps.
	until := time.Now().Add(5 * time.Second)
	ready := false
	for time.Now().Before(until) {
		at, ok := peerHandshake(run(gateway, "wg", "show", "wg0", "latest-handshakes"), serverPublic)
		if ok && at.Unix() > 0 {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("real WireGuard session not established")
	}
	gatewayAssessment := verify(0, "verify", "gateway", "router")
	if len(gatewayAssessment.Properties) != 4 {
		t.Fatal("gateway profile scope")
	}
	vpnAssessment := verify(0, "verify", "vpn", "tunnel")
	if len(vpnAssessment.Properties) != 6 {
		t.Fatal("VPN conditional profile scope")
	}
	baseline := verify(0, "verify", "access", "private-dns", "--from", "trusted")
	isolated := verify(0, "verify", "isolation", "guest", "private-dns", "--baseline", baseline.ID)
	for _, f := range isolated.Evidence {
		if f.Property == "isolation.baseline" {
			matched := false
			for _, prior := range baseline.Evidence {
				if prior.Property == "dns.response" && prior.Tuple.Transport == f.Tuple.Transport {
					matched = f.ObservedAt.Equal(prior.ObservedAt) && f.ValidUntil.Equal(prior.ValidUntil) && f.HistoricalAssessment == baseline.ID
				}
			}
			if !matched {
				t.Fatal("baseline reuse refreshed original time/provenance")
			}
		}
		if f.Property == "isolation.coverage" && len(f.ObserverWindows) != 2 {
			t.Fatal("actual observer windows absent")
		}
	}
	verify(0, "verify", "access", "private-dns", "--from", "guest", "--baseline", baseline.ID)
	closed = false
	verify(2, "verify", "isolation", "guest", "private-dns", "--baseline", baseline.ID)
	closed = true
	missingTool = true
	verify(2, "verify", "vpn", "tunnel")
	missingTool = false
	denyProbe = true
	verify(2, "verify", "access", "private-dns", "--from", "trusted")
	denyProbe = false
	// A real leak, not a mocked response. Refresh the real positive baseline after changing effective policy.
	run(gateway, "nft", "flush", "chain", "inet", "np", "guard")
	addGuard()
	leakBaseline := verify(0, "verify", "access", "private-dns", "--from", "trusted")
	leak := verify(1, "verify", "isolation", "guest", "private-dns", "--baseline", leakBaseline.ID)
	if leak.Verdict != Violated {
		t.Fatal("real leak did not violate")
	}
	verify(0, "verify", "gateway", "router")
	verify(0, "verify", "vpn", "tunnel")
	// A failed positive control is missing evidence, never a policy violation.
	run(gateway, "nft", "flush", "chain", "inet", "np", "guard")
	run(gateway, "nft", "add", "rule", "inet", "np", "guard", "ip", "saddr", guIP, "ip", "daddr", privateServer, "drop")
	addGuard()
	healthyBaseline := verify(0, "verify", "access", "private-dns", "--from", "trusted")
	stopAddress(underServer)
	verify(2, "verify", "isolation", "guest", "private-dns", "--baseline", healthyBaseline.ID)
	stopAddress(privateServer)
	verify(2, "verify", "access", "private-dns", "--from", "trusted")
	t.Log("REAL isolated Linux/WireGuard/DNS gate PASS: allow, isolation, leak, unsupported coverage/tool, bounded profiles, state/privacy/observer cleanup")
}
func TestOpenWrtKernelCrossModel(t *testing.T) {
	requireIsolatedNetworkRunner(t)
	if os.Geteuid() != 0 {
		t.Skip("requires authorized isolated Linux namespace runner")
	}
	for _, tool := range []string{"ip", "nft"} {
		if _, e := exec.LookPath(tool); e != nil {
			t.Skip("missing isolated fixture prerequisite")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	run := func(tool string, args ...string) []byte {
		t.Helper()
		cctx, done := context.WithTimeout(ctx, 3*time.Second)
		defer done()
		out, e := exec.CommandContext(cctx, tool, args...).Output()
		if e != nil {
			t.Fatalf("OpenWrt synthetic fixture setup/read failed (%s)", tool)
		}
		return out
	}
	name := "ow" + strings.TrimPrefix(policy.NewID("x"), "x_")[:8]
	run("ip", "netns", "add", name)
	t.Cleanup(func() {
		c, d := context.WithTimeout(context.Background(), 3*time.Second)
		defer d()
		if exec.CommandContext(c, "ip", "netns", "del", name).Run() != nil {
			t.Error("synthetic OpenWrt namespace cleanup failed")
		}
		if _, e := namespaceIdentity(name); e == nil {
			t.Error("synthetic namespace retained")
		}
	})
	for _, device := range []string{"edge0", "tunnel0", "uplink0"} {
		run("ip", "-n", name, "link", "add", device, "type", "dummy")
		run("ip", "-n", name, "link", "set", device, "up")
	}
	run("ip", "-n", name, "addr", "add", fixtureIP(1)+"/24", "dev", "edge0")
	contextID, _ := namespaceIdentity(name)
	if withinNamespace(ctx, Binding{Namespace: name, Context: contextID}, func() error { return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0600) }) != nil {
		t.Fatal("synthetic forwarding setup")
	}
	for _, table := range []struct{ number, device string }{{"100", "tunnel0"}, {"200", "uplink0"}} {
		run("ip", "-n", name, "route", "add", "table", table.number, fixtureIP(53)+"/32", "dev", table.device)
	}
	run("ip", "-n", name, "rule", "add", "priority", "100", "from", fixtureIP(2), "iif", "edge0", "fwmark", "100/255", "table", "100")
	nft := func(args ...string) []byte {
		return run("ip", append([]string{"netns", "exec", name, "nft"}, args...)...)
	}
	nft("add", "table", "inet", "fixture")
	nft("add", "set", "inet", "fixture", "destinations", "{", "type", "ipv4_addr", ";", "}")
	nft("add", "element", "inet", "fixture", "destinations", "{", fixtureIP(53), "}")
	for _, c := range owSelectors().Chains {
		nft("add", "chain", c.Family, c.Table, c.Chain, "{", "type", "filter", "hook", c.Hook, "priority", fmt.Sprint(*c.Priority), ";", "policy", "accept", ";", "}")
	}
	nft("add", "rule", "inet", "fixture", "classify", "ip", "saddr", fixtureIP(2), "iifname", "edge0", "ip", "daddr", "@destinations", "meta", "mark", "set", "100")
	nft("add", "rule", "inet", "fixture", "forward", "ip", "saddr", fixtureIP(2), "iifname", "edge0", "ip", "daddr", fixtureIP(53), "accept")
	nft("add", "rule", "inet", "fixture", "guard", "ip", "saddr", fixtureIP(2), "iifname", "edge0", "ip", "daddr", fixtureIP(53), "oifname", "!=", "tunnel0", "drop")
	q, s := owFixture()
	q.Gateway.Binding.Namespace = name
	q.Gateway.Binding.Context = contextID
	q.Target = q.Gateway
	q.VPN.Binding.Namespace = name
	q.VPN.Binding.Context = contextID
	sealOpenWrtQuestion(&q)
	// Only ubus/UCI are explicitly labeled fixture stubs; kernel ip/nft reads remain real.
	stubs := t.TempDir()
	logical := string(s.logical)
	ubus := "#!/bin/sh\n[ \"$1\" = call ] && [ \"$2\" = network.interface.home ] && [ \"$3\" = status ] || exit 42\nprintf '%s' '" + logical + "'\n"
	uci := "#!/bin/sh\n[ \"$1\" = -q ] && [ \"$2\" = get ] || exit 42\ncase \"$3\" in network.home.device) printf edge0;; firewall.home_to_uplink.src) printf home;; firewall.home_to_uplink.dest) printf uplink;; firewall.home_to_uplink.enabled) printf 0;; *) exit 42;; esac\n"
	if os.WriteFile(filepath.Join(stubs, "ubus"), []byte(ubus), 0700) != nil || os.WriteFile(filepath.Join(stubs, "uci"), []byte(uci), 0700) != nil {
		t.Fatal("fixture status stubs")
	}
	t.Setenv("PATH", stubs+":"+os.Getenv("PATH"))
	c := newCollector(func(context.Context, string) error { return nil })
	c.fixture = true
	fingerprint := func() string {
		return hashJSON([]any{owSemantic(run("ip", "-n", name, "-j", "-4", "rule", "show")), owSemantic(run("ip", "-n", name, "-j", "-4", "route", "show", "table", "100")), owSemantic(nft("-j", "list", "table", "inet", "fixture"))})
	}
	has := func(out Collection, p string) bool {
		for _, f := range out.Facts {
			if f.Property == p && f.Value {
				return true
			}
		}
		return false
	}
	before := fingerprint()
	out := c.collect(ctx, q)
	if !has(out, "gateway.policy_scope") || has(out, "enforcement.guard") || has(out, "source.binding") || has(out, "path.selection") {
		t.Log("missing:", out.Missing)
		t.Fatal("unknown production closure/origin became complete evidence or supported scope missing")
	}
	if fingerprint() != before {
		t.Fatal("read-only adapter mutated synthetic kernel state")
	}
	if len(out.Capabilities) != 1 || out.Capabilities[0].Support != Partial {
		t.Fatal("fixture became firmware support claim")
	}
	c.closed = map[string]bool{contextID: true}
	out = c.collect(ctx, q)
	if !has(out, "routing.policy_selection") || !has(out, "forwarding.permission") || !has(out, "enforcement.guard") {
		t.Log("missing:", out.Missing)
		t.Fatal("synthetic closed cross-model normalization incomplete")
	}
	if a := Evaluate(q.Request, out.Facts, time.Now().UTC(), out.Cleanup, true); a.Verdict != Verified || len(a.Properties) != 4 {
		t.Fatal("finite gateway profile widened")
	}
	snap, e := readOpenWrtSnapshot(ctx, q, c.permit, c.readNamespace)
	if e != nil || !normalizeOpenWrt(q, snap).vpnSelected {
		t.Fatal("real marked RPDB selection not normalized")
	}
	// Higher-priority real kernel selection overrides desired/main route without changing forwarding permission.
	run("ip", "-n", name, "rule", "add", "priority", "50", "from", fixtureIP(2), "iif", "edge0", "fwmark", "100/255", "table", "200")
	snap, e = readOpenWrtSnapshot(ctx, q, c.permit, c.readNamespace)
	if e != nil {
		t.Fatal("priority override snapshot")
	}
	normalized := normalizeOpenWrt(q, snap)
	if normalized.vpnSelected || !normalized.routeSelected || !normalized.guardCandidate {
		t.Fatal("effective precedence/path/guard conflated")
	}
	nft("flush", "chain", "inet", "fixture", "guard")
	out = c.collect(ctx, q)
	if has(out, "enforcement.guard") || !has(out, "forwarding.permission") {
		t.Fatal("forwarding permission became enforcement guard")
	}
	// Runtime change between samples is stale, never a composite proof.
	changed := false
	c.run = func(cctx context.Context, namespace, tool string, args ...string) ([]byte, error) {
		if tool == "uci" && !changed {
			changed = true
			run("ip", "-n", name, "rule", "del", "priority", "50")
		}
		return runNative(cctx, namespace, tool, args...)
	}
	out = c.collect(ctx, q)
	if len(out.Facts) != 0 || len(out.Missing) == 0 {
		t.Fatal("mixed kernel snapshots accepted")
	}
	c.run = runNative
	nft("delete", "element", "inet", "fixture", "destinations", "{", fixtureIP(53), "}")
	out = c.collect(ctx, q)
	if len(out.Facts) != 0 || len(out.Missing) == 0 {
		t.Fatal("ambiguous set nonmembership promoted")
	}
	t.Log("REAL kernel OpenWrt cross-model gate PASS; ubus/UCI synthetic only, live firmware UNVERIFIED; read-only state and namespace cleanup checked")
}

func startFixtureDNS(t *testing.T, ctx context.Context, b Binding, addresses []string) (func(), func(string)) {
	t.Helper()
	var packets []net.PacketConn
	var listeners []net.Listener
	var workers sync.WaitGroup
	for _, address := range addresses {
		var packet net.PacketConn
		var listener net.Listener
		e := withinNamespace(ctx, b, func() error {
			var e error
			packet, e = net.ListenPacket("udp", net.JoinHostPort(address, "53"))
			if e != nil {
				return e
			}
			listener, e = net.Listen("tcp", net.JoinHostPort(address, "53"))
			return e
		})
		if e != nil {
			t.Fatal("isolated DNS listeners unavailable")
		}
		packets = append(packets, packet)
		listeners = append(listeners, listener)
		workers.Add(2)
		go func(p net.PacketConn) {
			defer workers.Done()
			data := make([]byte, 4096)
			for {
				n, peer, e := p.ReadFrom(data)
				if e != nil {
					return
				}
				reply := append([]byte(nil), data[:n]...)
				if len(reply) < 12 {
					continue
				}
				binary.BigEndian.PutUint16(reply[2:4], 0x8183)
				p.WriteTo(reply, peer)
			}
		}(packet)
		go func(l net.Listener) {
			defer workers.Done()
			for {
				connection, e := l.Accept()
				if e != nil {
					return
				}
				connection.SetDeadline(time.Now().Add(time.Second))
				var length [2]byte
				if _, e = io.ReadFull(connection, length[:]); e == nil {
					n := int(binary.BigEndian.Uint16(length[:]))
					if n >= 12 && n <= 4096 {
						reply := make([]byte, n+2)
						copy(reply[:2], length[:])
						if _, e = io.ReadFull(connection, reply[2:]); e == nil {
							binary.BigEndian.PutUint16(reply[4:6], 0x8183)
							connection.Write(reply)
						}
					}
				}
				connection.Close()
			}
		}(listener)
	}
	return func() {
			for _, p := range packets {
				p.Close()
			}
			for _, l := range listeners {
				l.Close()
			}
			workers.Wait()
		}, func(address string) {
			for i, a := range addresses {
				if a == address {
					packets[i].Close()
					listeners[i].Close()
				}
			}
		}
}
