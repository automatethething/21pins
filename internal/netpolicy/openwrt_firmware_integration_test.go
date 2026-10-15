//go:build linux && openwrt_firmware_integration

package netpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/petrichor/21pins-cli/internal/policy"
)

func TestControlledRealFw4Validation(t *testing.T) {
	if os.Getenv("PINS21_REAL_FW4_TEST") != "1" {
		t.Skip("controlled real firmware guest only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cases := map[string]string{"real_logical_binding": "NOT_RUN", "stored_vs_runtime": "NOT_RUN", "native_scalar_membership": "NOT_RUN", "native_rpdb_mark_selection": "NOT_RUN", "earlier_rpdb_override": "NOT_RUN", "independent_forward_guard_traffic": "NOT_RUN", "foreign_namespace_binding": "NOT_RUN", "unsupported_expression": "NOT_RUN", "uncalled_chain": "NOT_RUN", "unknown_override": "NOT_RUN"}
	record := map[string]any{"stage": "real_fw4_validation", "source_commit": "214aad5", "status": "running", "cases": cases, "generic_contract_defect": false}
	defer func() {
		if record["status"] == "running" {
			record["status"] = "validation_failed"
		}
		raw, _ := json.Marshal(record)
		os.WriteFile("/tmp/pins-fw4-result.json", raw, 0600)
		fmt.Printf("\nPINS_JSON:%s\n", raw)
	}()
	fail := func(code string, contract bool) {
		record["status"] = "stopped"
		record["generic_contract_defect"] = contract
		record["defect"] = code
		t.Fatal(code)
	}
	run := func(namespace, tool string, args ...string) []byte {
		t.Helper()
		if namespace != "" {
			args = append([]string{"netns", "exec", namespace, tool}, args...)
			tool = "ip"
		}
		c, d := context.WithTimeout(ctx, 3*time.Second)
		defer d()
		out, e := exec.CommandContext(c, tool, args...).Output()
		if e != nil {
			fail("controlled_setup_or_tool_unavailable", false)
		}
		return out
	}
	address := func(a, b, c, d byte) string { return netip.AddrFrom4([4]byte{a, b, c, d}).String() }
	sourceGW, sourceIP, wrongIP := address(192, 0, 2, 1), address(192, 0, 2, 2), address(192, 0, 2, 99)
	targetGW, targetIP := address(198, 18, 0, 1), address(198, 18, 0, 53)
	sourceNS, sinkNS, mirrorNS := "pins_source", "pins_sink", "pins_mirror"
	for _, name := range []string{sourceNS, sinkNS, mirrorNS} {
		run("", "ip", "netns", "add", name)
	}
	t.Cleanup(func() {
		for _, name := range []string{sourceNS, sinkNS, mirrorNS} {
			c, d := context.WithTimeout(context.Background(), 3*time.Second)
			exec.CommandContext(c, "ip", "netns", "del", name).Run()
			d()
		}
	})
	for _, pair := range [][2]string{{"pins_edge", sourceNS}, {"pins_path", sinkNS}} {
		run("", "ip", "link", "add", pair[0], "type", "veth", "peer", "name", "eth0", "netns", pair[1])
		run("", "ip", "link", "set", pair[0], "up")
		run("", "ip", "-n", pair[1], "link", "set", "lo", "up")
		run("", "ip", "-n", pair[1], "link", "set", "eth0", "up")
	}
	run("", "ip", "-n", sourceNS, "addr", "add", sourceIP+"/24", "dev", "eth0")
	run("", "ip", "-n", sourceNS, "route", "add", "default", "via", sourceGW)
	run("", "ip", "-n", sinkNS, "addr", "add", targetIP+"/24", "dev", "eth0")
	run("", "ip", "-n", sinkNS, "route", "add", "default", "via", targetGW)
	run("", "ip", "link", "add", "pins_other", "type", "dummy")
	run("", "ip", "link", "set", "pins_other", "up")
	uci := func(value string) { run("", "uci", "set", value) }
	for _, item := range []string{"network.pinssource=interface", "network.pinssource.proto=static", "network.pinssource.device=pins_edge", "network.pinssource.ipaddr=" + sourceGW, "network.pinssource.netmask=" + address(255, 255, 255, 0), "network.pinsdest=interface", "network.pinsdest.proto=static", "network.pinsdest.device=pins_path", "network.pinsdest.ipaddr=" + targetGW, "network.pinsdest.netmask=" + address(255, 255, 255, 0)} {
		uci(item)
	}
	run("", "uci", "commit", "network")
	run("", "ubus", "call", "network", "reload")
	ready := false
	for i := 0; i < 20; i++ {
		var state struct{ Up bool }
		json.Unmarshal(run("", "ubus", "call", "network.interface.pinssource", "status"), &state)
		if state.Up {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		fail("real_netifd_logical_not_ready", false)
	}
	for _, item := range []string{"firewall.pinssrc=zone", "firewall.pinssrc.name=pinssrc", "firewall.pinssrc.network=pinssource", "firewall.pinssrc.input=ACCEPT", "firewall.pinssrc.output=ACCEPT", "firewall.pinssrc.forward=REJECT", "firewall.pinsdst=zone", "firewall.pinsdst.name=pinsdst", "firewall.pinsdst.network=pinsdest", "firewall.pinsdst.input=ACCEPT", "firewall.pinsdst.output=ACCEPT", "firewall.pinsdst.forward=REJECT", "firewall.pinslink=forwarding", "firewall.pinslink.src=pinssrc", "firewall.pinslink.dest=pinsdst", "firewall.pinslink.enabled=1"} {
		uci(item)
	}
	run("", "uci", "commit", "firewall")
	run("", "/etc/init.d/firewall", "reload")
	nft := func(namespace string, args ...string) []byte { return run(namespace, "nft", args...) }
	selectors := &OpenWrtBinding{LogicalNetwork: "pinssource", Profile: "fw4-basic", Chains: []BoundChain{{Family: "inet", Table: "pinstest", Chain: "classify", Role: "classifier", Hook: "prerouting", Priority: realPriority(-160)}, {Family: "inet", Table: "pinstest", Chain: "forward", Role: "forwarding", Hook: "forward", Priority: realPriority(10)}, {Family: "inet", Table: "pinstest", Chain: "guard", Role: "guard", Hook: "forward", Priority: realPriority(20)}}, DestinationSet: &BoundSet{Family: "inet", Table: "pinstest", Name: "targets", ElementFamily: "ipv4"}, StoredSections: []string{"pinslink"}}
	setupTable := func(namespace string, scope *OpenWrtBinding) {
		nft(namespace, "add", "table", "inet", "pinstest")
		for _, chain := range scope.Chains {
			nft(namespace, "add", "chain", chain.Family, chain.Table, chain.Chain, "{", "type", "filter", "hook", chain.Hook, "priority", fmt.Sprint(*chain.Priority), ";", "policy", "accept", ";", "}")
		}
	}
	setupTable("", selectors)
	nft("", "add", "set", "inet", "pinstest", "targets", "{", "type", "ipv4_addr", ";", "}")
	nft("", "add", "element", "inet", "pinstest", "targets", "{", targetIP, "}")
	nft("", "add", "rule", "inet", "pinstest", "classify", "ip", "saddr", sourceIP, "iifname", "pins_edge", "ip", "daddr", "@targets", "meta", "mark", "set", "100")
	nft("", "add", "rule", "inet", "pinstest", "forward", "ip", "saddr", sourceIP, "iifname", "pins_edge", "ip", "daddr", targetIP, "accept")
	for _, table := range [][2]string{{"100", "pins_path"}, {"200", "pins_other"}} {
		run("", "ip", "route", "add", "table", table[0], targetIP+"/32", "dev", table[1])
	}
	run("", "ip", "rule", "add", "priority", "100", "from", sourceIP, "iif", "pins_edge", "fwmark", "100/255", "table", "100")
	routerContext, _ := namespaceIdentity("")
	clientContext, _ := namespaceIdentity(sourceNS)
	registry := NewRegistry(filepath.Join(t.TempDir(), "registry", "network-state.json"))
	objects := []Object{{Kind: Gateway, Alias: "router", Binding: Binding{Context: routerContext, Interface: "pins_edge", Address: sourceGW, Target: targetIP, Source: Ref{ID: "client"}, OpenWrt: selectors}}, {Kind: Network, Alias: "client", Binding: Binding{Namespace: sourceNS, Context: clientContext, Interface: "eth0", Ingress: "pins_edge", Address: sourceIP, Gateway: Ref{ID: "router"}, OpenWrt: &OpenWrtBinding{LogicalNetwork: "pinssource"}}}}
	data, _ := json.Marshal(map[string]any{"objects": objects})
	if registry.Import(strings.NewReader(string(data))) != nil {
		fail("synthetic_registry_import", false)
	}
	q, e := registry.Question("gateway", "router", "", nil)
	if e != nil {
		fail("question_scope", false)
	}
	statePath := filepath.Join(t.TempDir(), "grant.json")
	now := time.Now()
	grant := policy.Grant{ID: "grant-fw4-test", Sub: "ck_sub_synthetic", Status: policy.GrantStatusActive, Pins: policy.Pins{Identity: policy.IdentityPin{Sub: "ck_sub_synthetic"}, Authority: policy.AuthorityPin{Chain: []string{"ck_sub_synthetic"}}, Capabilities: policy.CapabilityPin{Allowed: []string{"network.read"}}, DataPolicy: policy.DataPolicyPin{AllowedClasses: []string{"network-metadata"}}, SpendPolicy: policy.SpendPolicyPin{WindowStart: now.Add(-time.Minute), WindowEnd: now.Add(2 * time.Minute)}, ExecutionTargets: policy.ExecutionTargetPin{AllowedTargets: []string{q.Request.Digest("network.read")}}}}
	saveGrant := func(question Question) {
		grant.Pins.ExecutionTargets.AllowedTargets = []string{question.Request.Digest("network.read")}
		raw, _ := json.Marshal(map[string]any{"grants": []policy.Grant{grant}})
		os.WriteFile(statePath, raw, 0600)
	}
	saveGrant(q)
	collectorFor := func(question Question) *collector {
		saveGrant(question)
		c := newCollector(func(c context.Context, cap string) error {
			return Authorize(c, statePath, grant.ID, question.Request, cap, time.Now(), func(context.Context) ([]byte, error) { return []byte("ck_sub_synthetic"), nil })
		})
		c.fixture = true
		return c
	}
	collect := func(question Question) Collection { return collectorFor(question).collect(ctx, question) }
	has := func(out Collection, p string) bool {
		for _, f := range out.Facts {
			if f.Property == p && f.Value {
				return true
			}
		}
		return false
	}
	out := collect(q)
	assessment := Evaluate(q.Request, out.Facts, time.Now().UTC(), out.Cleanup, true)
	if assessment.Verdict != Verified {
		cases["native_read"] = "UNVERIFIED"
		fail("native_supported_subset_unverified", false)
	}
	cases["real_logical_binding"] = "PASS"
	cases["native_scalar_membership"] = "PASS"
	cases["native_rpdb_mark_selection"] = "PASS"
	cases["finite_gateway_profile"] = "PASS"
	c := collectorFor(q)
	snapshot, e := readOpenWrtSnapshot(ctx, q, c.permit, c.readNamespace)
	if e != nil {
		fail("native_snapshot", false)
	}
	baseRuntime := openWrtRuntimeDigest(snapshot)
	uci("firewall.pinslink.enabled=0")
	run("", "uci", "commit", "firewall")
	nft("", "add", "rule", "inet", "pinstest", "guard", "ip", "saddr", sourceIP, "iifname", "pins_edge", "ip", "daddr", targetIP, "drop")
	snapshot, e = readOpenWrtSnapshot(ctx, q, c.permit, c.readNamespace)
	if e != nil {
		fail("stored_runtime_snapshot", false)
	}
	norm := normalizeOpenWrt(q, snapshot)
	if snapshot.stored["pinslink.enabled"] != "0" || !norm.guardCandidate || openWrtRuntimeDigest(snapshot) == baseRuntime {
		fail("stored_runtime_contradiction", true)
	}
	cases["stored_vs_runtime"] = "PASS"
	out = collect(q)
	if has(out, "enforcement.guard") || has(out, "source.binding") || has(out, "path.selection") {
		fail("unknown_coverage_promoted", true)
	}
	cases["unknown_coverage_and_client_path"] = "UNVERIFIED_AS_REQUIRED"
	nft("", "flush", "chain", "inet", "pinstest", "guard")
	run("", "ip", "rule", "add", "priority", "50", "from", sourceIP, "iif", "pins_edge", "fwmark", "100/255", "table", "200")
	snapshot, e = readOpenWrtSnapshot(ctx, q, c.permit, c.readNamespace)
	if e != nil {
		fail("priority_override_snapshot", false)
	}
	var route []struct{ Dev string }
	json.Unmarshal(snapshot.route, &route)
	if len(route) != 1 || route[0].Dev != "pins_other" {
		fail("rpdb_override_interpretation", true)
	}
	cases["earlier_rpdb_override"] = "PASS"
	run("", "ip", "rule", "del", "priority", "50")
	// Independent traffic measurements never become adapter path or production isolation proof.
	var listener net.PacketConn
	sinkContext, _ := namespaceIdentity(sinkNS)
	if withinNamespace(ctx, Binding{Namespace: sinkNS, Context: sinkContext}, func() error {
		var err error
		listener, err = net.ListenPacket("udp", net.JoinHostPort(targetIP, "4053"))
		return err
	}) != nil {
		fail("traffic_sink", false)
	}
	defer listener.Close()
	go func() {
		buffer := make([]byte, 64)
		for {
			n, peer, err := listener.ReadFrom(buffer)
			if err != nil {
				return
			}
			if n > 0 {
				listener.WriteTo([]byte("ok"), peer)
			}
		}
	}()
	ping := func() bool {
		ok := false
		withinNamespace(ctx, Binding{Namespace: sourceNS, Context: clientContext}, func() error {
			connection, err := net.DialTimeout("udp", net.JoinHostPort(targetIP, "4053"), time.Second)
			if err != nil {
				return err
			}
			defer connection.Close()
			connection.SetDeadline(time.Now().Add(time.Second))
			connection.Write([]byte("synthetic"))
			var b [8]byte
			n, err := connection.Read(b[:])
			ok = err == nil && string(b[:n]) == "ok"
			return nil
		})
		return ok
	}
	if !ping() {
		fail("controlled_allow_traffic_not_established", false)
	}
	nft("", "add", "rule", "inet", "pinstest", "guard", "ip", "saddr", sourceIP, "iifname", "pins_edge", "ip", "daddr", targetIP, "drop")
	if ping() {
		fail("active_guard_observation_contradiction", true)
	}
	nft("", "flush", "chain", "inet", "pinstest", "guard")
	cases["independent_forward_guard_traffic"] = "PASS_SYNTHETIC_NOT_VPN_PROOF"
	// Highest-risk negative: system ubus is not automatically scoped by a caller's network namespace.
	run("", "ip", "-n", mirrorNS, "link", "add", "pins_edge", "type", "dummy")
	run("", "ip", "-n", mirrorNS, "addr", "add", wrongIP+"/24", "dev", "pins_edge")
	run("", "ip", "-n", mirrorNS, "link", "set", "pins_edge", "up")
	mirrorContext, _ := namespaceIdentity(mirrorNS)
	mirrorSelectors := cloneBinding(Binding{OpenWrt: selectors}).OpenWrt
	mirrorSelectors.DestinationSet = nil
	setupTable(mirrorNS, mirrorSelectors)
	mirrored := Object{Kind: Gateway, Alias: "mirror", Binding: Binding{Namespace: mirrorNS, Context: mirrorContext, Interface: "pins_edge", Address: sourceGW, Target: targetIP, OpenWrt: mirrorSelectors}}
	if _, e = registry.Create(mirrored); e != nil {
		fail("negative_context_setup", false)
	}
	mirror, e := registry.Question("gateway", "mirror", "", nil)
	if e != nil {
		fail("negative_context_question", false)
	}
	out = collect(mirror)
	a := Evaluate(mirror.Request, out.Facts, time.Now().UTC(), out.Cleanup, true)
	if has(out, "gateway.interface_binding") {
		cases["foreign_namespace_binding"] = "CONTRADICTION"
		record["observations"] = map[string]any{"distinct_native_context": mirrorContext != routerContext, "kernel_address_matches_binding": false, "adapter_interface_binding_true": true, "gateway_verdict": a.Verdict}
		fail("SYSTEM_UBUS_CONTEXT_MISATTRIBUTED_TO_FOREIGN_NETNS", true)
	}
	cases["foreign_namespace_binding"] = "UNVERIFIED_AS_REQUIRED"
	nft("", "add", "rule", "inet", "pinstest", "classify", "ip", "saddr", sourceIP, "iifname", "pins_edge", "ip", "daddr", targetIP, "ct", "mark", "set", "meta", "mark")
	out = collect(q)
	if has(out, "gateway.policy_scope") {
		fail("unsupported_expression_promoted", true)
	}
	cases["unsupported_expression"] = "UNVERIFIED_AS_REQUIRED"
	nft("", "flush", "chain", "inet", "pinstest", "classify")
	nft("", "add", "rule", "inet", "pinstest", "classify", "ip", "saddr", sourceIP, "iifname", "pins_edge", "ip", "daddr", "@targets", "meta", "mark", "set", "100")
	nft("", "add", "chain", "inet", "pinstest", "unused")
	extraSelectors := cloneBinding(Binding{OpenWrt: selectors}).OpenWrt
	extraSelectors.Chains = append(extraSelectors.Chains, BoundChain{Family: "inet", Table: "pinstest", Chain: "unused", Role: "classifier"})
	extraObjects := append([]Object(nil), objects...)
	extraObjects[0].Binding = cloneBinding(objects[0].Binding)
	extraObjects[0].Binding.OpenWrt = extraSelectors
	extraRegistry := NewRegistry(filepath.Join(t.TempDir(), "extra", "network-state.json"))
	extraData, _ := json.Marshal(map[string]any{"objects": extraObjects})
	if extraRegistry.Import(strings.NewReader(string(extraData))) != nil {
		fail("uncalled_negative_setup", false)
	}
	extraQuestion, err := extraRegistry.Question("gateway", "router", "", nil)
	if err != nil {
		fail("uncalled_question", false)
	}
	if a := Evaluate(extraQuestion.Request, collect(extraQuestion).Facts, time.Now().UTC(), true, true); a.Verdict != Unverified {
		fail("uncalled_chain_promoted", true)
	}
	cases["uncalled_chain"] = "UNVERIFIED_AS_REQUIRED"
	nft("", "add", "table", "inet", "pinsunread")
	nft("", "add", "chain", "inet", "pinsunread", "earlier", "{", "type", "filter", "hook", "prerouting", "priority", "-170", ";", "policy", "accept", ";", "}")
	out = collect(q)
	if len(out.Capabilities) == 0 || out.Capabilities[0].Support != Partial || has(out, "enforcement.guard") || has(out, "path.selection") {
		fail("unread_override_promoted", true)
	}
	cases["unknown_override"] = "UNVERIFIED_AS_REQUIRED"
	record["status"] = "passed"
}
func realPriority(n int32) *int32 { return &n }
