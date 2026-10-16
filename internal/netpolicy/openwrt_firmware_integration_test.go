//go:build linux && openwrt_firmware_integration

package netpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/petrichor/21pins-cli/internal/policy"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Test coordinator only: one named gate per invocation, never a production bypass.
// The guest record is secondary; a gate completes only after the host fsyncs it.
type fw4Lab struct {
	t                                               *testing.T
	ctx                                             context.Context
	stage                                           string
	report                                          map[string]any
	checks                                          map[string]bool
	sourceGW, sourceIP, wrongIP, targetGW, targetIP string
}

func fw4Address(a, b, c, d byte) string { return netip.AddrFrom4([4]byte{a, b, c, d}).String() }
func (f *fw4Lab) stop(code string, contract bool) {
	f.report["status"] = "UNVERIFIED"
	if contract {
		f.report["status"] = "CONTRADICTION"
	}
	f.report["reason"] = code
	f.t.Fatal(code)
}
func (f *fw4Lab) check(name string, ok, contract bool) {
	f.checks[name] = ok
	if !ok {
		f.stop(name, contract)
	}
}
func (f *fw4Lab) run(ns, tool string, args ...string) []byte {
	f.t.Helper()
	if ns != "" {
		args = append([]string{"netns", "exec", ns, tool}, args...)
		tool = "ip"
	}
	ctx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	out, e := exec.CommandContext(ctx, tool, args...).Output()
	if e != nil {
		f.stop("native_setup_or_tool_unavailable", false)
	}
	return out
}
func (f *fw4Lab) nft(ns string, args ...string) []byte { return f.run(ns, "nft", args...) }
func (f *fw4Lab) uci(value string)                     { f.run("", "uci", "set", value) }
func (f *fw4Lab) save() {
	if f.report["status"] == "RUNNING" {
		f.report["status"] = "UNVERIFIED"
		f.report["reason"] = "native_gate_interrupted"
	}
	f.report["finished_utc"] = time.Now().UTC().Format(time.RFC3339Nano)
	raw, e := json.Marshal(f.report)
	if e != nil {
		f.t.Fatal("safe_record_encoding")
	}
	dir := "/root/pins-fw4-checkpoints"
	if os.MkdirAll(dir, 0700) != nil {
		f.t.Fatal("guest_checkpoint_directory")
	}
	file, e := os.CreateTemp(dir, ".checkpoint-")
	if e != nil {
		f.t.Fatal("guest_checkpoint_create")
	}
	name := file.Name()
	defer os.Remove(name)
	if file.Chmod(0600) != nil {
		f.t.Fatal("guest_checkpoint_mode")
	}
	if _, e = file.Write(raw); e != nil {
		f.t.Fatal("guest_checkpoint_write")
	}
	if file.Sync() != nil || file.Close() != nil {
		f.t.Fatal("guest_checkpoint_sync")
	}
	if os.Rename(name, filepath.Join(dir, f.stage+".json")) != nil {
		f.t.Fatal("guest_checkpoint_commit")
	}
	d, e := os.Open(dir)
	if e != nil {
		f.t.Fatal("guest_checkpoint_parent")
	}
	e = d.Sync()
	d.Close()
	if e != nil {
		f.t.Fatal("guest_checkpoint_parent_sync")
	}
	fmt.Printf("\nPINS_JSON:%s\n", raw)
}
func fw4Priority(n int32) *int32 { return &n }
func (f *fw4Lab) selectors() *OpenWrtBinding {
	return &OpenWrtBinding{LogicalNetwork: "pinssource", Profile: "fw4-basic", Chains: []BoundChain{{Family: "inet", Table: "pinstest", Chain: "classify", Role: "classifier", Hook: "prerouting", Priority: fw4Priority(-160)}, {Family: "inet", Table: "pinstest", Chain: "forward", Role: "forwarding", Hook: "forward", Priority: fw4Priority(10)}, {Family: "inet", Table: "pinstest", Chain: "guard", Role: "guard", Hook: "forward", Priority: fw4Priority(20)}}, DestinationSet: &BoundSet{Family: "inet", Table: "pinstest", Name: "targets", ElementFamily: "ipv4"}, StoredSections: []string{"pinslink"}}
}
func (f *fw4Lab) table(ns string, s *OpenWrtBinding) {
	f.nft(ns, "add", "table", "inet", "pinstest")
	for _, c := range s.Chains {
		f.nft(ns, "add", "chain", c.Family, c.Table, c.Chain, "{", "type", "filter", "hook", c.Hook, "priority", fmt.Sprint(*c.Priority), ";", "policy", "accept", ";", "}")
	}
}
func (f *fw4Lab) classifier() {
	f.nft("", "add", "rule", "inet", "pinstest", "classify", "ip", "saddr", f.sourceIP, "iifname", "pins_edge", "ip", "daddr", "@targets", "meta", "mark", "set", "100")
}
func (f *fw4Lab) drop() {
	f.nft("", "add", "rule", "inet", "pinstest", "guard", "ip", "saddr", f.sourceIP, "iifname", "pins_edge", "ip", "daddr", f.targetIP, "drop")
}
func (f *fw4Lab) waitLogical(want string) {
	for i := 0; i < 25; i++ {
		var state struct {
			Up        bool
			Addresses []struct{ Address string } `json:"ipv4-address"`
		}
		if json.Unmarshal(f.run("", "ubus", "call", "network.interface.pinssource", "status"), &state) == nil && state.Up {
			for _, a := range state.Addresses {
				if a.Address == want {
					return
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	f.stop("logical_runtime_not_ready", false)
}
func (f *fw4Lab) setup() {
	for _, ns := range []string{"pins_source", "pins_sink", "pins_mirror"} {
		f.run("", "ip", "netns", "add", ns)
	}
	for _, pair := range [][2]string{{"pins_edge", "pins_source"}, {"pins_path", "pins_sink"}} {
		f.run("", "ip", "link", "add", pair[0], "type", "veth", "peer", "name", "eth0", "netns", pair[1])
		f.run("", "ip", "link", "set", pair[0], "up")
		f.run("", "ip", "-n", pair[1], "link", "set", "lo", "up")
		f.run("", "ip", "-n", pair[1], "link", "set", "eth0", "up")
	}
	f.run("", "ip", "-n", "pins_source", "addr", "add", f.sourceIP+"/24", "dev", "eth0")
	f.run("", "ip", "-n", "pins_source", "route", "add", "default", "via", f.sourceGW)
	f.run("", "ip", "-n", "pins_sink", "addr", "add", f.targetIP+"/24", "dev", "eth0")
	f.run("", "ip", "-n", "pins_sink", "route", "add", "default", "via", f.targetGW)
	f.run("", "ip", "link", "add", "pins_other", "type", "dummy")
	f.run("", "ip", "link", "set", "pins_other", "up")
	for _, item := range []string{"network.pinssource=interface", "network.pinssource.proto=static", "network.pinssource.device=pins_edge", "network.pinssource.ipaddr=" + f.sourceGW, "network.pinssource.netmask=" + fw4Address(255, 255, 255, 0), "network.pinsdest=interface", "network.pinsdest.proto=static", "network.pinsdest.device=pins_path", "network.pinsdest.ipaddr=" + f.targetGW, "network.pinsdest.netmask=" + fw4Address(255, 255, 255, 0)} {
		f.uci(item)
	}
	f.run("", "uci", "commit", "network")
	f.run("", "ubus", "call", "network", "reload")
	f.waitLogical(f.sourceGW)
	for _, item := range []string{"firewall.pinssrc=zone", "firewall.pinssrc.name=pinssrc", "firewall.pinssrc.network=pinssource", "firewall.pinssrc.input=ACCEPT", "firewall.pinssrc.output=ACCEPT", "firewall.pinssrc.forward=REJECT", "firewall.pinsdst=zone", "firewall.pinsdst.name=pinsdst", "firewall.pinsdst.network=pinsdest", "firewall.pinsdst.input=ACCEPT", "firewall.pinsdst.output=ACCEPT", "firewall.pinsdst.forward=REJECT", "firewall.pinslink=forwarding", "firewall.pinslink.src=pinssrc", "firewall.pinslink.dest=pinsdst", "firewall.pinslink.enabled=1"} {
		f.uci(item)
	}
	f.run("", "uci", "commit", "firewall")
	f.run("", "/etc/init.d/firewall", "reload")
	f.table("", f.selectors())
	f.nft("", "add", "set", "inet", "pinstest", "targets", "{", "type", "ipv4_addr", ";", "}")
	f.nft("", "add", "element", "inet", "pinstest", "targets", "{", f.targetIP, "}")
	f.classifier()
	f.nft("", "add", "rule", "inet", "pinstest", "forward", "ip", "saddr", f.sourceIP, "iifname", "pins_edge", "ip", "daddr", f.targetIP, "accept")
	for _, pair := range [][2]string{{"100", "pins_path"}, {"200", "pins_other"}} {
		f.run("", "ip", "route", "add", "table", pair[0], f.targetIP+"/32", "dev", pair[1])
	}
	f.run("", "ip", "rule", "add", "priority", "100", "from", f.sourceIP, "iif", "pins_edge", "fwmark", "100/255", "table", "100")
}
func (f *fw4Lab) question(extra *OpenWrtBinding, mirror bool) Question {
	root, e := namespaceIdentity("")
	f.check("root_context_available", e == nil, false)
	source, e := namespaceIdentity("pins_source")
	f.check("source_context_available", e == nil, false)
	s := f.selectors()
	if extra != nil {
		s = extra
	}
	objects := []Object{{Kind: Gateway, Alias: "router", Binding: Binding{Context: root, Interface: "pins_edge", Address: f.sourceGW, Target: f.targetIP, Source: Ref{ID: "client"}, OpenWrt: s}}, {Kind: Network, Alias: "client", Binding: Binding{Namespace: "pins_source", Context: source, Interface: "eth0", Ingress: "pins_edge", Address: f.sourceIP, Gateway: Ref{ID: "router"}, OpenWrt: &OpenWrtBinding{LogicalNetwork: "pinssource"}}}}
	alias := "router"
	if mirror {
		context, e := namespaceIdentity("pins_mirror")
		f.check("distinct_mirror_context", e == nil && context != root, false)
		s = cloneBinding(Binding{OpenWrt: s}).OpenWrt
		s.DestinationSet = nil
		objects = append(objects, Object{Kind: Gateway, Alias: "mirror", Binding: Binding{Namespace: "pins_mirror", Context: context, Interface: "pins_edge", Address: f.sourceGW, Target: f.targetIP, OpenWrt: s}})
		alias = "mirror"
	}
	registry := NewRegistry(filepath.Join(f.t.TempDir(), "registry", "state.json"))
	raw, _ := json.Marshal(map[string]any{"objects": objects})
	f.check("registry_import", registry.Import(strings.NewReader(string(raw))) == nil, false)
	q, e := registry.Question("gateway", alias, "", nil)
	f.check("immutable_question", e == nil, false)
	return q
}
func (f *fw4Lab) collector(q Question) *collector {
	now := time.Now()
	g := policy.Grant{ID: "grant-fw4-synthetic", Sub: "ck_sub_synthetic", Status: policy.GrantStatusActive, Pins: policy.Pins{Identity: policy.IdentityPin{Sub: "ck_sub_synthetic"}, Authority: policy.AuthorityPin{Chain: []string{"ck_sub_synthetic"}}, Capabilities: policy.CapabilityPin{Allowed: []string{"network.read"}}, DataPolicy: policy.DataPolicyPin{AllowedClasses: []string{"network-metadata"}}, SpendPolicy: policy.SpendPolicyPin{WindowStart: now.Add(-time.Minute), WindowEnd: now.Add(2 * time.Minute)}, ExecutionTargets: policy.ExecutionTargetPin{AllowedTargets: []string{q.Request.Digest("network.read")}}}}
	path := filepath.Join(f.t.TempDir(), "synthetic-grant.json")
	raw, _ := json.Marshal(map[string]any{"grants": []policy.Grant{g}})
	f.check("synthetic_admission_file", os.WriteFile(path, raw, 0600) == nil, false)
	c := newCollector(func(ctx context.Context, cap string) error {
		return Authorize(ctx, path, g.ID, q.Request, cap, time.Now(), func(context.Context) ([]byte, error) { return []byte("ck_sub_synthetic"), nil })
	})
	c.fixture = true // never sets closure; no tool/path stubs
	return c
}
func (f *fw4Lab) snapshot(q Question) openWrtSnapshot {
	c := f.collector(q)
	s, e := readOpenWrtSnapshot(f.ctx, q, c.permit, c.readNamespace)
	f.check("native_snapshot_available", e == nil, false)
	return s
}
func (f *fw4Lab) collect(q Question) Collection { return f.collector(q).collect(f.ctx, q) }
func fw4Has(c Collection, p string) bool {
	for _, fact := range c.Facts {
		if fact.Property == p && fact.Value {
			return true
		}
	}
	return false
}
func fw4Verdict(q Question, c Collection) Verdict {
	return Evaluate(q.Request, c.Facts, time.Now().UTC(), c.Cleanup, true).Verdict
}
func (f *fw4Lab) noComplete(c Collection) {
	for _, p := range []string{"source.binding", "path.selection", "forwarding.permission", "enforcement.guard"} {
		f.check("no_complete_"+strings.ReplaceAll(p, ".", "_"), !fw4Has(c, p), true)
	}
}
func (f *fw4Lab) kernelState() string {
	return hashJSON(struct {
		Rules, Links, Routes, Nft any
		Network, Firewall         string
	}{owSemantic(f.run("", "ip", "-j", "-4", "rule", "show")), owSemantic(f.run("", "ip", "-j", "link", "show")), owSemantic(f.run("", "ip", "-j", "-4", "route", "show", "table", "all")), owSemantic(f.nft("", "-j", "list", "ruleset")), string(f.run("", "uci", "export", "network")), string(f.run("", "uci", "export", "firewall"))})
}
func (f *fw4Lab) routeDev(s openWrtSnapshot) string {
	var rows []struct{ Dev string }
	f.check("native_fib_json", json.Unmarshal(s.route, &rows) == nil && len(rows) == 1, false)
	return rows[0].Dev
}
func (f *fw4Lab) traffic() {
	var listener net.PacketConn
	context, e := namespaceIdentity("pins_sink")
	f.check("sink_context", e == nil, false)
	e = withinNamespace(f.ctx, Binding{Namespace: "pins_sink", Context: context}, func() error {
		var err error
		listener, err = net.ListenPacket("udp", net.JoinHostPort(f.targetIP, "4053"))
		return err
	})
	f.check("synthetic_sink", e == nil, false)
	defer listener.Close()
	go func() {
		buffer := make([]byte, 64)
		for {
			n, p, e := listener.ReadFrom(buffer)
			if e != nil {
				return
			}
			if n > 0 {
				listener.WriteTo([]byte("ok"), p)
			}
		}
	}()
	source, e := namespaceIdentity("pins_source")
	f.check("traffic_source_context", e == nil, false)
	ping := func() bool {
		ok := false
		withinNamespace(f.ctx, Binding{Namespace: "pins_source", Context: source}, func() error {
			c, e := net.DialTimeout("udp", net.JoinHostPort(f.targetIP, "4053"), time.Second)
			if e != nil {
				return e
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			c.Write([]byte("synthetic"))
			var b [8]byte
			n, e := c.Read(b[:])
			ok = e == nil && string(b[:n]) == "ok"
			return nil
		})
		return ok
	}
	f.check("synthetic_allow_control", ping(), false)
	f.drop()
	defer f.nft("", "flush", "chain", "inet", "pinstest", "guard")
	q := f.question(nil, false)
	n := normalizeOpenWrt(q, f.snapshot(q))
	f.check("supported_guard_candidate", n.scopeSupported && n.guardCandidate, false)
	f.check("scoped_guard_blocks_synthetic_traffic", !ping(), true)
	f.nft("", "flush", "chain", "inet", "pinstest", "guard")
	f.check("post_guard_allow_control", ping(), false)
	f.check("native_forwarding_candidate", fw4Has(f.collect(q), "forwarding.candidate"), false)
	f.noComplete(f.collect(q))
}
func TestControlledRealFw4Validation(t *testing.T) {
	if os.Getenv("PINS21_REAL_FW4_TEST") != "1" {
		t.Skip("owned offline real firmware only")
	}
	stage := os.Getenv("PINS21_FW4_STAGE")
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	f := &fw4Lab{t: t, ctx: ctx, stage: stage, checks: map[string]bool{}, sourceGW: fw4Address(192, 0, 2, 1), sourceIP: fw4Address(192, 0, 2, 2), wrongIP: fw4Address(192, 0, 2, 99), targetGW: fw4Address(198, 18, 0, 1), targetIP: fw4Address(198, 18, 0, 53)}
	f.report = map[string]any{"stage": stage, "status": "RUNNING", "reason": "native_gate", "source_commit": "214aad5", "assertions": f.checks, "started_utc": time.Now().UTC().Format(time.RFC3339Nano)}
	defer f.save()
	switch stage {
	case "logical_runtime_binding":
		f.setup()
		q := f.question(nil, false)
		c := f.collect(q)
		f.check("live_logical_binding", fw4Has(c, "gateway.interface_binding"), false)
		f.check("finite_gateway_profile", fw4Verdict(q, c) == Verified, false)
		f.noComplete(c)
	case "logical_rebind":
		q := f.question(nil, false)
		f.uci("network.pinssource.ipaddr=" + f.wrongIP)
		f.run("", "uci", "commit", "network")
		f.run("", "ubus", "call", "network", "reload")
		f.waitLogical(f.wrongIP)
		c := f.collect(q)
		f.check("old_binding_rejected", !fw4Has(c, "gateway.interface_binding") && fw4Verdict(q, c) == Unverified, true)
		f.uci("network.pinssource.ipaddr=" + f.sourceGW)
		f.run("", "uci", "commit", "network")
		f.run("", "ubus", "call", "network", "reload")
		f.waitLogical(f.sourceGW)
	case "collection_nonmutation":
		q := f.question(nil, false)
		before := f.kernelState()
		c := f.collect(q)
		after := f.kernelState()
		f.check("reader_usable_for_nonmutation", fw4Has(c, "gateway.reader"), false)
		f.check("test_kernel_and_uci_unchanged", before == after, true)
	case "stored_runtime_separation":
		q := f.question(nil, false)
		initial := f.snapshot(q)
		f.uci("firewall.pinslink.enabled=0")
		f.run("", "uci", "commit", "firewall")
		f.drop()
		s := f.snapshot(q)
		n := normalizeOpenWrt(q, s)
		f.check("stored_disabled_with_runtime_drop", s.stored["pinslink.enabled"] == "0" && n.scopeSupported && n.guardCandidate, true)
		f.check("runtime_digest_changed", openWrtRuntimeDigest(s) != openWrtRuntimeDigest(initial), true)
		f.noComplete(f.collect(q))
		f.uci("firewall.pinslink.enabled=1")
		f.run("", "uci", "commit", "firewall")
		f.nft("", "flush", "chain", "inet", "pinstest", "guard")
		s = f.snapshot(q)
		n = normalizeOpenWrt(q, s)
		f.check("stored_enabled_without_runtime_drop", s.stored["pinslink.enabled"] == "1" && n.scopeSupported && !n.guardCandidate, true)
	case "destination_set_membership":
		q := f.question(nil, false)
		s := f.snapshot(q)
		f.check("exact_scalar_member", s.setKnown && s.setMember && normalizeOpenWrt(q, s).markKnown, false)
		f.nft("", "delete", "element", "inet", "pinstest", "targets", "{", f.targetIP, "}")
		c := f.collect(q)
		f.check("removed_member_not_promoted", fw4Verdict(q, c) == Unverified && !fw4Has(c, "routing.policy_selection"), true)
		f.nft("", "add", "element", "inet", "pinstest", "targets", "{", f.targetIP, "}")
	case "rpdb_classifier_path":
		q := f.question(nil, false)
		s := f.snapshot(q)
		n := normalizeOpenWrt(q, s)
		f.check("constant_mark_native_mask_path", n.markKnown && n.mark == 100 && n.routeSelected && f.routeDev(s) == "pins_path", false)
		f.run("", "ip", "rule", "add", "priority", "40", "from", f.sourceIP, "iif", "pins_edge", "fwmark", "101/255", "table", "200")
		s = f.snapshot(q)
		f.check("nonmatching_mask_rule_skipped", normalizeOpenWrt(q, s).routeSelected && f.routeDev(s) == "pins_path", true)
		f.run("", "ip", "rule", "del", "priority", "40")
		f.run("", "ip", "rule", "add", "priority", "50", "from", f.sourceIP, "iif", "pins_edge", "fwmark", "100/255", "table", "200")
		s = f.snapshot(q)
		selected, dev, known := owRoutePolicy(q, s, 100)
		f.check("earlier_rule_changes_prospective_path", known && selected && dev == "pins_other" && f.routeDev(s) == "pins_other", true)
		f.noComplete(f.collect(q))
		f.run("", "ip", "rule", "del", "priority", "50")
	case "forwarding_guard":
		f.traffic()
	case "negative_context":
		f.run("", "ip", "-n", "pins_mirror", "link", "add", "pins_edge", "type", "dummy")
		f.run("", "ip", "-n", "pins_mirror", "addr", "add", f.wrongIP+"/24", "dev", "pins_edge")
		f.run("", "ip", "-n", "pins_mirror", "link", "set", "pins_edge", "up")
		s := cloneBinding(Binding{OpenWrt: f.selectors()}).OpenWrt
		s.DestinationSet = nil
		f.table("pins_mirror", s)
		var devices []struct {
			Addresses []struct{ Local string } `json:"addr_info"`
		}
		f.check("mirror_native_state", json.Unmarshal(f.run("", "ip", "-j", "-n", "pins_mirror", "-4", "addr", "show", "dev", "pins_edge"), &devices) == nil && len(devices) == 1, false)
		matches, wrong := false, false
		for _, a := range devices[0].Addresses {
			matches = matches || a.Local == f.sourceGW
			wrong = wrong || a.Local == f.wrongIP
		}
		f.check("mirror_native_identity_differs", !matches && wrong, false)
		q := f.question(s, true)
		c := f.collect(q)
		f.check("system_ubus_not_foreign_binding_proof", !fw4Has(c, "gateway.interface_binding") && fw4Verdict(q, c) == Unverified, true)
	case "negative_expression":
		f.nft("", "add", "rule", "inet", "pinstest", "classify", "ip", "saddr", f.sourceIP, "iifname", "pins_edge", "ip", "daddr", f.targetIP, "ct", "mark", "set", "meta", "mark")
		q := f.question(nil, false)
		c := f.collect(q)
		f.check("ct_mark_expression_remains_unverified", fw4Verdict(q, c) == Unverified && !fw4Has(c, "gateway.policy_scope"), true)
		f.nft("", "flush", "chain", "inet", "pinstest", "classify")
		f.classifier()
	case "negative_uncalled_chain":
		f.nft("", "add", "chain", "inet", "pinstest", "unused")
		s := f.selectors()
		s.Chains = append(s.Chains, BoundChain{Family: "inet", Table: "pinstest", Chain: "unused", Role: "classifier"})
		q := f.question(s, false)
		f.check("uncalled_chain_remains_unverified", fw4Verdict(q, f.collect(q)) == Unverified, true)
	case "negative_unknown_override":
		f.nft("", "add", "table", "inet", "pinsunread")
		f.nft("", "add", "chain", "inet", "pinsunread", "earlier", "{", "type", "filter", "hook", "prerouting", "priority", "-170", ";", "policy", "accept", ";", "}")
		q := f.question(nil, false)
		c := f.collect(q)
		f.check("unknown_global_coverage_stays_partial", len(c.Capabilities) > 0 && c.Capabilities[0].Support == Partial, true)
		f.noComplete(c)
	case "negative_controls":
		// Progress aggregation only: never feeds unsigned checkpoints into the evaluator.
		for _, name := range []string{"negative_context", "negative_expression", "negative_uncalled_chain", "negative_unknown_override"} {
			raw, err := os.ReadFile(filepath.Join("/root/pins-fw4-checkpoints", name+".json"))
			var prior struct {
				Stage, Status string
				Source        string `json:"source_commit"`
				Assertions    map[string]bool
			}
			f.check("prior_negative_checkpoint_"+name, err == nil && json.Unmarshal(raw, &prior) == nil && prior.Stage == name && prior.Status == "PASS" && prior.Source == "214aad5" && len(prior.Assertions) > 0, false)
			for _, passed := range prior.Assertions {
				f.check("prior_assertions_"+name, passed, false)
			}
		}
	default:
		f.stop("unknown_stage", false)
	}
	f.report["status"] = "PASS"
	f.report["reason"] = "all_stage_assertions_passed"
}
