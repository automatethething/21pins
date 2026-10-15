package netpolicy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func owPriority(n int32) *int32 { return &n }
func owSelectors() *OpenWrtBinding {
	return &OpenWrtBinding{LogicalNetwork: "home", Profile: "gl-policy-fw4", Chains: []BoundChain{{Family: "inet", Table: "fixture", Chain: "classify", Role: "classifier", Hook: "prerouting", Priority: owPriority(-150)}, {Family: "inet", Table: "fixture", Chain: "forward", Role: "forwarding", Hook: "forward", Priority: owPriority(0)}, {Family: "inet", Table: "fixture", Chain: "guard", Role: "guard", Hook: "forward", Priority: owPriority(10)}}, DestinationSet: &BoundSet{Family: "inet", Table: "fixture", Name: "destinations", ElementFamily: "ipv4"}, StoredSections: []string{"home_to_uplink"}}
}
func owJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func owMatch(field, op string, value any) map[string]any {
	left := map[string]any{"payload": map[string]any{"protocol": "ip", "field": field}}
	if field == "iifname" || field == "oifname" {
		left = map[string]any{"meta": map[string]any{"key": field}}
	}
	return map[string]any{"match": map[string]any{"op": op, "left": left, "right": value}}
}
func owRule(action string, value any) []map[string]any {
	expr := []map[string]any{owMatch("saddr", "==", fixtureIP(2)), owMatch("iifname", "==", "edge0"), owMatch("daddr", "==", fixtureIP(53))}
	return append(expr, map[string]any{action: value})
}
func owChain(c BoundChain, rules ...[]map[string]any) []byte {
	meta := map[string]any{"family": c.Family, "table": c.Table, "name": c.Chain}
	if c.Hook != "" {
		meta["hook"] = c.Hook
		meta["prio"] = *c.Priority
		meta["type"] = "filter"
		meta["policy"] = "accept"
	}
	entries := []any{map[string]any{"chain": meta}}
	for _, expr := range rules {
		entries = append(entries, map[string]any{"rule": map[string]any{"family": c.Family, "table": c.Table, "chain": c.Chain, "expr": expr}})
	}
	return owJSON(map[string]any{"nftables": entries})
}
func owFixture() (Question, openWrtSnapshot) {
	gateway := Object{Ref: Ref{"net_gateway", 1}, Kind: Gateway, Alias: "router", Binding: Binding{Context: "ctx_fixture", Interface: "edge0", Address: fixtureIP(1), Target: fixtureIP(53), OpenWrt: owSelectors()}}
	source := Object{Ref: Ref{"net_source", 1}, Kind: Network, Alias: "home", Binding: Binding{Context: "ctx_client", Address: fixtureIP(2), Ingress: "edge0", OpenWrt: &OpenWrtBinding{LogicalNetwork: "home"}, Gateway: gateway.Ref}}
	q := Question{Gateway: gateway, Target: gateway, Source: source, VPN: Object{Ref: Ref{"net_vpn", 1}, Kind: VPN, Binding: Binding{Interface: "tunnel0", Context: gateway.Binding.Context, Namespace: gateway.Binding.Namespace, Gateway: gateway.Ref}}}
	q.Request = ObservationRequest{Operation: "gateway", Target: gateway.Ref, Objects: []Ref{gateway.Ref, source.Ref, q.VPN.Ref}, Required: Properties("gateway", Binding{}), MetadataDigest: "fixture"}
	s := openWrtSnapshot{scope: openWrtScope(q), context: gateway.Binding.Context, start: time.Now().UTC().Add(-time.Second), end: time.Now().UTC(), chains: map[string][]byte{}, stored: map[string]string{"home_to_uplink.enabled": "0"}, setKnown: true, setMember: true, closed: true, synthetic: true}
	s.logical = owJSON(map[string]any{"up": true, "l3_device": "edge0", "ipv4-address": []any{map[string]any{"address": fixtureIP(1), "mask": 24}}})
	s.set = owJSON(map[string]any{"nftables": []any{map[string]any{"set": map[string]any{"family": "inet", "table": "fixture", "name": "destinations", "type": "ipv4_addr"}}}})
	for _, c := range gateway.Binding.OpenWrt.Chains {
		expr := owRule("accept", nil)
		switch c.Role {
		case "classifier":
			expr = owRule("mangle", map[string]any{"key": map[string]any{"meta": map[string]any{"key": "mark"}}, "value": 100})
			expr[2] = owMatch("daddr", "==", "@destinations")
		case "guard":
			expr = owRule("drop", nil)
			expr = append(expr[:3], owMatch("oifname", "!=", "tunnel0"), map[string]any{"drop": nil})
		}
		s.chains[openWrtChainKey(c)] = owChain(c, expr)
	}
	s.rules = owJSON([]any{map[string]any{"priority": 0, "src": "all", "table": "local"}, map[string]any{"priority": 100, "src": fixtureIP(2), "iif": "edge0", "fwmark": "0x64", "fwmask": "0xff", "table": 100}, map[string]any{"priority": 32766, "src": "all", "table": "main"}})
	s.route = owJSON([]any{map[string]any{"dev": "tunnel0", "table": 100}})
	return q, s
}
func TestOpenWrtNormalize(t *testing.T) {
	q, s := owFixture()
	n := normalizeOpenWrt(q, s)
	if !n.logical || !n.sourceLogical || !n.markKnown || n.mark != 100 || !n.routeSelected || n.forwarding == nil || !*n.forwarding || !n.guardCandidate || !n.coverage {
		t.Fatalf("supported finite fixture not normalized: %v", n.missing)
	}
	if n.runtimeDigest == n.storedDigest {
		t.Fatal("stored/runtime conflated")
	}
	for _, tc := range []struct {
		name   string
		change func(*Question, *openWrtSnapshot)
		check  func(openWrtEvidence) bool
	}{
		{"forwarding_not_path", func(_ *Question, s *openWrtSnapshot) {
			s.route = owJSON([]any{map[string]any{"dev": "uplink0", "table": 100}})
		}, func(n openWrtEvidence) bool {
			return n.forwarding != nil && *n.forwarding && !n.vpnSelected && n.guardCandidate
		}},
		{"unknown_coverage", func(_ *Question, s *openWrtSnapshot) { s.closed = false }, func(n openWrtEvidence) bool { return !n.coverage }},
		{"precedence_override", func(_ *Question, s *openWrtSnapshot) { s.rules = []byte(`[{"priority":1,"src":"all","goto":42}]`) }, func(n openWrtEvidence) bool { return !n.routeSelected && !n.coverage }},
		{"wrong_source", func(q *Question, _ *openWrtSnapshot) { q.Source.Binding.Address = fixtureIP(9) }, func(n openWrtEvidence) bool { return !n.markKnown && !n.coverage }},
		{"stale", func(_ *Question, s *openWrtSnapshot) { s.end = time.Now().Add(-time.Hour) }, func(n openWrtEvidence) bool { return !n.logical }},
		{"wrong_device", func(_ *Question, s *openWrtSnapshot) { s.logical = []byte(`{"up":true,"l3_device":"other"}`) }, func(n openWrtEvidence) bool { return !n.logical }},
		{"fw3", func(q *Question, s *openWrtSnapshot) {
			q.Gateway.Binding.OpenWrt.Profile = "fw3"
			s.scope = openWrtScope(*q)
		}, func(n openWrtEvidence) bool { return !n.markKnown && !n.coverage }},
		{"unknown_set", func(_ *Question, s *openWrtSnapshot) { s.setKnown = false }, func(n openWrtEvidence) bool { return !n.markKnown && !n.coverage }},
		{"set_nonmember", func(_ *Question, s *openWrtSnapshot) { s.setMember = false }, func(n openWrtEvidence) bool { return !n.markKnown && !n.routeSelected }},
		{"import_has_no_runtime_seal", func(_ *Question, s *openWrtSnapshot) { s.runtime = false }, func(n openWrtEvidence) bool { return !n.runtime }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, s := owFixture()
			tc.change(&q, &s)
			n := normalizeOpenWrt(q, s)
			if !tc.check(n) {
				t.Fatal("unsupported/contradictory scope promoted", n.missing)
			}
		})
	}
	for _, kind := range []string{"uncalled", "wrong_hook", "unknown_action", "action_before_match", "masked_mark", "earlier_accept"} {
		t.Run(kind, func(t *testing.T) {
			q, s := owFixture()
			for i, c := range q.Gateway.Binding.OpenWrt.Chains {
				if c.Role != "classifier" {
					continue
				}
				expr := owRule("mangle", map[string]any{"key": map[string]any{"meta": map[string]any{"key": "mark"}}, "value": 100})
				switch kind {
				case "uncalled":
					c.Hook = ""
					c.Priority = nil
					q.Gateway.Binding.OpenWrt.Chains[i] = c
				case "wrong_hook":
					c.Hook = "output"
					q.Gateway.Binding.OpenWrt.Chains[i] = c
				case "unknown_action":
					expr = append(expr, map[string]any{"flow": map[string]any{}})
				case "action_before_match":
					expr[0], expr[3] = expr[3], expr[0]
				case "masked_mark":
					expr[3] = map[string]any{"mangle": map[string]any{"key": map[string]any{"meta": map[string]any{"key": "mark"}}, "value": map[string]any{"&": []any{1, 2}}}}
				case "earlier_accept":
					s.chains[openWrtChainKey(c)] = owChain(c, owRule("accept", nil), expr)
					continue
				}
				s.chains[openWrtChainKey(c)] = owChain(c, expr)
			}
			s.scope = openWrtScope(q)
			n := normalizeOpenWrt(q, s)
			if n.markKnown || n.coverage {
				t.Fatal("unreachable/unsupported classifier became effective")
			}
		})
	}
}

func TestOpenWrtNormalizeScopeAndReachability(t *testing.T) {
	q, s := owFixture()
	original := openWrtScope(q)
	q.Gateway.Alias = "renamed"
	q.Source.Alias = "renamed_source"
	q.Target.Alias = "renamed_target"
	if openWrtScope(q) != original {
		t.Fatal("friendly aliases entered native authority scope")
	}
	q, s = owFixture()
	s.rules = []byte(`[{"priority":100,"src":["malformed"],"fwmark":100,"table":100}]`)
	if normalizeOpenWrt(q, s).routeSelected {
		t.Fatal("malformed source selector treated as all")
	}
	q, s = owFixture()
	for i, c := range q.Gateway.Binding.OpenWrt.Chains {
		if c.Role != "classifier" {
			continue
		}
		child := c
		child.Chain = "regular"
		child.Hook = ""
		child.Priority = nil
		q.Gateway.Binding.OpenWrt.Chains = append(q.Gateway.Binding.OpenWrt.Chains, child)
		s.chains[openWrtChainKey(child)] = s.chains[openWrtChainKey(c)]
		s.chains[openWrtChainKey(child)] = owChain(child, owRule("mangle", map[string]any{"key": map[string]any{"meta": map[string]any{"key": "mark"}}, "value": 100}))
		s.chains[openWrtChainKey(c)] = owChain(c, []map[string]any{{"jump": map[string]any{"target": "regular"}}})
		_ = i
		break
	}
	s.scope = openWrtScope(q)
	if n := normalizeOpenWrt(q, s); !n.coverage || !n.markKnown {
		t.Fatal("modeled reachable regular classifier rejected", n.missing)
	}
	q, s = owFixture()
	d := openWrtRuntimeDigest(s)
	s.stored["home_to_uplink.enabled"] = "1"
	if openWrtRuntimeDigest(s) != d || !normalizeOpenWrt(q, s).guardCandidate {
		t.Fatal("stored configuration became runtime authority")
	}
}

func owFixtureRead(q Question, s openWrtSnapshot, calls *int) func(context.Context, Binding, string, ...string) ([]byte, error) {
	return func(ctx context.Context, b Binding, tool string, args ...string) ([]byte, error) {
		*calls++
		if b.Context != q.Gateway.Binding.Context {
			return nil, ErrStale
		}
		switch tool {
		case "ubus":
			return s.logical, nil
		case "uci":
			if strings.HasSuffix(args[len(args)-1], ".device") {
				return []byte("edge0"), nil
			}
			return []byte("0"), nil
		case "ip":
			if args[2] == "rule" {
				return s.rules, nil
			}
			return s.route, nil
		case "nft":
			for _, a := range args {
				if a == "get" {
					set := q.Gateway.Binding.OpenWrt.DestinationSet
					return owJSON(map[string]any{"nftables": []any{map[string]any{"element": map[string]any{"family": set.Family, "table": set.Table, "name": set.Name, "elem": []string{q.Gateway.Binding.Target}}}}}), nil
				}
			}
			for _, c := range q.Gateway.Binding.OpenWrt.Chains {
				if args[len(args)-1] == c.Chain {
					return s.chains[openWrtChainKey(c)], nil
				}
			}
			return s.set, nil
		}
		return nil, ErrUnsupported
	}
}
func TestOpenWrtRelatedVPNBinding(t *testing.T) {
	r, _, _ := testObjects(t)
	objects := []Object{{Kind: Gateway, Alias: "edge", Binding: Binding{Context: "ctx_router", OpenWrt: owSelectors(), VPN: Ref{ID: "link"}}}, {Kind: VPN, Alias: "link", Binding: Binding{Protocol: "wireguard", Context: "ctx_router", Interface: "tunnel0", Gateway: Ref{ID: "edge"}}}}
	raw := owJSON(map[string]any{"objects": objects})
	if e := r.Import(strings.NewReader(string(raw))); e != nil {
		t.Fatal(e)
	}
	question, e := r.Question("gateway", "edge", "", nil)
	if e != nil || question.VPN.Alias != "link" {
		t.Fatal("registered VPN context not resolved", e)
	}
	q, s := owFixture()
	q.VPN.Binding.Context = "ctx_other"
	s.scope = openWrtScope(q)
	n := normalizeOpenWrt(q, s)
	if n.guardCandidate || n.vpnSelected {
		t.Fatal("other namespace VPN became protected-path/guard identity")
	}
}

func TestOpenWrtScalarMemberNativeSyntax(t *testing.T) {
	q, _ := owFixture()
	raw := "table inet fixture { set destinations { type ipv4_addr elements = { " + q.Gateway.Binding.Target + " } } }"
	if !owMember(q, []byte(raw)) {
		t.Fatal("successful scoped native scalar element reply rejected")
	}
	for _, bad := range []string{strings.Replace(raw, "destinations", "other", 1), strings.Replace(raw, "ipv4_addr", "ipv6_addr", 1), strings.Replace(raw, " } } }", ", extra } } }", 1), raw + " trailing"} {
		if owMember(q, []byte(bad)) {
			t.Fatal("ambiguous/unbound element reply accepted")
		}
	}
}
func TestOpenWrtReadCanceledResultCannotBecomeEvidence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	session := owReadSession{ctx: ctx, permit: func(context.Context, string) error { return nil }, read: func(context.Context, Binding, string, ...string) ([]byte, error) { cancel(); return []byte(`{}`), nil }}
	if _, e := session.call("ubus", "call", "network.interface.home", "status"); e == nil {
		t.Fatal("canceled native result accepted")
	}
}
func TestOpenWrtReadBoundary(t *testing.T) {
	q, s := owFixture()
	sealOpenWrtQuestion(&q)
	calls, permits := 0, 0
	read := owFixtureRead(q, s, &calls)
	permit := func(context.Context, string) error { permits++; return nil }
	snap, e := readOpenWrtSnapshot(context.Background(), q, permit, read)
	if e != nil {
		t.Fatal(e)
	}
	if snap.runtime {
		t.Fatal("injectable reader helper minted runtime seal")
	}
	if permits != calls || calls > 32 || calls < 10 {
		t.Fatal("read admission/count bounds")
	}
	if n := normalizeOpenWrt(q, snap); !n.markKnown || !n.routeSelected {
		t.Fatal("fixed reads failed to normalize", n.missing)
	}
	calls = 0
	_, e = readOpenWrtSnapshot(context.Background(), q, func(context.Context, string) error { return ErrMissing }, read)
	if e == nil || calls != 0 {
		t.Fatal("native read before admission")
	}
	calls = 0
	permits = 0
	_, e = readOpenWrtSnapshot(context.Background(), q, func(context.Context, string) error {
		permits++
		if permits == 3 {
			return ErrMissing
		}
		return nil
	}, read)
	if e == nil || calls != 2 {
		t.Fatal("revocation did not stop subsequent reads")
	}
	calls = 0
	_, e = readOpenWrtSnapshot(context.Background(), q, permit, func(context.Context, Binding, string, ...string) ([]byte, error) {
		calls++
		return make([]byte, 65537), nil
	})
	if e == nil || calls != 1 {
		t.Fatal("oversized native output not bounded")
	}
	q, s = owFixture()
	sealOpenWrtQuestion(&q)
	calls = 0
	beforeMutation, _ := freezeOpenWrtQuestion(q)
	original := beforeMutation.Gateway.Binding.OpenWrt.Chains[0].Chain
	q.Gateway.Binding.OpenWrt.Chains[0].Chain = "caller_changed"
	fixed, _ := freezeOpenWrtQuestion(q)
	_, e = readOpenWrtSnapshot(context.Background(), q, permit, owFixtureRead(fixed, s, &calls))
	if e != nil || fixed.Gateway.Binding.OpenWrt.Chains[0].Chain != original {
		t.Fatal("caller mutation altered admitted reads", e)
	}
	q, s = owFixture()
	sealOpenWrtQuestion(&q)
	calls = 0
	read = owFixtureRead(q, s, &calls)
	changed := false
	_, e = readOpenWrtSnapshot(context.Background(), q, permit, func(c context.Context, b Binding, tool string, args ...string) ([]byte, error) {
		if calls > 8 && !changed && tool == "ip" && args[2] == "route" {
			changed = true
			calls++
			return owJSON([]any{map[string]any{"dev": "changed", "table": 100}}), nil
		}
		return read(c, b, tool, args...)
	})
	if e == nil {
		t.Fatal("mixed runtime samples accepted")
	}
	q, s = owFixture()
	q.Gateway.Binding.OpenWrt.StoredSections = []string{"one", "two", "three", "four", "five", "six", "seven", "eight"}
	sealOpenWrtQuestion(&q)
	calls = 0
	_, e = readOpenWrtSnapshot(context.Background(), q, permit, owFixtureRead(q, s, &calls))
	if e == nil || calls != 0 {
		t.Fatal("oversized read plan not rejected before execution")
	}
	q, s = owFixture()
	sealOpenWrtQuestion(&q)
	q.Request.MetadataDigest = "substituted"
	calls = 0
	_, e = readOpenWrtSnapshot(context.Background(), q, permit, owFixtureRead(q, s, &calls))
	if e == nil || calls != 0 {
		t.Fatal("substituted digest read native state")
	}
	q, s = owFixture()
	q.Gateway.Binding.OpenWrt.Profile = "fw3"
	sealOpenWrtQuestion(&q)
	calls = 0
	_, e = readOpenWrtSnapshot(context.Background(), q, permit, owFixtureRead(q, s, &calls))
	if e == nil || calls != 0 {
		t.Fatal("unsupported backend collected as supported")
	}
}

func TestOpenWrtBindingScope(t *testing.T) {
	legacy := Binding{Interface: "edge0"}
	raw, _ := json.Marshal(legacy)
	if strings.Contains(string(raw), "openwrt") {
		t.Fatal("omitted selector changed legacy JSON")
	}
	r, _, _ := testObjects(t)
	selectors := owSelectors()
	gateway, e := r.Create(Object{Kind: Gateway, Alias: "edge", Binding: Binding{OpenWrt: selectors}})
	if e != nil {
		t.Fatal(e)
	}
	q, e := r.Question("gateway", "edge", "", nil)
	if e != nil {
		t.Fatal(e)
	}
	digest := q.Request.Digest("network.read")
	selectors.Chains[0].Chain = "caller_mutated"
	*selectors.Chains[0].Priority = 99
	selectors.DestinationSet.Name = "caller_mutated"
	selectors.StoredSections[0] = "caller_mutated"
	gateway.Binding.OpenWrt.Chains[0].Chain = "return_mutated"
	again, e := r.Question("gateway", "edge", "", nil)
	if e != nil || again.Request.Digest("network.read") != digest {
		t.Fatal("mutable input/return changed authority")
	}
	expectedChain := q.Gateway.Binding.OpenWrt.Chains[0].Chain
	q.Gateway.Binding.OpenWrt.Chains[0].Chain = "question_mutated"
	frozen, e := freezeOpenWrtQuestion(q)
	if e != nil || frozen.Gateway.Binding.OpenWrt.Chains[0].Chain != expectedChain {
		t.Fatal("question exposed mutable read scope")
	}
	r.Rename(Gateway, "edge", "renamed")
	renamed, e := r.Question("gateway", "renamed", "", nil)
	if e != nil || renamed.Request.Digest("network.read") != digest {
		t.Fatal("friendly rename changed authority")
	}
	binding := renamed.Gateway.Binding
	binding.OpenWrt.Chains[0].Priority = owPriority(-149)
	r.Rebind(Gateway, "renamed", binding)
	rebound, e := r.Question("gateway", "renamed", "", nil)
	if e != nil || rebound.Request.Digest("network.read") == digest {
		t.Fatal("rebind failed to invalidate scope")
	}
	for _, mutate := range []func(*OpenWrtBinding){func(s *OpenWrtBinding) { s.Chains[0].Chain = "bad;command" }, func(s *OpenWrtBinding) { s.Chains = append(s.Chains, s.Chains[0]) }, func(s *OpenWrtBinding) { s.Chains[0].Priority = nil }, func(s *OpenWrtBinding) { s.DestinationSet.ElementFamily = "ipv6"; s.DestinationSet.Family = "ip" }, func(s *OpenWrtBinding) { s.StoredSections = []string{"../secret"} }} {
		s := owSelectors()
		mutate(s)
		if _, e := r.Create(Object{Kind: Gateway, Alias: "bad", Binding: Binding{OpenWrt: s}}); e == nil {
			t.Fatal("unsafe selector accepted")
		}
	}
	if _, e = r.Create(Object{Kind: Service, Alias: "invalid", Binding: Binding{Target: fixtureIP(53), Port: 53, Realm: "private", OpenWrt: owSelectors()}}); e == nil {
		t.Fatal("kind scope broadened")
	}
	if e = r.Import(strings.NewReader(`{"objects":[{"kind":"network_gateway","alias":"forged","binding":{"openwrt":{"closed":true}}}]}`)); e == nil {
		t.Fatal("imported closure bit accepted")
	}
}
