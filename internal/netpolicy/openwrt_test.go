package netpolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

func owPriority(n int32) *int32 { return &n }
func owSelectors() *OpenWrtBinding {
	return &OpenWrtBinding{LogicalNetwork: "home", Profile: "gl-policy-fw4", Chains: []BoundChain{{Family: "inet", Table: "fixture", Chain: "classify", Role: "classifier", Hook: "prerouting", Priority: owPriority(-150)}, {Family: "inet", Table: "fixture", Chain: "forward", Role: "forwarding", Hook: "forward", Priority: owPriority(0)}, {Family: "inet", Table: "fixture", Chain: "guard", Role: "guard", Hook: "forward", Priority: owPriority(10)}}, DestinationSet: &BoundSet{Family: "inet", Table: "fixture", Name: "destinations", ElementFamily: "ipv4"}, StoredSections: []string{"home_to_uplink"}}
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
