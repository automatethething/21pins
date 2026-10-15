package netpolicy

import (
	"path/filepath"
	"testing"
)

func testObjects(t *testing.T) (*Registry, Object, Object) {
	t.Helper()
	r := NewRegistry(filepath.Join(t.TempDir(), "private", "network-state.json"))
	source, e := r.Create(Object{Kind: Network, Alias: "trusted", Binding: Binding{Address: fixtureIP(2)}})
	if e != nil {
		t.Fatal(e)
	}
	service, e := r.Create(Object{Kind: Service, Alias: "dns", Binding: Binding{Target: fixtureIP(53), Port: 53, Realm: "private", Protocol: "dns"}})
	if e != nil {
		t.Fatal(e)
	}
	return r, source, service
}
func TestPolicyResolution(t *testing.T) {
	r, source, service := testObjects(t)
	tuple := Tuple{Source: source.Ref, Endpoint: service.Ref, Realm: "private", Family: "ipv4", Transport: "udp", Port: 53, Mode: "direct"}
	rule, e := r.PutPolicy(Rule{Alias: "allow-dns", Decision: "allow", Tuples: []Tuple{tuple}})
	if e != nil {
		t.Fatal(e)
	}
	resolved, e := r.ResolveTuples([]Tuple{tuple})
	if e != nil || len(resolved) != 1 || resolved[0].Policy != rule.Ref {
		t.Fatal("not resolved", e)
	}
	if _, e = r.PutPolicy(Rule{Alias: "overlap", Decision: "deny", Tuples: []Tuple{tuple}}); e == nil {
		t.Fatal("overlap accepted")
	}
	missing := tuple
	missing.Transport = "tcp"
	if _, e = r.ResolveTuples([]Tuple{missing}); e == nil {
		t.Fatal("scope hole accepted")
	}
	request := ObservationRequest{Operation: "access", Target: service.Ref, Source: source.Ref, Objects: []Ref{source.Ref, service.Ref}, Policies: []Ref{rule.Ref}, Tuples: []Tuple{tuple}, Required: []string{"response"}}
	a := request.Digest("network.read")
	r.Rename(Network, "trusted", "renamed")
	if request.Digest("network.read") != a {
		t.Fatal("alias changed digest")
	}
	request.Target.Revision++
	if request.Digest("network.read") == a {
		t.Fatal("binding substitution not bound")
	}
	tuple.Mode = "mediated"
	if _, e = r.ResolveTuples([]Tuple{tuple}); e == nil {
		t.Fatal("mediated scope silently narrowed")
	}
}
