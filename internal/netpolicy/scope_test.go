package netpolicy

import (
	"testing"
)

func TestAmbiguousSourceMembershipIsNotAProof(t *testing.T) {
	r, source, _ := testObjects(t)
	b := source.Binding
	b.Context = "ctx_shared"
	b.Namespace = "same-source"
	if _, e := r.Rebind(Network, source.Ref.ID, b); e != nil {
		t.Fatal(e)
	}
	_, e := r.Create(Object{Kind: Network, Alias: "other-source", Binding: b})
	if e != nil {
		if e == ErrConflict {
			return
		}
		t.Fatal(e)
	}
	if _, e = r.Question("access", "dns", "trusted", nil); e != ErrConflict {
		t.Fatal("duplicate actual source membership accepted", e)
	}
}

func TestPolicyInvalidMatchingRevisionDoesNotDisappear(t *testing.T) {
	r, source, service := testObjects(t)
	tuple := Tuple{Source: source.Ref, Endpoint: service.Ref, Realm: "private", Family: "ipv4", Transport: "udp", Port: 53, Mode: "direct"}
	rule, e := r.PutPolicy(Rule{Alias: "allow-dns", Decision: "allow", Tuples: []Tuple{tuple}})
	if e != nil {
		t.Fatal(e)
	}
	state, e := r.load()
	if e != nil {
		t.Fatal(e)
	}
	bad := rule
	bad.Ref = Ref{"npol_bad", 1}
	bad.Alias = "conflicting"
	bad.Path = Ref{"net_missing", 1}
	state.Policies = append(state.Policies, bad)
	if e = atomicJSON(r.Path, state); e != nil {
		t.Fatal(e)
	}
	if _, e = r.ResolveTuples([]Tuple{tuple}); e == nil {
		t.Fatal("invalid matching declaration silently ignored")
	}
}
func TestNetworkDeclaredMediatedScopeNotDropped(t *testing.T) {
	r, source, service := testObjects(t)
	b := service.Binding
	b.Transports = []string{"udp"}
	b.AccessModes = []string{"direct", "mediated"}
	service, e := r.Rebind(Service, service.Ref.ID, b)
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range b.AccessModes {
		_, e = r.PutPolicy(Rule{Alias: "allow-" + mode, Decision: "allow", Tuples: []Tuple{{Source: source.Ref, Endpoint: service.Ref, Realm: "private", Family: "ipv4", Transport: "udp", Port: 53, Mode: mode}}})
		if e != nil {
			t.Fatal(e)
		}
	}
	q, e := r.Question("access", "dns", "trusted", nil)
	if e != nil || len(q.Request.Tuples) != 2 {
		t.Fatal("declared mediated scope silently omitted", e)
	}
}
