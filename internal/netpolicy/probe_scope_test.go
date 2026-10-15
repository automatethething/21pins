package netpolicy

import "testing"

func TestDNSProbeScopeCannotAggregateDifferentAttempts(t *testing.T) {
	q := Question{Source: Object{Ref: Ref{"net_source", 1}}, Service: Object{Ref: Ref{"net_endpoint", 1}, Binding: Binding{Target: fixtureIP(53), Port: 53, Realm: "private"}}}
	q.Request.Target = q.Service.Ref
	tuple := Tuple{Source: q.Source.Ref, Endpoint: q.Service.Ref, Realm: "realm_" + hashJSON(struct {
		Endpoint Ref
		Name     string
	}{q.Service.Ref, q.Service.Binding.Realm}), Family: "ipv4", Transport: "udp", Port: 53, Mode: "direct"}
	q.Request.Tuples = []Tuple{tuple}
	if e := validateProbeScopes(q); e != nil {
		t.Fatal(e)
	}
	second := tuple
	second.Family = "ipv6"
	q.Request.Tuples = append(q.Request.Tuples, second)
	if validateProbeScopes(q) == nil {
		t.Fatal("cross-family same-transport attribution accepted")
	}
	q.Request.Tuples = []Tuple{tuple, tuple}
	if validateProbeScopes(q) == nil {
		t.Fatal("multiple same-transport attempts accepted")
	}
	q.Request.Tuples = []Tuple{tuple}
	q.Control = q.Service
	if validateProbeScopes(q) == nil {
		t.Fatal("control aliases protected endpoint")
	}
}
