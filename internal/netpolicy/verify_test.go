package netpolicy

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestFiniteProfiles(t *testing.T) {
	want := []string{"gateway.binding", "gateway.interface_binding", "gateway.reader", "gateway.policy_scope"}
	if !reflect.DeepEqual(Properties("gateway", Binding{}), want) {
		t.Fatal("gateway claim expanded")
	}
	vpn := []string{"vpn.binding", "vpn.peer_binding", "vpn.session_freshness", "vpn.route_ownership"}
	if !reflect.DeepEqual(Properties("vpn", Binding{}), vpn) {
		t.Fatal("vpn claim expanded")
	}
	with := Properties("vpn", Binding{RequirePath: true, FailClosed: true})
	if len(with) != 6 || with[4] != "vpn.path_selection" || with[5] != "vpn.fail_closed_guard" {
		t.Fatal("conditional requirements omitted")
	}
	now := time.Now()
	q := ObservationRequest{Operation: "gateway", Target: Ref{"net_fixture", 1}, Required: want}
	var facts []Fact
	for _, p := range want {
		facts = append(facts, newFact(p, q, nil, true, now, "runtime_validated"))
	}
	facts = append(facts, newFact("dns.denied", q, nil, false, now, "runtime_validated"))
	got := Evaluate(q, facts, now, true, false)
	if got.Verdict != Verified || len(got.Properties) != 4 {
		t.Fatal("unrelated access leak expanded gateway health claim")
	}
	q.Required = want[:1]
	if Evaluate(q, facts, now, true, false).Verdict != Unverified {
		t.Fatal("gateway profile silently narrowed")
	}
}
func TestEvaluate(t *testing.T) {
	now := time.Now()
	tuple := Tuple{Source: Ref{"net_source", 1}, Endpoint: Ref{"net_endpoint", 1}, Transport: "udp", Port: 53, Family: "ipv4", Mode: "direct"}
	q := ObservationRequest{Operation: "isolation", Target: tuple.Endpoint, Tuples: []Tuple{tuple}, Required: []string{"dns.control", "dns.denied", "isolation.baseline", "isolation.coverage", "isolation.boundary"}}
	var facts []Fact
	for _, p := range q.Required {
		facts = append(facts, newFact(p, q, &tuple, true, now, "runtime_validated"))
	}
	if Evaluate(q, facts, now, true, false).Verdict != Verified {
		t.Fatal("complete intentional deny rejected")
	}
	noBoundary := facts[:len(facts)-1]
	if Evaluate(q, noBoundary, now, true, false).Verdict != Unverified {
		t.Fatal("absence alone verified")
	}
	unrelated := append(append([]Fact(nil), noBoundary...), newFact("forwarding.permission", q, &tuple, true, now, "runtime_validated"))
	if Evaluate(q, unrelated, now, true, false).Verdict != Unverified {
		t.Fatal("forwarding became boundary")
	}
	leak := append(append([]Fact(nil), noBoundary...), newFact("dns.denied", q, &tuple, false, now, "runtime_validated"))
	if Evaluate(q, leak, now, true, false).Verdict != Violated {
		t.Fatal("leak not prioritized")
	}
	if Evaluate(q, facts, now, false, false).Verdict != Unverified {
		t.Fatal("cleanup failure passed")
	}
	stale := append([]Fact(nil), facts...)
	stale[0].ValidUntil = now.Add(-time.Second)
	if Evaluate(q, stale, now, true, false).Verdict != Unverified {
		t.Fatal("stale scope passed")
	}
}
func TestAssessmentReceipt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "receipts")
	a := Assessment{ID: "nver_fixture", Verdict: Unverified, Cleanup: true, CreatedAt: time.Now()}
	if e := SaveAssessment(dir, a); e != nil {
		t.Fatal(e)
	}
	if e := SaveAssessment(dir, a); e == nil {
		t.Fatal("immutable receipt overwritten")
	}
	got, e := ReadAssessment(dir, a.ID)
	if e != nil || got.Verdict != Unverified {
		t.Fatal("cannot read receipt", e)
	}
	if _, e = ReadAssessment(dir, "../escape"); e == nil {
		t.Fatal("traversal receipt")
	}
}
