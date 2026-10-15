package netpolicy

import (
	"testing"
	"time"
)

func TestBaselineSelectionRetainsExactValidatedRecord(t *testing.T) {
	now := time.Now().UTC()
	source, guest, endpoint := Ref{"net_trusted", 1}, Ref{"net_guest", 1}, Ref{"net_dns", 1}
	tuple := Tuple{Source: source, Endpoint: endpoint, Realm: "realm_private", Family: "ipv4", Transport: "udp", Port: 53, Mode: "direct"}
	request := ObservationRequest{Operation: "access", Target: endpoint, Source: source, Objects: []Ref{source, endpoint}}
	good := newFact("dns.response", request, &tuple, true, now.Add(-time.Minute), "runtime_validated")
	good.RuntimeBinding = "binding"
	good.WindowStart = good.ObservedAt.Add(-time.Second)
	good.WindowEnd = good.ObservedAt
	bad := good
	bad.ID = "invalid-first"
	badTuple := tuple
	badTuple.Family = "ipv6"
	bad.Tuple = &badTuple
	bad.WindowStart = now.Add(-time.Hour)
	a := Assessment{ID: "nver_baseline", Request: request, Verdict: Verified, Cleanup: true, CreatedAt: now.Add(-time.Minute), Evidence: []Fact{bad, good}}
	q := Question{Service: Object{Ref: endpoint}}
	denied := tuple
	denied.Source = guest
	selected, ok := baselineObservation(&a, q, denied, now, "binding", false)
	if !ok || selected.ID != good.ID || !selected.WindowStart.Equal(good.WindowStart) || !selected.ObservedAt.Equal(good.ObservedAt) {
		t.Fatal("copied unvalidated lookalike or refreshed observation")
	}
}
