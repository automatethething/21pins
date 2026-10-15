package netpolicy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEvidenceBindingAndPrivacy(t *testing.T) {
	now := time.Now()
	q := ObservationRequest{Target: Ref{"net_fixture", 1}, Objects: []Ref{{"net_fixture", 1}}}
	f := newFact("gateway.binding", q, nil, true, now, "runtime_validated")
	if !validFact(f, q, now, false) {
		t.Fatal("valid scoped fact rejected")
	}
	f.ValidUntil = now.Add(-time.Second)
	if validFact(f, q, now, false) {
		t.Fatal("stale fact")
	}
	f = newFact("gateway.binding", q, nil, true, now, "runtime_validated")
	changed := q
	changed.Target.Revision++
	if validFact(f, changed, now, false) {
		t.Fatal("substituted target")
	}
	encoded, _ := json.Marshal(f)
	var imported Fact
	if json.Unmarshal(encoded, &imported) != nil {
		t.Fatal("decode")
	}
	if validFact(imported, q, now, false) {
		t.Fatal("JSON self-promoted runtime provenance")
	}
	fixture := newFact("gateway.binding", q, nil, true, now, "synthetic_runtime")
	if validFact(fixture, q, now, false) || !validFact(fixture, q, now, true) {
		t.Fatal("fixture upgraded production evidence")
	}
	object := Object{Kind: Service, Alias: "public-docs", Ref: q.Target, Binding: Binding{Target: fixtureIP(53), Peer: "SENSITIVE_KEY", Context: "PRIVATE_TOPOLOGY"}}
	safe, _ := json.Marshal(InspectObject(object))
	for _, protectedValue := range []string{fixtureIP(53), "SENSITIVE_KEY", "PRIVATE_TOPOLOGY"} {
		if strings.Contains(string(safe), protectedValue) {
			t.Fatal("endpoint/key/topology displayed")
		}
	}
	if strings.Contains(string(safe), "confirmed_public") {
		t.Fatal("unreachable confirmation state")
	}
}
