package netpolicy

import (
	"testing"
	"time"
)

func TestSessionFactExpiresAtNativeFreshnessDeadline(t *testing.T) {
	now := time.Now().UTC()
	at := now.Add(-120 * time.Second)
	q := Question{Request: ObservationRequest{Target: Ref{"net_vpn", 1}}}
	fact := newCollector(nil).sessionFact(q, at, now)
	if !fact.Value || !fact.ValidUntil.Equal(at.Add(180*time.Second)) || validFact(fact, q.Request, at.Add(181*time.Second), false) {
		t.Fatal("native session freshness was extended by generic evidence lifetime")
	}
}
