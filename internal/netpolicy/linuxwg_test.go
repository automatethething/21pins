package netpolicy

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestLinuxPolicyNormalization(t *testing.T) {
	source, target := fixtureIP(2), fixtureIP(53)
	raw := fmt.Sprintf(`{"nftables":[{"chain":{"family":"inet","table":"test","name":"guard"}},{"rule":{"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":%q}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":%q}},{"drop":null}]}}]}`, source, target)
	p := normalizeNFT([]byte(raw), target)
	if !p.supported || !p.denied[source] {
		t.Fatal("source-scoped guard not normalized")
	}
	var body map[string]any
	json.Unmarshal([]byte(raw), &body)
	body["nftables"] = append(body["nftables"].([]any), map[string]any{"rule": map[string]any{"expr": []any{map[string]any{"jump": map[string]any{"target": "unknown"}}}}})
	bad, _ := json.Marshal(body)
	if normalizeNFT(bad, target).supported {
		t.Fatal("unparsed override ignored")
	}
	if normalizeNFT([]byte(`{"nftables":[]}`), target).supported {
		t.Fatal("empty output supported")
	}
}
func TestWireGuardNormalization(t *testing.T) {
	now := time.Now()
	peer := "fixture-peer"
	allowed := peer + "\t" + fixtureIP(53) + "/32\nother-peer\t" + fixtureIP(70) + "/32\n"
	if !peerOwns([]byte(allowed), peer, fixtureIP(53)) || peerOwns([]byte(allowed), peer, fixtureIP(70)) {
		t.Fatal("unbound peer path accepted")
	}
	at, ok := peerHandshake([]byte(fmt.Sprintf("%s\t%d\n", peer, now.Unix())), peer)
	if !ok || now.Sub(at) > time.Second {
		t.Fatal("handshake missing")
	}
	if _, ok = peerHandshake([]byte("other-peer\t1\n"), peer); ok {
		t.Fatal("other peer bound")
	}
}
