package netpolicy

import (
	"encoding/json"
	"testing"
)

func TestLinuxPolicyOrderAndAmbiguity(t *testing.T) {
	source, target := fixtureIP(2), fixtureIP(53)
	match := func(field, value string) any {
		return map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "ip", "field": field}}, "right": value}}
	}
	rule := func(action string) map[string]any {
		return map[string]any{"rule": map[string]any{"expr": []any{match("saddr", source), match("daddr", target), map[string]any{action: nil}}}}
	}
	encode := func(entries ...any) []byte {
		body := []any{map[string]any{"chain": map[string]any{"hook": "forward"}}}
		body = append(body, entries...)
		raw, _ := json.Marshal(map[string]any{"nftables": body})
		return raw
	}
	p := normalizeNFT(encode(rule("accept"), rule("drop")), target)
	if !p.supported || p.denied[source] {
		t.Fatal("unreachable drop became causal guard")
	}
	global := map[string]any{"rule": map[string]any{"expr": []any{map[string]any{"accept": nil}}}}
	if normalizeNFT(encode(global, rule("drop")), target).supported {
		t.Fatal("global override silently skipped")
	}
	duplicate := map[string]any{"rule": map[string]any{"expr": []any{match("saddr", fixtureIP(3)), match("saddr", source), match("daddr", target), map[string]any{"drop": nil}}}}
	if normalizeNFT(encode(duplicate), target).supported {
		t.Fatal("conflicting selectors became guard")
	}
}
