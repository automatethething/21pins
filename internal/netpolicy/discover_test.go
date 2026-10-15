package netpolicy

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestDiscoverIsPassive(t *testing.T) {
	r, _, _ := testObjects(t)
	r.Create(Object{Kind: VPN, Alias: "wireguard-vpn", Binding: Binding{Protocol: "wireguard"}})
	before, _ := os.ReadFile(r.Path)
	calls := 0
	candidates, e := Discover(r, func(name string) bool { calls++; return name == "wg" })
	if e != nil {
		t.Fatal(e)
	}
	if calls != 2 || len(candidates) != 4 {
		t.Fatal("unbounded discovery or lost candidates")
	}
	if candidates[len(candidates)-1].Name != "wireguard-vpn-2" || candidates[len(candidates)-1].Registered {
		t.Fatal("candidate auto-enrolled/collision")
	}
	after, _ := os.ReadFile(r.Path)
	if !bytes.Equal(before, after) {
		t.Fatal("discovery writes")
	}
	encoded, _ := json.Marshal(candidates)
	if bytes.Contains(encoded, []byte(fixtureIP(53))) {
		t.Fatal("discovery leaked endpoint")
	}
}
