package netpolicy

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"testing"
)

func fixtureIP(n byte) string { return netip.AddrFrom4([4]byte{192, 0, 2, n}).String() }

func TestRegistryBindings(t *testing.T) {
	r := NewRegistry(filepath.Join(t.TempDir(), "private", "network-state.json"))
	a, err := r.Create(Object{Kind: Network, Alias: "trusted", Binding: Binding{Namespace: "trusted"}})
	if err != nil {
		t.Fatal(err)
	}
	if a.Ref.ID == "" || a.Ref.Revision != 1 {
		t.Fatal("missing immutable identity")
	}
	if _, err = r.Create(Object{Kind: Network, Alias: "trusted"}); err == nil {
		t.Fatal("duplicate alias accepted")
	}
	renamed, err := r.Rename(Network, "trusted", "safe")
	if err != nil || renamed.Ref != a.Ref {
		t.Fatal("rename changed binding", err)
	}
	changed, err := r.Rebind(Network, "safe", Binding{Namespace: "changed"})
	if err != nil || changed.Ref.ID != a.Ref.ID || changed.Ref.Revision != 2 {
		t.Fatal("rebind did not invalidate", err)
	}
	if _, err = r.ResolveRef(a.Ref); err == nil {
		t.Fatal("stale reference resolved")
	}
	if _, err = r.Create(Object{Kind: Network, Alias: "bad;echo"}); err == nil {
		t.Fatal("shell alias accepted")
	}
	if _, err = r.Create(Object{Kind: Service, Alias: "dns", Binding: Binding{Target: "invalid", Port: 53}}); err == nil {
		t.Fatal("invalid endpoint")
	}
	before, _ := os.ReadFile(r.Path)
	if err = r.Import(strings.NewReader(`{"objects":[],"confirmed_public":true}`)); err == nil {
		t.Fatal("unknown import field accepted")
	}
	if err = r.Import(strings.NewReader(fmt.Sprintf(`{"objects":[{"kind":"service","alias":"web","binding":{"target":%q,"port":443,"realm":"public","confirmed_public":true}}]}`, fixtureIP(80)))); err == nil {
		t.Fatal("forged public confirmation accepted")
	}
	after, _ := os.ReadFile(r.Path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed import changed state")
	}
	info, _ := os.Stat(r.Path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe state mode")
	}
}
func TestRegistryAtomicFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private", "network-state.json")
	r := NewRegistry(path)
	if _, err := r.Create(Object{Kind: Network, Alias: "first"}); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(path)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Create(Object{Kind: Network, Alias: "second"}); err == nil {
		t.Fatal("unsafe state accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(original, after) {
		t.Fatal("failed save damaged old state")
	}
	os.Chmod(path, 0600)
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRegistry(link).Objects(); err == nil {
		t.Fatal("symlink accepted")
	}
}
func TestRegistryImportReferences(t *testing.T) {
	r := NewRegistry(filepath.Join(t.TempDir(), "private", "network-state.json"))
	err := r.Import(strings.NewReader(fmt.Sprintf(`{"objects":[{"kind":"network_gateway","alias":"router"},{"kind":"network","alias":"trusted","binding":{"gateway":{"id":"router"}}},{"kind":"service","alias":"dns","binding":{"target":%q,"port":53,"realm":"private"}}]}`, fixtureIP(53))))
	if err != nil {
		t.Fatal(err)
	}
	source, err := r.Resolve(Network, "trusted")
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := r.Resolve(Gateway, "router")
	if err != nil || source.Binding.Gateway != gateway.Ref {
		t.Fatal("alias not canonically bound")
	}
	if err = r.Import(strings.NewReader(fmt.Sprintf(`{"objects":[{"kind":"service","alias":"same","binding":{"target":%q,"port":53,"realm":"private"}}]}`, fixtureIP(53)))); err == nil {
		t.Fatal("duplicate canonical endpoint accepted")
	}
}
