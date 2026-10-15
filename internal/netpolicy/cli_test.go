package netpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNetworkCLIIsMetadataOnly(t *testing.T) {
	r, _, _ := testObjects(t)
	env := CLIEnv{RegistryPath: r.Path, StatePath: filepath.Join(t.TempDir(), "absent-provider.json"), ReceiptDir: filepath.Join(t.TempDir(), "receipts"), Collect: func(context.Context, Question, func(context.Context, string) error) Collection {
		t.Fatal("metadata command executed native collector")
		return Collection{}
	}}
	for _, args := range [][]string{{"discover"}, {"inspect", "service", "dns", "--details"}, {"inspect", "network", "trusted"}} {
		var out, errout bytes.Buffer
		if code := Run(context.Background(), args, env, &out, &errout); code != 0 {
			t.Fatalf("%v failed: %s", args, errout.String())
		}
		if bytes.Contains(out.Bytes(), []byte(fixtureIP(53))) {
			t.Fatal("endpoint leaked")
		}
	}
	var unsupported, errs bytes.Buffer
	if Run(context.Background(), []string{"inspect", "tailscale", "unimplemented"}, env, &unsupported, &errs) != 2 || !bytes.Contains(unsupported.Bytes(), []byte(ErrUnsupported.Error())) {
		t.Fatal("deferred expert adapter not honestly unsupported")
	}
	if _, e := os.Stat(env.StatePath); !os.IsNotExist(e) {
		t.Fatal("legacy provider state initialized")
	}
}
func TestNetworkRequestProfiles(t *testing.T) {
	r, _, _ := testObjects(t)
	gateway, e := r.Create(Object{Kind: Gateway, Alias: "router"})
	if e != nil {
		t.Fatal(e)
	}
	env := CLIEnv{RegistryPath: r.Path, StatePath: filepath.Join(t.TempDir(), "absent.json")}
	var out, errs bytes.Buffer
	if code := Run(context.Background(), []string{"verify", "gateway", "router", "--request"}, env, &out, &errs); code != 0 {
		t.Fatal(errs.String())
	}
	var desc RequestDescriptor
	if json.Unmarshal(out.Bytes(), &desc) != nil || len(desc.Request.Required) != 4 || desc.Request.Target != gateway.Ref {
		t.Fatal("gateway finite profile changed")
	}
	first := desc.Targets["network.read"]
	r.Rename(Gateway, "router", "renamed")
	out.Reset()
	if code := Run(context.Background(), []string{"verify", "gateway", "renamed", "--request"}, env, &out, &errs); code != 0 {
		t.Fatal(errs.String())
	}
	json.Unmarshal(out.Bytes(), &desc)
	if desc.Targets["network.read"] != first {
		t.Fatal("alias rename changed authority")
	}
	var invalid bytes.Buffer
	if Run(context.Background(), []string{"verify", "gateway", "renamed", "--all-health"}, env, &invalid, &errs) != 3 {
		t.Fatal("universal-health flag accepted")
	}
}
