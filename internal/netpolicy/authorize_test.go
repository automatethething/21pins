package netpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/petrichor/21pins-cli/internal/policy"
)

func fixtureGrant(req ObservationRequest, now time.Time) policy.Grant {
	return policy.Grant{ID: "grant-fixture", Sub: "ck_sub_fixture", Status: policy.GrantStatusActive, Pins: policy.Pins{Identity: policy.IdentityPin{Sub: "ck_sub_fixture"}, Authority: policy.AuthorityPin{Chain: []string{"ck_sub_fixture"}}, Capabilities: policy.CapabilityPin{Allowed: []string{"network.read", "network.probe"}}, DataPolicy: policy.DataPolicyPin{AllowedClasses: []string{"network-metadata"}}, SpendPolicy: policy.SpendPolicyPin{WindowStart: now.Add(-time.Minute), WindowEnd: now.Add(time.Minute)}, ExecutionTargets: policy.ExecutionTargetPin{AllowedTargets: []string{req.Digest("network.read"), req.Digest("network.probe")}}}}
}
func TestAdmission(t *testing.T) {
	now := time.Now()
	req := ObservationRequest{Operation: "access", Target: Ref{"net_fixture", 1}}
	grant := fixtureGrant(req, now)
	path := filepath.Join(t.TempDir(), "state.json")
	state := map[string]any{"grants": []policy.Grant{grant}, "provider_keys": []int{1, 2}, "signing_keys": "SENSITIVE_SENTINEL"}
	data, _ := json.Marshal(state)
	if e := os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	actor := func(context.Context) ([]byte, error) { return []byte("ck_sub_fixture"), nil }
	if e := Authorize(context.Background(), path, grant.ID, req, "network.read", now, actor); e != nil {
		t.Fatal(e)
	}
	bad := req
	bad.Target.Revision++
	if e := Authorize(context.Background(), path, grant.ID, bad, "network.read", now, actor); e == nil {
		t.Fatal("substitution authorized")
	}
	if e := Authorize(context.Background(), path, grant.ID, req, "network.read", now.Add(2*time.Minute), actor); e == nil {
		t.Fatal("expired grant")
	}
	if e := Authorize(context.Background(), path, grant.ID, req, "network.read", now, func(context.Context) ([]byte, error) { return []byte("ck_sub_other"), nil }); e == nil {
		t.Fatal("wrong subject")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(data, after) {
		t.Fatal("legacy state mutated")
	}
	got, e := ReadGrantProjection(path, grant.ID)
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal(got)
	if bytes.Contains(encoded, []byte("SENSITIVE_SENTINEL")) {
		t.Fatal("secret returned")
	}
	os.Chmod(path, 0644)
	if _, e = ReadGrantProjection(path, grant.ID); e == nil {
		t.Fatal("unsafe state")
	}
	missing := filepath.Join(t.TempDir(), "absent.json")
	if _, e = ReadGrantProjection(missing, grant.ID); e == nil {
		t.Fatal("missing state")
	}
	if _, e = os.Stat(missing); !os.IsNotExist(e) {
		t.Fatal("state initialized")
	}
}
