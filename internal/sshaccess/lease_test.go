package sshaccess

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPublic(t *testing.T) string {
	t.Helper()
	p, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, 11)
	b = append(b, []byte("ssh-ed25519")...)
	n := make([]byte, 4)
	binary.BigEndian.PutUint32(n, 32)
	b = append(b, n...)
	b = append(b, p...)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(b)
}

type fakeSigner struct {
	calls  []SignRequest
	fail   bool
	onSign func()
}

func (f *fakeSigner) Sign(r SignRequest) (string, error) {
	if f.fail {
		return "", errors.New("synthetic failure")
	}
	f.calls = append(f.calls, r)
	if f.onSign != nil {
		f.onSign()
	}
	return "synthetic-certificate", nil
}
func fixture(t *testing.T, approval bool) (*Service, *fakeSigner, Actor, OpenRequest, time.Time) {
	t.Helper()
	mode := "preapproved"
	if approval {
		mode = "approval"
	}
	c := Config{Workspace: "test", CertTTL: "15m", RenewBefore: "5m", ClockSkew: "30s", Hosts: map[string]Host{"alpha": {Alias: "alpha", Roles: map[string]Role{"observe": {SSHUser: "dev", DefaultLease: "1h", MaxLease: "8h", MaxCertTTL: "15m", Requesters: map[string]string{"pi": mode}}}}}}
	f := &fakeSigner{}
	s, e := New(filepath.Join(t.TempDir(), "ssh"), c, f)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	s.Now = func() time.Time { return now }
	a := Actor{ID: "actor1", Name: "pi"}
	q := OpenRequest{HostID: "alpha", RoleID: "observe", AgentClass: "pi", ObjectiveID: "objective-x", Purpose: "synthetic verification", PublicKey: testPublic(t), EstimatedDuration: "45m"}
	return s, f, a, q, now
}

func TestLeaseLifecycleAndImmutableRenewal(t *testing.T) {
	s, f, a, q, now := fixture(t, false)
	l, e := s.Open(a, q)
	if e != nil {
		t.Fatal(e)
	}
	if l.Status != Active || l.Principal != "21pins:test:alpha:observe" {
		t.Fatal("wrong scope/state")
	}
	r, e := s.Issue(a, l.ID, q.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	if !r.Issuance.ValidBefore.Equal(now.Add(15 * time.Minute)) {
		t.Fatal("TTL")
	}
	if len(f.calls) != 1 || f.calls[0].PermitAgentForwarding || f.calls[0].PermitPortForwarding || f.calls[0].PermitX11 || f.calls[0].PermitPTY {
		t.Fatal("unsafe options")
	}
	if _, e = s.Issue(a, l.ID, testPublic(t)); e == nil {
		t.Fatal("key replacement accepted")
	}
	if _, e = s.Issue(Actor{ID: "other", Name: "pi"}, l.ID, q.PublicKey); e == nil {
		t.Fatal("requester replacement accepted")
	}
	s.Now = func() time.Time { return now.Add(10 * time.Minute) }
	r2, e := s.Issue(a, l.ID, q.PublicKey)
	if e != nil || r2.Issuance.Serial == r.Issuance.Serial {
		t.Fatal("renewal", e)
	}
	if _, e = s.Close(a, l.ID, Completed, "complete"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Issue(a, l.ID, q.PublicKey); e == nil {
		t.Fatal("closed issued")
	}
	if _, e = s.Close(a, l.ID, Active, ""); e == nil {
		t.Fatal("reactivation accepted")
	}
}

func TestExpiryAndApproval(t *testing.T) {
	s, _, a, q, now := fixture(t, true)
	q.MaxDuration = "20m"
	l, e := s.Open(a, q)
	if e != nil || l.Status != PendingApproval {
		t.Fatal(e)
	}
	if _, e = s.Issue(a, l.ID, q.PublicKey); e == nil {
		t.Fatal("pending issued")
	}
	if _, e = s.Approve(a, l.ID); e == nil {
		t.Fatal("self approval")
	}
	admin := Actor{ID: "approver", Name: "owner", CanApprove: true}
	l, e = s.Approve(admin, l.ID)
	if e != nil {
		t.Fatal(e)
	}
	s.Now = func() time.Time { return now.Add(18 * time.Minute) }
	r, e := s.Issue(a, l.ID, q.PublicKey)
	if e != nil || !r.Issuance.ValidBefore.Equal(l.HardExpiresAt) {
		t.Fatal("clamp", e)
	}
	s.Now = func() time.Time { return l.HardExpiresAt }
	if _, e = s.Issue(a, l.ID, q.PublicKey); e == nil {
		t.Fatal("expired issued")
	}
	l, e = s.Get(a, l.ID)
	if e != nil || l.Status != Expired {
		t.Fatal("not expired", e)
	}
}

func TestScopePolicyAndPublicKeyValidation(t *testing.T) {
	s, _, a, q, _ := fixture(t, false)
	for _, bad := range []string{"-----BEGIN OPENSSH PRIVATE KEY-----", "ssh-rsa AAAA", "ssh-ed25519 AAAA", "command=evil " + q.PublicKey, q.PublicKey + "\n" + q.PublicKey} {
		q2 := q
		q2.PublicKey = bad
		if _, e := s.Open(a, q2); e == nil {
			t.Fatal("bad key accepted")
		}
	}
	for _, change := range []func(*OpenRequest){func(r *OpenRequest) { r.HostID = "other" }, func(r *OpenRequest) { r.RoleID = "root" }, func(r *OpenRequest) { r.ObjectiveID = "../../oops" }, func(r *OpenRequest) { r.MaxDuration = "9h" }, func(r *OpenRequest) { r.EstimatedDuration = "-1m" }} {
		r := q
		change(&r)
		if _, e := s.Open(a, r); e == nil {
			t.Fatal("bad scope accepted")
		}
	}
	if _, e := s.Open(Actor{ID: "x", Name: "unapproved"}, q); e == nil {
		t.Fatal("unauthorized")
	}
	l, e := s.Open(a, q)
	if e != nil {
		t.Fatal(e)
	}
	s.Config.Hosts["alpha"].Roles["observe"] = Role{SSHUser: "root", MaxLease: "8h", DefaultLease: "1h", MaxCertTTL: "15m", Requesters: map[string]string{"pi": "preapproved"}}
	if _, e = s.Issue(a, l.ID, q.PublicKey); e == nil {
		t.Fatal("scope changed renewal")
	}
}

func TestPersistenceAndNoPrivateMaterial(t *testing.T) {
	s, _, a, q, _ := fixture(t, false)
	l, e := s.Open(a, q)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Issue(a, l.ID, q.PublicKey); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(s.Dir, "leases.json"))
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"PRIVATE KEY", "synthetic-certificate", "public_key\"", "purpose-private-key"} {
		if strings.Contains(string(b), v) {
			t.Fatal("unexpected material", v)
		}
	}
	info, e := os.Stat(filepath.Join(s.Dir, "leases.json"))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("mode", e)
	}
	s2, e := New(s.Dir, s.Config, &fakeSigner{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s2.Get(a, l.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s2.Close(a, l.ID, Revoked, "revoked"); e == nil {
		t.Fatal("nonadmin revoke")
	}
}
