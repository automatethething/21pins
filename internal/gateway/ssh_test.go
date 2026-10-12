package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/petrichor/21pins-cli/internal/sshaccess"
	"github.com/petrichor/21pins-cli/internal/store"
)

func sshAPI(t *testing.T) (*Server, *store.Store, string, string) {
	t.Helper()
	root := t.TempDir()
	st, e := store.New(filepath.Join(root, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	use, e := st.CreateToken("pi", []string{"ssh:use"})
	if e != nil {
		t.Fatal(e)
	}
	approve, e := st.CreateToken("owner", []string{"ssh:approve"})
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(root, "ssh")
	if e = sshaccess.PrivateDir(dir); e != nil {
		t.Fatal(e)
	}
	c := sshaccess.Config{Workspace: "test", CertTTL: "15m", RenewBefore: "5m", ClockSkew: "30s", Hosts: map[string]sshaccess.Host{"alpha": {Alias: "alpha", Roles: map[string]sshaccess.Role{"observe": {SSHUser: "dev", DefaultLease: "1h", MaxLease: "8h", MaxCertTTL: "15m", Requesters: map[string]string{"pi": "approval"}}}}}}
	b, _ := json.Marshal(c)
	if e = os.WriteFile(filepath.Join(dir, "config.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	return NewServer(st, Config{SSHDir: dir}), st, use, approve
}
func apiRequest(s *Server, method, path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:3333"
	if token != "" {
		r.Header.Set("Authorization", fmt.Sprintf("%s %s", "Bearer", token))
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func pubAPI(t *testing.T) string {
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
func TestSSHAPIAuthScopeAndLifecycle(t *testing.T) {
	s, st, use, approve := sshAPI(t)
	proxy, e := st.CreateToken("proxy", []string{"proxy:*"})
	if e != nil {
		t.Fatal(e)
	}
	for _, tok := range []string{"", proxy} {
		w := apiRequest(s, "GET", "/v1/ssh/leases", tok, "")
		if w.Code != http.StatusUnauthorized {
			t.Fatal("scope bypass", w.Code)
		}
	}
	q := sshaccess.OpenRequest{HostID: "alpha", RoleID: "observe", AgentClass: "pi", ObjectiveID: "task", Purpose: "synthetic", PublicKey: pubAPI(t)}
	b, _ := json.Marshal(q)
	w := apiRequest(s, "POST", "/v1/ssh/leases", use, string(b))
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS enabled")
	}
	var l sshaccess.Lease
	if json.Unmarshal(w.Body.Bytes(), &l) != nil || l.Status != sshaccess.PendingApproval {
		t.Fatal("lease")
	}
	if apiRequest(s, "GET", "/v1/ssh/leases/"+l.ID, approve, "").Code != 200 {
		t.Fatal("approver cannot review immutable scope")
	}
	if apiRequest(s, "POST", "/v1/ssh/leases/"+l.ID+"/approve", use, "{}").Code != 401 {
		t.Fatal("self approve")
	}
	if apiRequest(s, "POST", "/v1/ssh/leases/"+l.ID+"/approve", approve, "{}").Code != 200 {
		t.Fatal("approve")
	}
	if apiRequest(s, "POST", "/v1/ssh/leases/"+l.ID+"/complete", use, "{}").Code != 200 {
		t.Fatal("complete")
	}
	body, _ := json.Marshal(map[string]string{"public_key": q.PublicKey})
	if apiRequest(s, "POST", "/v1/ssh/leases/"+l.ID+"/certificate", use, string(body)).Code == 200 {
		t.Fatal("closed issue")
	}
	if e = st.RevokeToken(use); e != nil {
		t.Fatal(e)
	}
	if apiRequest(s, "GET", "/v1/ssh/leases/"+l.ID, use, "").Code != 401 {
		t.Fatal("revoked token accepted")
	}
}
func TestSSHAPIRejectsPrivateKeysMutationsOriginsAndRemote(t *testing.T) {
	s, _, use, _ := sshAPI(t)
	bad := []string{`{"public_key":"-----BEGIN OPENSSH PRIVATE KEY-----"}`, `{"private_key":"synthetic"}`, `{"host_id":"alpha","role_id":"observe","objective_id":"task","purpose":"synthetic","public_key":"bad","requester_id":"owner"}`}
	for _, b := range bad {
		if apiRequest(s, "POST", "/v1/ssh/leases", use, b).Code == 201 {
			t.Fatal("bad accepted")
		}
	}
	for _, remote := range []bool{true, false} {
		r := httptest.NewRequest("GET", "/v1/ssh/leases", nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Authorization", fmt.Sprintf("%s %s", "Bearer", use))
		if remote {
			r.RemoteAddr = "<public-ip>:1234"
		} else {
			r.Header.Set("Origin", "http://synthetic.invalid")
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("origin/remote allowed", w.Code)
		}
	}
}
