package main

import (
	"encoding/json"
	"github.com/petrichor/21pins-cli/internal/sshaccess"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestSSHClientRejectsUnsafeLeaseResponse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "client")
	pub, e := generateLeaseKey(dir)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(sshaccess.Lease{ID: "../../unsafe", Status: sshaccess.Active})
	}))
	defer server.Close()
	t.Setenv("PINS21_SSH_API_URL", server.URL)
	t.Setenv("PINS21_TOKEN", "synthetic-app")
	t.Setenv("PINS21_SSH_TOKEN_FILE", "")
	c, a, e := newSSHClient()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Open(a, sshaccess.OpenRequest{PublicKey: pub, HostID: "alpha", RoleID: "observe", AgentClass: "pi", ObjectiveID: "task", Purpose: "synthetic"}); e == nil {
		t.Fatal("unsafe response accepted")
	}
}
