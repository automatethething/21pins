package main

import (
	"encoding/json"
	"github.com/petrichor/21pins-cli/internal/sshaccess"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSSHClientUsesAPIWithoutIssuerState(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var obj map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&obj) != nil {
			t.Fatal("body")
		}
		if _, ok := obj["public_key"]; !ok {
			t.Fatal("public request missing")
		}
		for _, field := range []string{"private_key", "ca", "requester_id"} {
			if _, ok := obj[field]; ok {
				t.Fatal("forbidden request")
			}
		}
		json.NewEncoder(w).Encode(sshaccess.Lease{ID: strings.Repeat("a", 32), Status: sshaccess.PendingApproval})
	}))
	defer server.Close()
	t.Setenv("PINS21_SSH_API_URL", server.URL)
	t.Setenv("PINS21_TOKEN", "synthetic-requester")
	t.Setenv("PINS21_SSH_TOKEN_FILE", "")
	t.Setenv("PINS21_SSH_DIR", "/synthetic-no-issuer-config")
	c, _, e := newSSHClient()
	if e != nil {
		t.Fatal(e)
	}
	var result sshaccess.Lease
	if e = c.call("POST", "", sshaccess.OpenRequest{PublicKey: "synthetic-public"}, &result); e != nil {
		t.Fatal(e)
	}
	if calls != 1 {
		t.Fatal("not API client")
	}
}
func TestSSHClientRejectsRemoteOrCredentialURLs(t *testing.T) {
	withUser := url.URL{Scheme: "http", Host: "127.0.0.1", User: url.UserPassword("synthetic", "synthetic")}
	for _, u := range []string{"http://synthetic.invalid", withUser.String(), "http://127.0.0.1?q=synthetic"} {
		t.Setenv("PINS21_SSH_API_URL", u)
		if _, _, e := newSSHClient(); e == nil {
			t.Fatal("unsafe API URL")
		}
	}
}
