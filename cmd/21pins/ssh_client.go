package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/petrichor/21pins-cli/internal/sshaccess"
)

var clientIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func safeLease(l sshaccess.Lease) bool {
	if !validLeaseID(l.ID) || !l.HardExpiresAt.After(l.OpenedAt) || l.SSHUser != l.EffectivePolicy.SSHUser {
		return false
	}
	for _, v := range []string{l.Workspace, l.HostID, l.RoleID, l.SSHUser, l.SSHAlias, l.AgentClass, l.ObjectiveID, l.Requester} {
		if !clientIdentifier.MatchString(v) {
			return false
		}
	}
	if l.SSHJumpAlias != "" && !clientIdentifier.MatchString(l.SSHJumpAlias) {
		return false
	}
	if l.Principal != "21pins:"+l.Workspace+":"+l.HostID+":"+l.RoleID {
		return false
	}
	return l.Status == sshaccess.PendingApproval || l.Status == sshaccess.Active || l.Status == sshaccess.Completed || l.Status == sshaccess.Cancelled || l.Status == sshaccess.Revoked || l.Status == sshaccess.Expired
}

// The harness client is not a signer. Only public key material enters requests.
type sshClient struct {
	Base      string
	authorize func(*http.Request)
	HTTP      *http.Client
	Initial   *sshaccess.IssueResult
}

func newSSHClient() (*sshClient, sshaccess.Actor, error) {
	base := os.Getenv("PINS21_SSH_API_URL")
	if base == "" {
		base = strings.TrimSuffix(os.Getenv("PINS21_BASE_URL"), "/v1")
	}
	if base == "" {
		base = "http://127.0.0.1:8787"
	}
	u, e := url.Parse(base)
	if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") {
		return nil, sshaccess.Actor{}, errors.New("V1 SSH control API must be loopback with no URL credentials")
	}
	raw := os.Getenv("PINS21_TOKEN")
	if p := os.Getenv("PINS21_SSH_TOKEN_FILE"); p != "" {
		b, e := sshaccess.ReadPrivate(p)
		if e != nil {
			return nil, sshaccess.Actor{}, errors.New("private SSH token file unavailable")
		}
		raw = strings.TrimSpace(string(b))
	}
	if raw == "" {
		return nil, sshaccess.Actor{}, errors.New("SSH requester token required")
	}
	hash := sha256.Sum256([]byte(raw))
	actor := sshaccess.Actor{ID: hex.EncodeToString(hash[:])}
	client := &sshClient{Base: strings.TrimRight(base, "/"), HTTP: &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("SSH API redirect refused") }, Transport: &http.Transport{Proxy: nil}}}
	client.authorize = func(r *http.Request) { r.Header.Set("Authorization", fmt.Sprintf("%s %s", "Bearer", raw)) }
	return client, actor, nil
}
func (c *sshClient) call(method, path string, body any, result any) error {
	var data []byte
	var e error
	if body != nil {
		data, e = json.Marshal(body)
		if e != nil {
			return errors.New("invalid SSH metadata")
		}
	}
	req, e := http.NewRequest(method, c.Base+"/v1/ssh/leases"+path, bytes.NewReader(data))
	if e != nil {
		return errors.New("invalid SSH API request")
	}
	c.authorize(req)
	req.Header.Set("Content-Type", "application/json")
	response, e := c.HTTP.Do(req)
	if e != nil {
		return errors.New("SSH control API unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("SSH control API rejected request")
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 65536))
	if decoder.Decode(result) != nil {
		return errors.New("SSH control response invalid")
	}
	return nil
}
func (c *sshClient) Open(actor sshaccess.Actor, q sshaccess.OpenRequest) (sshaccess.Lease, error) {
	var r struct {
		sshaccess.Lease
		Certificate string             `json:"certificate"`
		Issuance    sshaccess.Issuance `json:"issuance"`
	}
	e := c.call("POST", "", q, &r)
	fp, err := sshaccess.PublicFingerprint(q.PublicKey)
	if e == nil && (err != nil || !safeLease(r.Lease) || r.RequesterID != actor.ID || r.HostID != q.HostID || r.RoleID != q.RoleID || r.ObjectiveID != q.ObjectiveID || r.AgentClass != q.AgentClass || r.Purpose != q.Purpose || r.PublicKeyFingerprint != fp) {
		e = errors.New("SSH lease response scope mismatch")
	}
	if e == nil && r.Certificate != "" {
		c.Initial = &sshaccess.IssueResult{Lease: r.Lease, Certificate: r.Certificate, Issuance: r.Issuance}
	}
	return r.Lease, e
}
func (c *sshClient) Issue(actor sshaccess.Actor, id, pub string) (sshaccess.IssueResult, error) {
	if c.Initial != nil && c.Initial.Lease.ID == id {
		r := *c.Initial
		c.Initial = nil
		return r, nil
	}
	var r sshaccess.IssueResult
	e := c.call("POST", "/"+id+"/certificate", map[string]string{"public_key": pub}, &r)
	fp, err := sshaccess.PublicFingerprint(pub)
	if e == nil && (err != nil || !safeLease(r.Lease) || r.Lease.ID != id || r.Lease.RequesterID != actor.ID || r.Lease.PublicKeyFingerprint != fp || r.Issuance.LeaseID != id || r.Issuance.ValidBefore.After(r.Lease.HardExpiresAt) || !strings.HasPrefix(r.Certificate, "ssh-ed25519-cert-v01@openssh.com ")) {
		e = errors.New("SSH certificate response scope mismatch")
	}
	return r, e
}
func (c *sshClient) Get(_ sshaccess.Actor, id string) (sshaccess.Lease, error) {
	var l sshaccess.Lease
	e := c.call("GET", "/"+id, nil, &l)
	if e == nil && (l.ID != id || !safeLease(l)) {
		e = errors.New("SSH lease response invalid")
	}
	return l, e
}
func (c *sshClient) List(_ sshaccess.Actor, objective string) ([]sshaccess.Lease, error) {
	var l []sshaccess.Lease
	e := c.call("GET", "?objective="+url.QueryEscape(objective), nil, &l)
	return l, e
}
func (c *sshClient) Approve(_ sshaccess.Actor, id string) (sshaccess.Lease, error) {
	var l sshaccess.Lease
	e := c.call("POST", "/"+id+"/approve", map[string]string{}, &l)
	return l, e
}
func (c *sshClient) Close(_ sshaccess.Actor, id string, state sshaccess.Status, reason string) (sshaccess.Lease, error) {
	action := "complete"
	if state == sshaccess.Cancelled {
		action = "cancel"
	}
	if state == sshaccess.Revoked {
		action = "revoke"
	}
	var l sshaccess.Lease
	e := c.call("POST", "/"+id+"/"+action, map[string]string{"reason": reason}, &l)
	return l, e
}
