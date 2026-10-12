package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/petrichor/21pins-cli/internal/sshaccess"
)

func sshDecode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return errors.New("extra body")
	}
	return nil
}
func (s *Server) handleSSH(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if s.cfg.SSHDir == "" {
		writeJSON(w, 404, map[string]string{"error": "SSH disabled"})
		return
	}
	if !isLoopbackRequest(r) || r.Header.Get("Origin") != "" {
		writeJSON(w, 403, map[string]string{"error": "local non-browser SSH API only"})
		return
	}
	scope := "ssh:use"
	if strings.HasSuffix(r.URL.Path, "/approve") || strings.HasSuffix(r.URL.Path, "/revoke") {
		scope = "ssh:approve"
	}
	t, ok := s.store.ValidateSSHToken(bearerToken(r.Header.Get("Authorization")), scope)
	if r.Method == "GET" {
		if reviewer, valid := s.store.ValidateSSHToken(bearerToken(r.Header.Get("Authorization")), "ssh:approve"); valid {
			t = reviewer
			ok = true
			scope = "ssh:approve"
		}
	}
	if !ok {
		writeJSON(w, 401, map[string]string{"error": "SSH authentication required"})
		return
	}
	actor := sshaccess.Actor{ID: t.TokenHash, Name: t.Name, CanApprove: scope == "ssh:approve"}
	svc, e := sshaccess.Load(s.cfg.SSHDir)
	if e != nil {
		writeJSON(w, 503, map[string]string{"error": "SSH configuration unavailable"})
		return
	}
	svc.Authorize = func(a sshaccess.Actor) bool {
		record, valid := s.store.ValidateSSHToken(bearerToken(r.Header.Get("Authorization")), scope)
		return valid && record.TokenHash == a.ID && record.Name == a.Name
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/ssh/leases"), "/")
	var value any
	code := 200
	if r.URL.Path == "/v1/ssh/leases" {
		switch r.Method {
		case "GET":
			value, e = svc.List(actor, r.URL.Query().Get("objective"))
		case "POST":
			var q sshaccess.OpenRequest
			if sshDecode(w, r, &q) != nil {
				e = errors.New("invalid request")
				break
			}
			var l sshaccess.Lease
			l, e = svc.Open(actor, q)
			if e != nil {
				break
			}
			code = 201
			if l.Status == sshaccess.Active {
				var issued sshaccess.IssueResult
				issued, e = svc.Issue(actor, l.ID, q.PublicKey)
				value = struct {
					sshaccess.Lease
					Certificate string             `json:"certificate"`
					Issuance    sshaccess.Issuance `json:"issuance"`
				}{l, issued.Certificate, issued.Issuance}
			} else {
				value = l
			}
		default:
			writeJSON(w, 405, map[string]string{"error": "method not allowed"})
			return
		}
	} else if len(parts) == 2 && parts[0] == "" && parts[1] != "" && r.Method == "GET" {
		value, e = svc.Get(actor, parts[1])
	} else if len(parts) == 3 && parts[0] == "" && parts[1] != "" && r.Method == "POST" {
		id := parts[1]
		if parts[2] == "certificate" {
			var q struct {
				PublicKey string `json:"public_key"`
			}
			if sshDecode(w, r, &q) != nil {
				e = errors.New("invalid request")
			} else {
				value, e = svc.Issue(actor, id, q.PublicKey)
			}
		} else {
			var q struct {
				Reason string `json:"reason,omitempty"`
			}
			if sshDecode(w, r, &q) != nil {
				e = errors.New("invalid request")
			} else {
				switch parts[2] {
				case "approve":
					value, e = svc.Approve(actor, id)
				case "complete":
					value, e = svc.Close(actor, id, sshaccess.Completed, "complete")
				case "cancel":
					reason := q.Reason
					if reason == "" {
						reason = "cancelled"
					}
					value, e = svc.Close(actor, id, sshaccess.Cancelled, reason)
				case "revoke":
					value, e = svc.Close(actor, id, sshaccess.Revoked, "revoked")
				default:
					writeJSON(w, 404, map[string]string{"error": "unknown SSH action"})
					return
				}
			}
		}
	} else {
		writeJSON(w, 404, map[string]string{"error": "unknown SSH route"})
		return
	}
	if e != nil {
		writeJSON(w, 403, map[string]string{"error": "SSH request rejected"})
		return
	}
	writeJSON(w, code, value)
}
