package sshaccess

import "testing"

func TestRequesterPolicyCanNarrowRoleMaximum(t *testing.T) {
	s, _, a, q, _ := fixture(t, false)
	h := s.Config.Hosts["alpha"]
	r := h.Roles["observe"]
	r.RequesterMaxLease = map[string]string{"pi": "2h"}
	h.Roles["observe"] = r
	s.Config.Hosts["alpha"] = h
	q.MaxDuration = "3h"
	if _, e := s.Open(a, q); e == nil {
		t.Fatal("requester ceiling ignored")
	}
	q.MaxDuration = "2h"
	l, e := s.Open(a, q)
	if e != nil || l.EffectivePolicy.MaxLease != "2h" {
		t.Fatal("requester ceiling not effective", e)
	}
}
