package sshaccess

import (
	"testing"
	"time"
)

func TestAuthorizationAndScopeRecheckedBeforeDelivery(t *testing.T) {
	for _, mode := range []string{"credential", "policy", "expiry"} {
		s, f, a, q, _ := fixture(t, false)
		l, e := s.Open(a, q)
		if e != nil {
			t.Fatal(e)
		}
		authorized := true
		s.Authorize = func(Actor) bool { return authorized }
		f.onSign = func() {
			switch mode {
			case "credential":
				authorized = false
			case "policy":
				h := s.Config.Hosts["alpha"]
				r := h.Roles["observe"]
				r.PermitPTY = true
				h.Roles["observe"] = r
				s.Config.Hosts["alpha"] = h
			case "expiry":
				s.Now = func() time.Time { return l.HardExpiresAt }
			}
		}
		if r, e := s.Issue(a, l.ID, q.PublicKey); e == nil || r.Certificate != "" {
			t.Fatal("stale authority delivered", mode)
		}
	}
}
