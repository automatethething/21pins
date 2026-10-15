package netpolicy

import (
	"context"
	"net/netip"
	"time"
)

func baselineObservation(a *Assessment, q Question, t Tuple, now time.Time, runtimeBinding string, fixture bool) (Fact, bool) {
	if a == nil || a.Verdict != Verified || !a.Cleanup || a.Request.Operation != "access" || a.Request.Target != q.Service.Ref || a.Request.Source == t.Source || now.Sub(a.CreatedAt) > 10*time.Minute || a.CreatedAt.After(now) || a.Synthetic && !fixture {
		return Fact{}, false
	}
	var response Fact
	foundResponse := false
	path := q.VPN.Ref.ID == ""
	for _, f := range a.Evidence {
		if f.Tuple == nil || f.Target != a.Request.Target || f.Tuple.Source != a.Request.Source || f.Tuple.Endpoint != t.Endpoint || f.Tuple.Transport != t.Transport || f.Tuple.Family != t.Family || f.Tuple.Port != t.Port || f.Tuple.Mode != t.Mode || f.Tuple.Realm != t.Realm || (!fixture && f.Assurance == "synthetic_runtime") || !f.Value || f.RuntimeBinding != runtimeBinding || f.ValidUntil.Before(now) || f.ObservedAt.After(now) || f.ValidUntil.After(f.ObservedAt.Add(10*time.Minute)) || !sameRefs(f.Scope, a.Request.Objects) || !sameRefs(f.Policies, a.Request.Policies) {
			continue
		}
		if f.Property == "dns.response" {
			response = f
			foundResponse = true
		}
		if f.Property == "path.selection" {
			path = true
		}
	}
	return response, foundResponse && path
}

// v1 has one bound endpoint/source/family/port/realm and at most one probe per transport.
// Richer multi-attempt scopes must remain unsupported, never share hit attribution.
func validateProbeScopes(q Question) error {
	address, e := netip.ParseAddr(q.Service.Binding.Target)
	if e != nil || len(q.Request.Tuples) == 0 || len(q.Request.Tuples) > 2 || q.Request.Target != q.Service.Ref {
		return ErrUnsupported
	}
	if q.Control.Ref.ID != "" && q.Control.Binding.Target == q.Service.Binding.Target && q.Control.Binding.Port == q.Service.Binding.Port {
		return ErrUnsupported
	}
	realm := "realm_" + hashJSON(struct {
		Endpoint Ref
		Name     string
	}{q.Service.Ref, q.Service.Binding.Realm})
	seen := map[string]bool{}
	for _, t := range q.Request.Tuples {
		if t.Source != q.Source.Ref || t.Endpoint != q.Service.Ref || t.Port != q.Service.Binding.Port || t.Realm != realm || t.Mode != "direct" || (t.Family != "ipv4" && t.Family != "ipv6") || (t.Family == "ipv4") != address.Is4() || (t.Transport != "udp" && t.Transport != "tcp") || seen[t.Transport] {
			return ErrUnsupported
		}
		seen[t.Transport] = true
	}
	return nil
}

func (c *collector) collectDNS(ctx context.Context, q Question) (out Collection) {
	out = Collection{Cleanup: true}
	if validateProbeScopes(q) != nil {
		out.Missing = []string{"unsupported_probe_scope"}
		return out
	}
	if c.permit == nil || c.permit(ctx, "network.read") != nil {
		return out
	}
	bound, e := c.interfaceBinding(ctx, q.Source)
	if e != nil {
		return out
	}
	if !bound {
		out.Missing = append(out.Missing, "source_membership")
		return out
	}
	for i := range q.Request.Tuples {
		t := q.Request.Tuples[i]
		out.Facts = append(out.Facts, c.fact("source.binding", q, &t, true))
	}
	if q.Service.Binding.Protocol != "dns" || len(q.Request.Tuples) == 0 {
		return out
	}
	for _, t := range q.Request.Tuples {
		if t.Mode != "direct" {
			out.Missing = append(out.Missing, "mediated_dns_unsupported")
			return out
		}
	}
	p := nftPolicy{}
	if q.Gateway.Ref.ID != "" {
		p, _ = c.policy(ctx, q.Gateway, q.Service.Binding.Target)
	}
	isDeny := len(q.Resolved) > 0 && q.Resolved[0].Decision == "deny"
	for _, rule := range q.Resolved {
		if (rule.Decision == "deny") != isDeny {
			out.Missing = append(out.Missing, "mixed_decision_unsupported")
			return out
		}
	}
	if isDeny && (!c.closed[q.Gateway.Binding.Context] || !p.supported || p.hook != "forward") {
		out.Missing = append(out.Missing, "effective_policy_coverage")
		return out
	}
	runtimeBinding := hashJSON(struct {
		Gateway, VPN, Endpoint Ref
		Native                 string
	}{q.Gateway.Ref, q.VPN.Ref, q.Service.Ref, p.digest})
	if isDeny {
		for _, t := range q.Request.Tuples {
			prior, ok := baselineObservation(q.Baseline, q, t, time.Now(), runtimeBinding, c.fixture)
			if ok {
				f := c.fact("isolation.baseline", q, &t, true)
				f.Assurance = "operator_attested"
				if c.fixture {
					f.Assurance = "synthetic_runtime"
				}
				f.HistoricalAssessment = q.Baseline.ID
				f.RuntimeBinding = runtimeBinding
				f.ObservedAt = prior.ObservedAt
				f.ValidUntil = prior.ValidUntil
				f.WindowStart = prior.WindowStart
				f.WindowEnd = prior.WindowEnd
				f.ObserverWindows = append([]ObserverWindow(nil), prior.ObserverWindows...)
				out.Facts = append(out.Facts, f)
			} else {
				out.Missing = append(out.Missing, "same_endpoint_baseline")
				return out
			}
		}
	}
	if c.permit(ctx, "network.probe") != nil {
		out.Missing = append(out.Missing, "network.probe")
		return out
	}
	nonce := challenge()
	if nonce == "" {
		return out
	}
	var first, second monitor
	protected := q.VPN.Ref.ID != ""
	if protected {
		if q.VPN.Binding.Protocol != "wireguard" {
			return out
		}
		binding, e := c.interfaceBinding(ctx, q.VPN)
		if e != nil || !binding {
			return out
		}
		raw, e := c.read(ctx, q.VPN.Binding, "wg", "show", q.VPN.Binding.Interface, "allowed-ips")
		if e != nil || !peerOwns(raw, q.VPN.Binding.Peer, q.Service.Binding.Target) {
			return out
		}
		if c.permit(ctx, "network.read") != nil {
			return out
		}
		first, e = startMonitor(ctx, q.VPN.Binding, q.VPN.Binding.Address, q.Service.Binding.Target, q.Service.Binding.Port, nonce)
		if e != nil {
			out.Missing = append(out.Missing, "gateway_observer")
			return out
		}
		defer func() { obs := first.stop(); out.Cleanup = out.Cleanup && obs.Closed }()
		if c.permit(ctx, "network.read") != nil {
			return out
		}
		second, e = startMonitor(ctx, q.Service.Binding, q.VPN.Binding.Address, q.Service.Binding.Target, q.Service.Binding.Port, nonce)
		if e != nil {
			first.stop()
			out.Missing = append(out.Missing, "resolver_observer")
			return out
		}
		defer func() { obs := second.stop(); out.Cleanup = out.Cleanup && obs.Closed }()
	} else if isDeny {
		out.Missing = append(out.Missing, "protected_path_vantage")
		return out
	}
	type attempt struct {
		tuple Tuple
		probe probeResult
		err   error
	}
	var attempts []attempt
	for _, t := range q.Request.Tuples {
		if c.permit(ctx, "network.probe") != nil {
			break
		}
		if isDeny && q.Control.Ref.ID != "" {
			control, e := probeDNS(ctx, q.Source.Binding, q.Control.Binding, t.Transport, challenge())
			if e == nil && control.usable {
				fact := c.fact("dns.control", q, &t, true)
				fact.WindowStart = control.start
				fact.WindowEnd = control.end
				out.Facts = append(out.Facts, fact)
			} else {
				out.Missing = append(out.Missing, "positive_control")
			}
		}
		if c.permit(ctx, "network.probe") != nil {
			break
		}
		got, e := probeDNS(ctx, q.Source.Binding, q.Service.Binding, t.Transport, nonce)
		attempts = append(attempts, attempt{t, got, e})
	}
	// Bracket the final probe and give the bound kernel observers time to drain.
	if protected {
		timer := time.NewTimer(150 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
		}
		timer.Stop()
	}
	var a, b observation
	if protected {
		a = first.stop()
		b = second.stop()
		out.Cleanup = a.Closed && b.Closed
	}
	current := p
	if q.Gateway.Ref.ID != "" {
		current, _ = c.policy(ctx, q.Gateway, q.Service.Binding.Target)
	}
	stable := p.digest == current.digest
	for _, attempt := range attempts {
		t, got := attempt.tuple, attempt.probe
		makeFact := func(property string, value bool) Fact {
			f := c.fact(property, q, &t, value)
			f.RuntimeBinding = runtimeBinding
			f.WindowStart = got.start
			f.WindowEnd = got.end
			if protected {
				f.ObserverWindows = []ObserverWindow{{q.Gateway.Ref, a.Start, a.End, a.Complete}, {q.Service.Ref, b.Start, b.End, b.Complete}}
			}
			return f
		}
		if attempt.err != nil {
			continue
		}
		if isDeny {
			if got.responded {
				out.Facts = append(out.Facts, makeFact("dns.denied", false))
			} else if got.silent {
				out.Facts = append(out.Facts, makeFact("dns.denied", true))
			}
		} else if got.responded {
			out.Facts = append(out.Facts, makeFact("dns.response", got.usable))
		}
		if !protected {
			continue
		}
		covered := a.Complete && b.Complete && !a.Start.After(got.start) && !b.Start.After(got.start) && !a.End.Before(got.end) && !b.End.Before(got.end)
		seen := a.Seen[t.Transport] > 0 && b.Seen[t.Transport] > 0
		if !isDeny && (!covered || !seen) {
			if !a.Complete {
				out.Missing = append(out.Missing, "gateway_observer_incomplete")
			}
			if !b.Complete {
				out.Missing = append(out.Missing, "resolver_observer_incomplete")
			}
			if a.Seen[t.Transport] == 0 {
				out.Missing = append(out.Missing, "gateway_challenge_absent")
			}
			if b.Seen[t.Transport] == 0 {
				out.Missing = append(out.Missing, "resolver_challenge_absent")
			}
			if !covered {
				out.Missing = append(out.Missing, "observation_window_coverage")
			}
		}
		if isDeny {
			if covered {
				out.Facts = append(out.Facts, makeFact("isolation.coverage", true))
				out.Facts = append(out.Facts, makeFact("isolation.absence", a.Seen[t.Transport] == 0 && b.Seen[t.Transport] == 0))
			} else {
				out.Missing = append(out.Missing, "observation_window_coverage")
			}
			if stable && p.supported && p.denied[q.Source.Binding.Address] && c.closed[q.Gateway.Binding.Context] {
				out.Facts = append(out.Facts, makeFact("isolation.boundary", true), makeFact("guard.fail_closed", true))
			}
		} else {
			if covered && stable && seen {
				out.Facts = append(out.Facts, makeFact("path.selection", true))
			}
			if stable && p.supported && c.closed[q.Gateway.Binding.Context] && p.guards[q.Source.Binding.Address] == q.VPN.Binding.Interface {
				out.Facts = append(out.Facts, makeFact("guard.fail_closed", true))
			}
			for _, rule := range q.Resolved {
				if rule.Tuple == t && rule.Filtering && got.filtered {
					out.Facts = append(out.Facts, makeFact("dns.filtering", true))
				}
			}
		}
	}
	return out
}
