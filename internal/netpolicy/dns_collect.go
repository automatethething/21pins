package netpolicy

import (
	"context"
	"time"
)

func baselineValid(a *Assessment, q Question, t Tuple, now time.Time, runtimeBinding string, fixture bool) bool {
	if a == nil || a.Verdict != Verified || !a.Cleanup || a.Request.Operation != "access" || a.Request.Target != q.Service.Ref || a.Request.Source == t.Source || now.Sub(a.CreatedAt) > 10*time.Minute || a.CreatedAt.After(now) || a.Synthetic && !fixture {
		return false
	}
	response, path := false, q.VPN.Ref.ID == ""
	for _, f := range a.Evidence {
		if f.Tuple == nil || f.Tuple.Endpoint != t.Endpoint || f.Tuple.Transport != t.Transport || f.Tuple.Family != t.Family || f.Tuple.Port != t.Port || f.Tuple.Mode != t.Mode || !f.Value || f.RuntimeBinding != runtimeBinding || f.ValidUntil.Before(now) {
			continue
		}
		if f.Property == "dns.response" {
			response = true
		}
		if f.Property == "path.selection" {
			path = true
		}
	}
	return response && path
}
func (c *collector) collectDNS(ctx context.Context, q Question) (out Collection) {
	out = Collection{Cleanup: true}
	if c.permit == nil || c.permit(ctx, "network.read") != nil {
		return out
	}
	bound, e := c.interfaceBinding(ctx, q.Source)
	if e != nil {
		return out
	}
	for i := range q.Request.Tuples {
		t := q.Request.Tuples[i]
		out.Facts = append(out.Facts, c.fact("source.binding", q, &t, bound))
	}
	if !bound {
		return out
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
	isDeny := q.Request.Operation == "isolation"
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
			if baselineValid(q.Baseline, q, t, time.Now(), runtimeBinding, c.fixture) {
				f := c.fact("isolation.baseline", q, &t, true)
				f.Assurance = "operator_attested"
				if c.fixture {
					f.Assurance = "synthetic_runtime"
				}
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
			control, e := probeDNS(ctx, q.Source.Binding, q.Control.Binding, t.Transport, nonce)
			if e == nil {
				out.Facts = append(out.Facts, c.fact("dns.control", q, &t, control.usable))
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
		} else {
			out.Facts = append(out.Facts, makeFact("dns.response", got.usable))
		}
		if !protected {
			continue
		}
		covered := a.Complete && b.Complete && !a.Start.After(got.start) && !b.Start.After(got.start) && !a.End.Before(got.end) && !b.End.Before(got.end)
		seen := a.Seen[t.Transport] > 0 && b.Seen[t.Transport] > 0
		if isDeny {
			out.Facts = append(out.Facts, makeFact("isolation.coverage", covered))
			if covered {
				out.Facts = append(out.Facts, makeFact("isolation.absence", a.Seen[t.Transport] == 0 && b.Seen[t.Transport] == 0))
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
