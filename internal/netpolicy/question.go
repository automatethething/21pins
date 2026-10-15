package netpolicy

import (
	"net/netip"
	"sort"
)

func (r *Registry) Question(operation, name, source string, baseline *Assessment) (Question, error) {
	q := Question{Baseline: baseline}
	q.Request.Operation = operation
	kind := Service
	if operation == "gateway" {
		kind = Gateway
	}
	if operation == "vpn" {
		kind = VPN
	}
	target, e := r.Resolve(kind, name)
	if e != nil {
		return q, e
	}
	q.Target = target
	q.Request.Target = target.Ref
	resolve := func(ref Ref) (Object, error) {
		if ref.ID == "" {
			return Object{}, nil
		}
		return r.ResolveRef(ref)
	}
	switch operation {
	case "gateway":
		q.Gateway = target
		if target.Binding.OpenWrt != nil {
			q.Source, e = resolve(target.Binding.Source)
			if e != nil {
				return q, e
			}
			q.VPN, e = resolve(target.Binding.VPN)
			if e != nil {
				return q, e
			}
		}
		q.Request.Required = Properties(operation, target.Binding)
	case "vpn":
		if target.Binding.Protocol != "wireguard" {
			return q, ErrUnsupported
		}
		q.VPN = target
		q.Gateway, e = resolve(target.Binding.Gateway)
		if e != nil {
			return q, e
		}
		q.Source, e = resolve(target.Binding.Source)
		if e != nil {
			return q, e
		}
		q.Request.Required = Properties(operation, target.Binding)
	case "access", "isolation":
		q.Service = target
		if source == "" {
			q.Source, e = resolve(target.Binding.Source)
		} else {
			q.Source, e = r.Resolve(Network, source)
		}
		if e != nil || q.Source.Ref.ID == "" {
			return q, ErrMissing
		}
		declaredSources, e := r.Objects()
		if e != nil {
			return q, e
		}
		for _, other := range declaredSources {
			if other.Kind == Network && other.Ref.ID != q.Source.Ref.ID && q.Source.Binding.Context != "" && other.Binding.Context == q.Source.Binding.Context && other.Binding.Address == q.Source.Binding.Address {
				return q, ErrConflict
			}
		}
		q.Request.Source = q.Source.Ref
		q.Gateway, e = resolve(target.Binding.Gateway)
		if e != nil {
			return q, e
		}
		if q.Gateway.Ref.ID == "" {
			q.Gateway, e = resolve(q.Source.Binding.Gateway)
			if e != nil {
				return q, e
			}
		}
		q.VPN, e = resolve(target.Binding.VPN)
		if e != nil {
			return q, e
		}
		q.Control, e = resolve(target.Binding.Control)
		if e != nil {
			return q, e
		}
		address, e := netip.ParseAddr(target.Binding.Target)
		if e != nil || len(target.Binding.Transports) == 0 || len(target.Binding.AccessModes) == 0 {
			return q, ErrMissing
		}
		family := "ipv4"
		if !address.Is4() {
			family = "ipv6"
		}
		seen := map[string]bool{}
		for _, transport := range target.Binding.Transports {
			if seen[transport] {
				return q, ErrInvalid
			}
			seen[transport] = true
			for _, mode := range target.Binding.AccessModes {
				q.Request.Tuples = append(q.Request.Tuples, Tuple{Source: q.Source.Ref, Endpoint: target.Ref, Realm: target.Binding.Realm, Family: family, Transport: transport, Port: target.Binding.Port, Mode: mode})
			}
		}
		q.Resolved, e = r.ResolveTuples(q.Request.Tuples)
		if e != nil {
			return q, e
		}
		q.Request.TupleRequired = map[string][]string{}
		union := map[string]bool{}
		for i, rule := range q.Resolved {
			if operation == "isolation" && rule.Decision != "deny" {
				return q, ErrInvalid
			}
			if rule.Path.ID != "" {
				vpn, e := resolve(rule.Path)
				if e != nil {
					return q, e
				}
				if q.VPN.Ref.ID != "" && q.VPN.Ref != vpn.Ref {
					return q, ErrUnsupported
				}
				q.VPN = vpn
			}
			q.Request.Tuples[i] = rule.Tuple
			q.Request.Policies = appendUniqueRef(q.Request.Policies, rule.Policy)
			required := []string{"source.binding"}
			if rule.Decision == "deny" {
				required = append(required, "dns.control", "dns.denied", "isolation.baseline", "isolation.coverage", "isolation.absence", "isolation.boundary")
			} else {
				required = append(required, "dns.response")
				if rule.Path.ID != "" {
					required = append(required, "path.selection")
				}
				if rule.Filtering {
					required = append(required, "dns.filtering")
				}
			}
			if rule.FailClosed {
				required = append(required, "guard.fail_closed")
			}
			q.Request.TupleRequired[hashJSON(rule.Tuple)] = required
			for _, p := range required {
				union[p] = true
			}
		}
		for p := range union {
			q.Request.Required = append(q.Request.Required, p)
		}
		sort.Strings(q.Request.Required)
	default:
		return q, ErrInvalid
	}
	s, e := r.load()
	if e != nil {
		return q, e
	}
	selected := map[string]Object{}
	var walk func(Object) error
	walk = func(o Object) error {
		if o.Ref.ID == "" {
			return nil
		}
		if _, ok := selected[o.Ref.ID]; ok {
			return nil
		}
		if len(selected) >= 64 {
			return ErrUnsupported
		}
		selected[o.Ref.ID] = o
		for _, ref := range []Ref{o.Binding.Gateway, o.Binding.VPN, o.Binding.Source, o.Binding.Control} {
			if ref.ID != "" {
				child, e := resolve(ref)
				if e != nil {
					return e
				}
				if e = walk(child); e != nil {
					return e
				}
			}
		}
		return nil
	}
	for _, o := range []Object{q.Target, q.Source, q.Gateway, q.VPN, q.Control} {
		if e = walk(o); e != nil {
			return q, e
		}
	}
	if baseline != nil {
		for _, ref := range baseline.Request.Objects {
			o, e := r.ResolveRef(ref)
			if e != nil {
				return q, e
			}
			if e = walk(o); e != nil {
				return q, e
			}
		}
		for _, ref := range baseline.Request.Policies {
			q.Request.Policies = appendUniqueRef(q.Request.Policies, ref)
		}
	}
	type node struct {
		Ref     Ref
		Kind    Kind
		Binding Binding
	}
	var nodes []node
	for _, o := range selected {
		q.Request.Objects = append(q.Request.Objects, o.Ref)
		nodes = append(nodes, node{o.Ref, o.Kind, o.Binding})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Ref.ID < nodes[j].Ref.ID })
	sort.Slice(q.Request.Objects, func(i, j int) bool { return q.Request.Objects[i].ID < q.Request.Objects[j].ID })
	var rules []Rule
	for _, ref := range q.Request.Policies {
		found := false
		for _, rule := range s.Policies {
			if rule.Ref == ref {
				rule.Alias = ""
				rules = append(rules, rule)
				found = true
				break
			}
		}
		if !found {
			return q, ErrStale
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Ref.ID < rules[j].Ref.ID })
	q.Request.MetadataDigest = hashJSON(struct {
		Nodes []node
		Rules []Rule
	}{nodes, rules})
	sealOpenWrtQuestion(&q)
	return q, nil
}
func appendUniqueRef(refs []Ref, ref Ref) []Ref {
	for _, r := range refs {
		if r == ref {
			return refs
		}
	}
	return append(refs, ref)
}
