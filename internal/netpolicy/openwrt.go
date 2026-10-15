package netpolicy

import (
	"regexp"
	"sort"
)

type OpenWrtBinding struct {
	LogicalNetwork string       `json:"logical_network,omitempty"`
	Profile        string       `json:"profile,omitempty"`
	Chains         []BoundChain `json:"chains,omitempty"`
	DestinationSet *BoundSet    `json:"destination_set,omitempty"`
	StoredSections []string     `json:"stored_sections,omitempty"`
}
type BoundChain struct {
	Family   string `json:"family"`
	Table    string `json:"table"`
	Chain    string `json:"chain"`
	Role     string `json:"role"`
	Hook     string `json:"hook,omitempty"`
	Priority *int32 `json:"priority,omitempty"`
}
type BoundSet struct {
	Family        string `json:"family"`
	Table         string `json:"table"`
	Name          string `json:"name"`
	ElementFamily string `json:"element_family"`
}

var openWrtName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,47}$`)

func cloneBinding(b Binding) Binding {
	b.Transports = append([]string(nil), b.Transports...)
	b.AccessModes = append([]string(nil), b.AccessModes...)
	if b.OpenWrt == nil {
		return b
	}
	s := *b.OpenWrt
	s.Chains = append([]BoundChain(nil), s.Chains...)
	s.StoredSections = append([]string(nil), s.StoredSections...)
	for i := range s.Chains {
		if s.Chains[i].Priority != nil {
			p := *s.Chains[i].Priority
			s.Chains[i].Priority = &p
		}
	}
	if s.DestinationSet != nil {
		set := *s.DestinationSet
		s.DestinationSet = &set
	}
	sort.Slice(s.Chains, func(i, j int) bool { return hashJSON(s.Chains[i]) < hashJSON(s.Chains[j]) })
	sort.Strings(s.StoredSections)
	b.OpenWrt = &s
	return b
}
func cloneObject(o Object) Object { o.Binding = cloneBinding(o.Binding); return o }
func validOpenWrt(o Object) bool {
	s := o.Binding.OpenWrt
	if s == nil {
		return true
	}
	if s.LogicalNetwork != "" && !openWrtName.MatchString(s.LogicalNetwork) {
		return false
	}
	if o.Kind == Network {
		return s.LogicalNetwork != "" && s.Profile == "" && len(s.Chains) == 0 && s.DestinationSet == nil && len(s.StoredSections) == 0 && o.Binding.Gateway.ID != ""
	}
	if o.Kind != Gateway || len(s.Profile) > 48 || len(s.Chains) > 8 || len(s.StoredSections) > 8 {
		return false
	}
	seen := map[string]bool{}
	for _, c := range s.Chains {
		if (c.Family != "ip" && c.Family != "ip6" && c.Family != "inet") || !openWrtName.MatchString(c.Table) || !openWrtName.MatchString(c.Chain) {
			return false
		}
		key := c.Family + ":" + c.Table + ":" + c.Chain
		if seen[key] {
			return false
		}
		seen[key] = true
		if (c.Hook == "") != (c.Priority == nil) {
			return false
		}
		if c.Hook != "" && c.Hook != "prerouting" && c.Hook != "forward" && c.Hook != "output" {
			return false
		}
		if c.Role != "classifier" && c.Role != "forwarding" && c.Role != "guard" {
			return false
		}
		if c.Role == "classifier" && c.Hook == "forward" || c.Role == "forwarding" && c.Hook != "" && c.Hook != "forward" {
			return false
		}
	}
	seen = map[string]bool{}
	for _, section := range s.StoredSections {
		if !openWrtName.MatchString(section) || seen[section] {
			return false
		}
		seen[section] = true
	}
	if s.DestinationSet != nil {
		set := s.DestinationSet
		if !openWrtName.MatchString(set.Table) || !openWrtName.MatchString(set.Name) || (set.Family != "ip" && set.Family != "ip6" && set.Family != "inet") || (set.ElementFamily != "ipv4" && set.ElementFamily != "ipv6") {
			return false
		}
		if set.Family == "ip" && set.ElementFamily != "ipv4" || set.Family == "ip6" && set.ElementFamily != "ipv6" {
			return false
		}
	}
	return true
}

// ponytail: private deep-owned read snapshot, not a new registry or authority mechanism.
type openWrtQuestion struct {
	target, source, service, gateway, vpn Object
	digest                                string
}

func sealOpenWrtQuestion(q *Question) {
	if q.Gateway.Binding.OpenWrt == nil {
		return
	}
	q.openwrtBound = &openWrtQuestion{cloneObject(q.Target), cloneObject(q.Source), cloneObject(q.Service), cloneObject(q.Gateway), cloneObject(q.VPN), q.Request.Digest("network.read")}
}
func freezeOpenWrtQuestion(q Question) (Question, error) {
	if q.openwrtBound == nil {
		if q.Gateway.Binding.OpenWrt != nil {
			return q, ErrStale
		}
		return q, nil
	}
	b := q.openwrtBound
	if q.Request.Digest("network.read") != b.digest {
		return q, ErrStale
	}
	q.Target = cloneObject(b.target)
	q.Source = cloneObject(b.source)
	q.Service = cloneObject(b.service)
	q.Gateway = cloneObject(b.gateway)
	q.VPN = cloneObject(b.vpn)
	return q, nil
}
