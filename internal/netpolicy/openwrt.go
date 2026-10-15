package netpolicy

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
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

// Raw samples never leave the private normalizer. JSON cannot set the runtime/closure seals.
type openWrtSnapshot struct {
	scope, context             string
	start, end                 time.Time
	logical, rules, route, set []byte
	chains                     map[string][]byte
	stored                     map[string]string
	setKnown, setMember        bool
	runtime, synthetic, closed bool
}
type openWrtEvidence struct {
	logical, sourceLogical, markKnown, routeSelected, vpnSelected, guardCandidate, coverage, runtime, synthetic, scopeSupported bool
	mark                                                                                                                        uint32
	forwarding                                                                                                                  *bool
	runtimeDigest, storedDigest                                                                                                 string
	missing                                                                                                                     []string
}

func openWrtScope(q Question) string {
	q.Gateway = cloneObject(q.Gateway)
	q.Source = cloneObject(q.Source)
	q.Service = cloneObject(q.Service)
	q.VPN = cloneObject(q.VPN)
	q.Gateway.Alias = ""
	q.Source.Alias = ""
	q.Service.Alias = ""
	q.VPN.Alias = ""
	return hashJSON(struct {
		Request                       string
		Gateway, Source, Service, VPN Object
	}{q.Request.Digest("network.read"), q.Gateway, q.Source, q.Service, q.VPN})
}
func openWrtChainKey(c BoundChain) string { return c.Family + ":" + c.Table + ":" + c.Chain }
func owBool(b bool) *bool                 { return &b }
func owNumber(raw json.RawMessage) (uint32, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	var n uint32
	if json.Unmarshal(raw, &n) == nil {
		return n, true
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return 0, false
	}
	v, e := strconv.ParseUint(s, 0, 32)
	return uint32(v), e == nil
}
func owSameAddress(text, want string) bool {
	if p, e := netip.ParsePrefix(text); e == nil {
		return p.Bits() == 32 && p.Addr().String() == want
	}
	return text == want
}
func owPrefix(text, address string) (bool, bool) {
	if text == "" || text == "all" {
		return true, true
	}
	if p, e := netip.ParsePrefix(text); e == nil {
		a, e := netip.ParseAddr(address)
		return e == nil && p.Contains(a), e == nil
	}
	a, e := netip.ParseAddr(text)
	b, be := netip.ParseAddr(address)
	return e == nil && be == nil && a == b, e == nil && be == nil
}

// Counter/handle churn is not configuration identity; ordered rule semantics are retained.
func owSemantic(raw []byte) any {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return "invalid"
	}
	var clean func(any) any
	clean = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			out := map[string]any{}
			for k, v := range x {
				switch k {
				case "counter", "handle", "packets", "bytes", "comment", "position", "metainfo":
					continue
				}
				out[k] = clean(v)
			}
			return out
		case []any:
			out := []any{}
			for _, v := range x {
				c := clean(v)
				if m, ok := c.(map[string]any); ok && len(m) == 0 {
					continue
				}
				out = append(out, c)
			}
			return out
		}
		return v
	}
	return clean(value)
}
func openWrtRuntimeDigest(s openWrtSnapshot) string {
	chains := map[string]any{}
	for k, v := range s.chains {
		chains[k] = owSemantic(v)
	}
	return hashJSON(struct {
		Scope, Context             string
		Logical, Rules, Route, Set any
		Chains                     map[string]any
		Known, Member              bool
	}{s.scope, s.context, owSemantic(s.logical), owSemantic(s.rules), owSemantic(s.route), owSemantic(s.set), chains, s.setKnown, s.setMember})
}

type owRuleState struct {
	source, destination, ingress, oifNot, action, jump string
	mark                                               uint32
	valid                                              bool
}
type owChainState struct {
	bound  BoundChain
	policy string
	rules  []owRuleState
	valid  bool
}

func owParseRule(expr []map[string]json.RawMessage) owRuleState {
	r := owRuleState{valid: true}
	seen := map[string]bool{}
	acted := false
	for _, part := range expr {
		if len(part) != 1 {
			r.valid = false
		}
		for key, value := range part {
			switch key {
			case "counter", "comment":
				continue
			case "match":
				if acted {
					r.valid = false
				}
				var m struct {
					Op   string
					Left struct {
						Payload struct{ Protocol, Field string }
						Meta    struct{ Key string }
					}
					Right string
				}
				if json.Unmarshal(value, &m) != nil {
					r.valid = false
					continue
				}
				field := m.Left.Payload.Field
				if m.Left.Meta.Key != "" {
					field = m.Left.Meta.Key
				} else if m.Left.Payload.Protocol != "ip" {
					r.valid = false
				}
				if seen[field] {
					r.valid = false
				}
				seen[field] = true
				switch field {
				case "saddr":
					r.source = m.Right
				case "daddr":
					r.destination = m.Right
				case "iifname":
					r.ingress = m.Right
				case "oifname":
					if m.Op != "!=" || !nativePattern.MatchString(m.Right) {
						r.valid = false
					}
					r.oifNot = m.Right
				default:
					r.valid = false
				}
				if field != "oifname" && m.Op != "==" {
					r.valid = false
				}
			case "mangle":
				if acted {
					r.valid = false
				}
				acted = true
				var m struct {
					Key   struct{ Meta struct{ Key string } }
					Value json.RawMessage
				}
				if json.Unmarshal(value, &m) != nil || m.Key.Meta.Key != "mark" {
					r.valid = false
				}
				var ok bool
				r.mark, ok = owNumber(m.Value)
				if !ok {
					r.valid = false
				}
				r.action = "mark"
			case "accept", "drop", "reject", "return":
				if acted {
					r.valid = false
				}
				acted = true
				r.action = key
			case "jump":
				if acted {
					r.valid = false
				}
				acted = true
				var target struct{ Target string }
				if json.Unmarshal(value, &target) != nil || !openWrtName.MatchString(target.Target) {
					r.valid = false
				}
				r.action = "jump"
				r.jump = target.Target
			default:
				r.valid = false
			}
		}
	}
	if r.action == "" {
		r.valid = false
	}
	return r
}
func owParseChain(c BoundChain, raw []byte) owChainState {
	out := owChainState{bound: c, valid: true}
	var body struct{ Nftables []map[string]json.RawMessage }
	if json.Unmarshal(raw, &body) != nil || len(body.Nftables) > 258 {
		out.valid = false
		return out
	}
	metadata := 0
	for _, entry := range body.Nftables {
		if len(entry) != 1 {
			out.valid = false
		}
		for kind, raw := range entry {
			switch kind {
			case "metainfo":
				continue
			case "chain":
				var m struct {
					Family, Table, Name, Hook, Type, Policy string
					Prio                                    *int32
				}
				if json.Unmarshal(raw, &m) != nil || m.Family != c.Family || m.Table != c.Table || m.Name != c.Chain || m.Hook != c.Hook || (c.Hook != "" && (m.Type != "filter" || m.Prio == nil || *m.Prio != *c.Priority || (m.Policy != "accept" && m.Policy != "drop"))) {
					out.valid = false
				}
				metadata++
				out.policy = m.Policy
			case "rule":
				var r struct {
					Family, Table, Chain string
					Expr                 []map[string]json.RawMessage
				}
				if json.Unmarshal(raw, &r) != nil || r.Family != c.Family || r.Table != c.Table || r.Chain != c.Chain || len(r.Expr) > 32 {
					out.valid = false
					continue
				}
				out.rules = append(out.rules, owParseRule(r.Expr))
			default:
				out.valid = false
			}
		}
	}
	out.valid = out.valid && metadata == 1
	return out
}
func owSetSupported(q Question, s openWrtSnapshot) bool {
	set := q.Gateway.Binding.OpenWrt.DestinationSet
	if set == nil {
		return false
	}
	var body struct{ Nftables []map[string]json.RawMessage }
	if json.Unmarshal(s.set, &body) != nil {
		return false
	}
	found := 0
	for _, entry := range body.Nftables {
		for kind, raw := range entry {
			if kind == "metainfo" {
				continue
			}
			if kind != "set" {
				return false
			}
			var m struct {
				Family, Table, Name, Type string
				Flags                     []string
				Elem                      []any
			}
			if json.Unmarshal(raw, &m) != nil || m.Family != set.Family || m.Table != set.Table || m.Name != set.Name || m.Type != "ipv4_addr" || len(m.Flags) != 0 || len(m.Elem) != 0 || set.ElementFamily != "ipv4" {
				return false
			}
			found++
		}
	}
	return found == 1
}
func owRuleMatches(r owRuleState, q Question, s openWrtSnapshot) (bool, bool) {
	target := q.Service.Binding.Target
	if target == "" {
		target = q.Gateway.Binding.Target
	}
	// Only parsed known selectors can exclude a rule; an invalid rule may act before its selectors.
	if !r.valid {
		return false, false
	}
	if r.source != "" && !owSameAddress(r.source, q.Source.Binding.Address) {
		if a, e := netip.ParseAddr(r.source); e == nil && a.Is4() {
			return false, true
		}
		if p, e := netip.ParsePrefix(r.source); e == nil && p.Bits() == 32 {
			return false, true
		}
		return false, false
	}
	if r.ingress != "" && r.ingress != q.Source.Binding.Ingress {
		return false, true
	}
	if r.destination != "" {
		if strings.HasPrefix(r.destination, "@") {
			set := q.Gateway.Binding.OpenWrt.DestinationSet
			if set == nil || r.destination != "@"+set.Name || !s.setKnown || !owSetSupported(q, s) {
				return false, false
			}
			if !s.setMember {
				return false, true
			}
		} else if !owSameAddress(r.destination, target) {
			if a, e := netip.ParseAddr(r.destination); e == nil && a.Is4() {
				return false, true
			}
			return false, false
		}
	}
	return true, true
}
func owRoutePolicy(q Question, s openWrtSnapshot, mark uint32) (bool, string, bool) {
	var route []struct {
		Dev, Type string
		Table     json.RawMessage
	}
	if json.Unmarshal(s.route, &route) != nil || len(route) != 1 {
		return false, "", false
	}
	tableName := func(raw json.RawMessage) (string, bool) {
		if len(raw) == 0 {
			return "254", true
		}
		if n, ok := owNumber(raw); ok {
			return strconv.FormatUint(uint64(n), 10), true
		}
		var v string
		if json.Unmarshal(raw, &v) != nil {
			return "", false
		}
		switch v {
		case "local":
			return "255", true
		case "main":
			return "254", true
		case "default":
			return "253", true
		}
		return "", false
	}
	selected, ok := tableName(route[0].Table)
	if !ok || route[0].Dev == "" || (route[0].Type != "" && route[0].Type != "unicast") {
		return false, "", false
	}
	var rows []map[string]json.RawMessage
	if json.Unmarshal(s.rules, &rows) != nil || len(rows) > 64 {
		return false, "", false
	}
	type row struct {
		priority uint32
		table    string
	}
	var applicable []row
	target := q.Service.Binding.Target
	if target == "" {
		target = q.Gateway.Binding.Target
	}
	seen := map[uint32]bool{}
	for _, fields := range rows {
		var source, dest, iif string
		for key, ptr := range map[string]*string{"src": &source, "dst": &dest, "iif": &iif} {
			if raw, ok := fields[key]; ok {
				if string(raw) == "null" || json.Unmarshal(raw, ptr) != nil {
					return false, "", false
				}
			}
		}
		sm, sk := owPrefix(source, q.Source.Binding.Address)
		dm, dk := owPrefix(dest, target)
		if sk && dk && (!sm || !dm || iif != "" && iif != q.Source.Binding.Ingress) {
			continue
		}
		if !sk || !dk {
			return false, "", false
		}
		priority, pok := owNumber(fields["priority"])
		if !pok || seen[priority] {
			return false, "", false
		}
		seen[priority] = true
		for key, value := range fields {
			switch key {
			case "priority", "src", "dst", "iif", "fwmark", "fwmask", "table", "protocol":
			case "flags":
				if string(value) != "[]" && string(value) != "null" {
					return false, "", false
				}
			case "action":
				var action string
				json.Unmarshal(value, &action)
				if action != "to_tbl" && action != "lookup" {
					return false, "", false
				}
			default:
				return false, "", false
			}
		}
		if raw, exists := fields["fwmark"]; exists {
			v, ok := owNumber(raw)
			mask := uint32(0xffffffff)
			if raw, yes := fields["fwmask"]; yes {
				var valid bool
				mask, valid = owNumber(raw)
				if !valid {
					return false, "", false
				}
			}
			if !ok {
				return false, "", false
			}
			if mark&mask != v&mask {
				continue
			}
		}
		if len(fields["table"]) == 0 {
			return false, "", false
		}
		table, ok := tableName(fields["table"])
		if !ok {
			return false, "", false
		}
		applicable = append(applicable, row{priority, table})
	}
	sort.Slice(applicable, func(i, j int) bool { return applicable[i].priority < applicable[j].priority })
	// The kernel result accounts for earlier plain lookup misses; unsupported actions were not discarded.
	for _, row := range applicable {
		if row.table == selected {
			return true, route[0].Dev, true
		}
	}
	return false, "", false
}
func normalizeOpenWrt(q Question, s openWrtSnapshot) openWrtEvidence {
	n := openWrtEvidence{runtime: s.runtime, synthetic: s.synthetic, runtimeDigest: openWrtRuntimeDigest(s), storedDigest: hashJSON(s.stored)}
	fail := func(code string) openWrtEvidence { n.missing = append(n.missing, code); return n }
	binding := q.Gateway.Binding.OpenWrt
	if binding == nil || !validOpenWrt(q.Gateway) || s.scope != openWrtScope(q) || s.context != q.Gateway.Binding.Context || s.start.IsZero() || s.end.Before(s.start) || s.end.After(time.Now().Add(time.Second)) || time.Since(s.end) > 10*time.Minute {
		return fail("openwrt_scope_or_time")
	}
	var logical struct {
		Up        bool
		Device    string                     `json:"l3_device"`
		Addresses []struct{ Address string } `json:"ipv4-address"`
	}
	if json.Unmarshal(s.logical, &logical) != nil || !logical.Up || logical.Device != q.Gateway.Binding.Interface {
		return fail("openwrt_logical_binding")
	}
	for _, a := range logical.Addresses {
		if a.Address == q.Gateway.Binding.Address {
			n.logical = true
		}
	}
	if !n.logical {
		return fail("openwrt_address_binding")
	}
	n.sourceLogical = q.Source.Kind == Network && q.Source.Binding.Gateway == q.Gateway.Ref && q.Source.Binding.OpenWrt != nil && q.Source.Binding.OpenWrt.LogicalNetwork == binding.LogicalNetwork && q.Source.Binding.Ingress == logical.Device
	if binding.Profile != "fw4-basic" && binding.Profile != "gl-policy-fw4" {
		return fail("openwrt_profile_unsupported")
	}
	target := q.Service.Binding.Target
	if target == "" {
		target = q.Gateway.Binding.Target
	}
	a, e := netip.ParseAddr(target)
	if e != nil || !a.Is4() {
		return fail("openwrt_family_unsupported")
	}
	chains := map[string]owChainState{}
	supported := true
	for _, c := range binding.Chains {
		parsed := owParseChain(c, s.chains[openWrtChainKey(c)])
		if c.Family == "ip6" || !parsed.valid {
			supported = false
		}
		chains[openWrtChainKey(c)] = parsed
	}
	if len(chains) == 0 {
		supported = false
	}
	roots := []owChainState{}
	for _, c := range chains {
		if c.bound.Hook != "" {
			roots = append(roots, c)
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		a, b := roots[i].bound, roots[j].bound
		if a.Hook != b.Hook {
			return a.Hook < b.Hook
		}
		if *a.Priority == *b.Priority {
			supported = false
		}
		return *a.Priority < *b.Priority
	})
	markKnown := false
	mark := uint32(0)
	forwardSeen := false
	forwardAllowed := true
	reached := map[string]bool{}
	var walk func(owChainState, int, map[string]bool) (string, bool)
	walk = func(chain owChainState, depth int, stack map[string]bool) (string, bool) {
		key := openWrtChainKey(chain.bound)
		if depth > 4 || stack[key] || !chain.valid {
			return "", false
		}
		stack[key] = true
		defer delete(stack, key)
		reached[key] = true
		for _, r := range chain.rules {
			matches, known := owRuleMatches(r, q, s)
			if !known {
				return "", false
			}
			if !matches {
				continue
			}
			switch r.action {
			case "mark":
				if chain.bound.Role != "classifier" || r.source == "" || r.destination == "" || r.ingress == "" || r.oifNot != "" || !n.sourceLogical {
					return "", false
				}
				mark = r.mark
				markKnown = true
			case "jump":
				child, exists := chains[chain.bound.Family+":"+chain.bound.Table+":"+r.jump]
				if !exists || child.bound.Hook != "" || child.bound.Role != chain.bound.Role {
					return "", false
				}
				verdict, ok := walk(child, depth+1, stack)
				if !ok {
					return "", false
				}
				if verdict == "drop" || verdict == "accept" {
					return verdict, true
				}
			case "return":
				if chain.bound.Hook != "" {
					return "", false
				}
				return "return", true
			case "accept":
				if r.oifNot != "" {
					return "", false
				}
				return "accept", true
			case "drop", "reject":
				if chain.bound.Role == "guard" && r.source != "" && r.destination != "" && r.ingress != "" && (r.oifNot == "" || q.VPN.Binding.Interface != "" && r.oifNot == q.VPN.Binding.Interface) {
					n.guardCandidate = true
				}
				if r.oifNot != "" {
					continue
				}
				return "drop", true
			default:
				return "", false
			}
		}
		if chain.bound.Hook != "" && chain.policy == "drop" {
			return "drop", true
		}
		return "return", true
	}
	// Classification is only for forwarded client origin; output never substitutes for that context.
	for _, root := range roots {
		if root.bound.Role != "classifier" {
			continue
		}
		if root.bound.Hook != "prerouting" {
			supported = false
			continue
		}
		verdict, ok := walk(root, 1, map[string]bool{})
		if !ok {
			supported = false
			markKnown = false
			break
		}
		if verdict == "drop" {
			markKnown = false
			break
		}
	}
	if supported && markKnown {
		n.markKnown = true
		n.mark = mark
		n.routeSelected, _, _ = owRoutePolicy(q, s, mark)
		if n.routeSelected {
			_, dev, _ := owRoutePolicy(q, s, mark)
			n.vpnSelected = q.VPN.Binding.Interface != "" && dev == q.VPN.Binding.Interface
		} else {
			supported = false
			n.missing = append(n.missing, "openwrt_rpdb_coverage")
		}
	}
	for _, root := range roots {
		if root.bound.Role == "classifier" {
			continue
		}
		if root.bound.Hook != "forward" {
			supported = false
			continue
		}
		verdict, ok := walk(root, 1, map[string]bool{})
		if !ok {
			supported = false
			continue
		}
		if root.bound.Role == "forwarding" {
			forwardSeen = true
			if verdict == "drop" {
				forwardAllowed = false
			}
		}
	}
	// Uncalled registered chains cannot silently contribute or count as complete coverage.
	for key := range chains {
		if !reached[key] {
			supported = false
		}
	}
	if forwardSeen && supported {
		n.forwarding = owBool(forwardAllowed)
	}
	n.scopeSupported = supported
	n.coverage = s.closed && supported && n.markKnown && n.routeSelected
	if !supported {
		n.missing = append(n.missing, "openwrt_unsupported_or_unreachable_policy")
	}
	return n
}
