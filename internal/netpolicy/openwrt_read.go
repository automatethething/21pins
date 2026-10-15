package netpolicy

import (
	"context"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type openWrtRead func(context.Context, Binding, string, ...string) ([]byte, error)
type nativeOutputLimit struct{}
type owReadSession struct {
	ctx     context.Context
	permit  func(context.Context, string) error
	read    openWrtRead
	binding Binding
	used    int
}

func (r *owReadSession) call(tool string, args ...string) ([]byte, error) {
	if r.ctx.Err() != nil || r.used >= 32 || r.permit == nil || r.read == nil {
		return nil, ErrUnsupported
	}
	ctx, cancel := context.WithTimeout(r.ctx, 3*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, nativeOutputLimit{}, 64<<10)
	if e := r.permit(ctx, "network.read"); e != nil {
		return nil, e
	}
	r.used++
	raw, e := r.read(ctx, r.binding, tool, args...)
	if ctx.Err() != nil {
		return nil, ErrUnsupported
	}
	if e != nil {
		return nil, e
	}
	if len(raw) > 64<<10 {
		return nil, ErrUnsupported
	}
	return raw, nil
}
func owMember(q Question, raw []byte) bool {
	set := q.Gateway.Binding.OpenWrt.DestinationSet
	if set == nil {
		return false
	}
	target := q.Service.Binding.Target
	if target == "" {
		target = q.Gateway.Binding.Target
	}
	var body struct{ Nftables []map[string]json.RawMessage }
	if json.Unmarshal(raw, &body) != nil {
		return false
	}
	found := 0
	for _, entry := range body.Nftables {
		if len(entry) != 1 {
			return false
		}
		for kind, data := range entry {
			if kind == "metainfo" {
				continue
			}
			if kind != "element" && kind != "set" {
				return false
			}
			var value struct {
				Family, Table, Name string
				Elem                []string
			}
			if json.Unmarshal(data, &value) != nil || value.Family != set.Family || value.Table != set.Table || value.Name != set.Name || len(value.Elem) != 1 || value.Elem[0] != target {
				return false
			}
			found++
		}
	}
	return found == 1
}
func (r *owReadSession) sample(q Question) (openWrtSnapshot, error) {
	b := q.Gateway.Binding
	s := openWrtSnapshot{scope: openWrtScope(q), context: b.Context, start: time.Now().UTC(), chains: map[string][]byte{}}
	raw, e := r.call("ubus", "call", "network.interface."+b.OpenWrt.LogicalNetwork, "status")
	if e != nil {
		return s, e
	}
	// Project before retaining/comparing: do not keep arbitrary protocol data, DNS, MACs or uptime.
	var logical struct {
		Up        bool   `json:"up"`
		Device    string `json:"l3_device"`
		Addresses []struct {
			Address string `json:"address"`
			Mask    int    `json:"mask"`
		} `json:"ipv4-address"`
	}
	if json.Unmarshal(raw, &logical) != nil || len(logical.Addresses) > 16 {
		return s, ErrUnsupported
	}
	s.logical, _ = json.Marshal(logical)
	for _, chain := range b.OpenWrt.Chains {
		raw, e = r.call("nft", "-j", "list", "chain", chain.Family, chain.Table, chain.Chain)
		if e != nil {
			return s, e
		}
		s.chains[openWrtChainKey(chain)] = raw
	}
	if set := b.OpenWrt.DestinationSet; set != nil {
		s.set, e = r.call("nft", "-j", "-t", "list", "set", set.Family, set.Table, set.Name)
		if e != nil {
			return s, e
		}
		target := q.Service.Binding.Target
		if target == "" {
			target = b.Target
		}
		member, err := r.call("nft", "-j", "get", "element", set.Family, set.Table, set.Name, "{", target, "}")
		if err != nil {
			return s, err
		}
		// Only unambiguous positive native membership is supported. All failures/nonmember ambiguity are unknown.
		s.setKnown = owMember(q, member)
		s.setMember = s.setKnown
	}
	if q.Source.Ref.ID != "" {
		address, e := netip.ParseAddr(q.Source.Binding.Address)
		if e != nil || !address.Is4() {
			return s, ErrUnsupported
		}
		s.rules, e = r.call("ip", "-j", "-4", "rule", "show")
		if e != nil {
			return s, e
		}
		var rows []json.RawMessage
		if json.Unmarshal(s.rules, &rows) != nil || len(rows) > 64 {
			return s, ErrUnsupported
		}
	}
	s.end = time.Now().UTC()
	n := normalizeOpenWrt(q, s)
	if n.markKnown {
		target := q.Service.Binding.Target
		if target == "" {
			target = b.Target
		}
		s.route, e = r.call("ip", "-j", "-4", "route", "get", target, "from", q.Source.Binding.Address, "iif", q.Source.Binding.Ingress, "mark", strconv.FormatUint(uint64(n.mark), 10))
		if e != nil {
			return s, e
		}
	}
	s.end = time.Now().UTC()
	return s, nil
}
func readOpenWrtSnapshot(parent context.Context, q Question, permit func(context.Context, string) error, read openWrtRead) (openWrtSnapshot, error) {
	q, e := freezeOpenWrtQuestion(q)
	if e != nil {
		return openWrtSnapshot{}, e
	}
	b := q.Gateway.Binding
	if b.OpenWrt == nil || !validOpenWrt(q.Gateway) || b.OpenWrt.LogicalNetwork == "" || (b.OpenWrt.Profile != "fw4-basic" && b.OpenWrt.Profile != "gl-policy-fw4") {
		return openWrtSnapshot{}, ErrUnsupported
	}
	for _, chain := range b.OpenWrt.Chains {
		if chain.Family == "ip6" {
			return openWrtSnapshot{}, ErrUnsupported
		}
	}
	target := q.Service.Binding.Target
	if target == "" {
		target = b.Target
	}
	address, e := netip.ParseAddr(target)
	if e != nil || !address.Is4() {
		return openWrtSnapshot{}, ErrUnsupported
	}
	if b.OpenWrt.DestinationSet != nil && b.OpenWrt.DestinationSet.ElementFamily != "ipv4" {
		return openWrtSnapshot{}, ErrUnsupported
	}
	worst := 2*(1+len(b.OpenWrt.Chains)) + 1 + 3*len(b.OpenWrt.StoredSections)
	if b.OpenWrt.DestinationSet != nil {
		worst += 4
	}
	if q.Source.Ref.ID != "" {
		worst += 4
	}
	if worst > 32 {
		return openWrtSnapshot{}, ErrUnsupported
	}
	// Reserve15s of the existing100s operation for cleanup; no retries or background collector.
	ctx, cancel := context.WithTimeout(parent, 85*time.Second)
	defer cancel()
	r := owReadSession{ctx: ctx, permit: permit, read: read, binding: cloneBinding(b)}
	first, e := r.sample(q)
	if e != nil {
		return first, e
	}
	stored := map[string]string{}
	value, e := r.call("uci", "-q", "get", "network."+b.OpenWrt.LogicalNetwork+".device")
	if e != nil {
		return first, e
	}
	stored["network.device"] = strings.TrimSpace(string(value))
	if len(value) > 128 {
		return first, ErrUnsupported
	}
	for _, section := range b.OpenWrt.StoredSections {
		for _, field := range []string{"src", "dest", "enabled"} {
			value, e = r.call("uci", "-q", "get", "firewall."+section+"."+field)
			if e != nil {
				return first, e
			}
			if len(value) > 128 {
				return first, ErrUnsupported
			}
			stored[section+"."+field] = strings.TrimSpace(string(value))
		}
	}
	second, e := r.sample(q)
	if e != nil {
		return first, e
	}
	if openWrtRuntimeDigest(first) != openWrtRuntimeDigest(second) {
		return first, ErrStale
	}
	first.end = second.end
	first.stored = stored
	return first, nil
}
func (c *collector) collectOpenWrt(ctx context.Context, q Question) Collection {
	out := Collection{Cleanup: true}
	q, e := freezeOpenWrtQuestion(q)
	if e != nil {
		out.Missing = []string{"openwrt_frozen_scope"}
		return out
	}
	s, e := readOpenWrtSnapshot(ctx, q, c.permit, c.readNamespace)
	if e != nil {
		out.Missing = []string{safeError(e)}
		return out
	}
	s.runtime = true
	s.synthetic = c.fixture
	s.closed = c.fixture && c.closed[q.Gateway.Binding.Context]
	n := normalizeOpenWrt(q, s)
	add := func(property string, value bool) {
		f := c.fact(property, q, nil, value)
		f.WindowStart = s.start
		f.WindowEnd = s.end
		f.RuntimeBinding = n.runtimeDigest
		out.Facts = append(out.Facts, f)
	}
	if !n.runtime {
		return out
	}
	add("gateway.binding", s.context == q.Gateway.Binding.Context)
	add("gateway.reader", true)
	if n.logical {
		add("gateway.interface_binding", true)
	}
	if n.scopeSupported {
		add("gateway.policy_scope", true)
	}
	if n.sourceLogical {
		add("network.logical_binding", true)
	} // not client-origin/source.binding proof
	if n.routeSelected {
		add("routing.policy_selection", true)
	} // prospective FIB, never observed path.selection
	if n.forwarding != nil {
		add("forwarding.candidate", *n.forwarding)
		if n.coverage {
			add("forwarding.permission", *n.forwarding)
		}
	}
	if n.guardCandidate {
		add("enforcement.guard_candidate", true)
		if n.coverage {
			add("enforcement.guard", true)
		}
	}
	support := Partial
	missing := []string{"live_firmware_compatibility", "global_override_coverage", "client_origin_and_observed_path"}
	if !n.scopeSupported {
		missing = append(missing, "native_subset")
	}
	out.Capabilities = []Capability{{Operation: "gateway_evidence", Support: support, Scope: append([]Ref(nil), q.Request.Objects...), Missing: missing}}
	if q.Request.Operation != "gateway" {
		out.Missing = append(out.Missing, "openwrt_readonly_no_client_proof")
	}
	return out
}
