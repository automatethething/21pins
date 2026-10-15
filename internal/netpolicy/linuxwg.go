package netpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Question struct {
	Request                                        ObservationRequest
	Target, Source, Service, Gateway, VPN, Control Object
	Resolved                                       []ResolvedTuple
	Baseline                                       *Assessment
}
type Collection struct {
	Facts   []Fact
	Cleanup bool
	Missing []string
}
type nativeRun func(context.Context, string, string, ...string) ([]byte, error)
type collector struct {
	permit  func(context.Context, string) error
	run     nativeRun
	fixture bool
	// Only a trusted isolated fixture coordinator populates this; never manifest data.
	closed map[string]bool
}

func newCollector(permit func(context.Context, string) error) *collector {
	return &collector{permit: permit, run: runNative}
}
func CollectNative(ctx context.Context, q Question, permit func(context.Context, string) error) Collection {
	return newCollector(permit).collect(ctx, q)
}

type boundedOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1<<20 {
		b.overflow = true
		return 0, ErrUnsupported
	}
	return b.Buffer.Write(p)
}
func runNative(parent context.Context, namespace, tool string, args ...string) ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrUnsupported
	}
	if tool != "ip" && tool != "wg" && tool != "nft" {
		return nil, ErrInvalid
	}
	// Execute only after the caller entered the verified namespace FD; never reopen an alias in ip netns exec.
	if namespace != "" {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C", "LC_ALL=C"}
	var out boundedOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if cmd.Run() != nil || out.overflow {
		return nil, ErrUnsupported
	}
	return out.Bytes(), nil
}
func (c *collector) read(ctx context.Context, b Binding, tool string, args ...string) ([]byte, error) {
	if c.permit == nil || c.permit(ctx, "network.read") != nil {
		return nil, ErrMissing
	}
	id, e := namespaceIdentity(b.Namespace)
	if e != nil || b.Context == "" || id != b.Context {
		return nil, ErrStale
	}
	var out []byte
	e = withinNamespace(ctx, b, func() error { var runErr error; out, runErr = c.run(ctx, "", tool, args...); return runErr })
	if e != nil {
		return nil, e
	}
	id, e = namespaceIdentity(b.Namespace)
	if e != nil || id != b.Context {
		return nil, ErrStale
	}
	return out, nil
}
func (c *collector) assurance() string {
	if c.fixture {
		return "synthetic_runtime"
	}
	return "runtime_validated"
}
func (c *collector) fact(property string, q Question, tuple *Tuple, value bool) Fact {
	return newFact(property, q.Request, tuple, value, time.Now().UTC(), c.assurance())
}
func (c *collector) sessionFact(q Question, at, now time.Time) Fact {
	fresh := at.Unix() > 0 && !at.After(now) && now.Sub(at) <= 180*time.Second
	f := newFact("vpn.session_freshness", q.Request, nil, fresh, now, c.assurance())
	if fresh {
		f.ValidUntil = at.Add(180 * time.Second)
	}
	return f
}

func interfaceMatches(data []byte, address string) bool {
	for _, f := range strings.Fields(string(data)) {
		if prefix, e := netip.ParsePrefix(f); e == nil && prefix.Addr().String() == address {
			return true
		}
	}
	return false
}
func (c *collector) interfaceBinding(ctx context.Context, o Object) (bool, error) {
	if o.Binding.Interface == "" || o.Binding.Address == "" {
		return false, ErrMissing
	}
	family := "-4"
	if addr, e := netip.ParseAddr(o.Binding.Address); e == nil && !addr.Is4() {
		family = "-6"
	}
	raw, e := c.read(ctx, o.Binding, "ip", "-o", family, "addr", "show", "dev", o.Binding.Interface)
	if e != nil {
		return false, e
	}
	return interfaceMatches(raw, o.Binding.Address), nil
}
func peerOwns(data []byte, peer, target string) bool {
	address, e := netip.ParseAddr(target)
	if e != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.ReplaceAll(line, ",", " "))
		if len(fields) < 2 || fields[0] != peer {
			continue
		}
		for _, s := range fields[1:] {
			prefix, e := netip.ParsePrefix(s)
			if e == nil && prefix.Contains(address) {
				return true
			}
		}
	}
	return false
}
func peerHandshake(data []byte, peer string) (time.Time, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != peer {
			continue
		}
		value, e := strconv.ParseInt(fields[1], 10, 64)
		if e != nil || value < 0 {
			return time.Time{}, false
		}
		return time.Unix(value, 0), true
	}
	return time.Time{}, false
}

type nftPolicy struct {
	supported bool
	denied    map[string]bool
	marks     map[string]uint32
	forwarded map[string]bool
	guards    map[string]string
	hook      string
	digest    string
}

func normalizeNFT(raw []byte, target string) nftPolicy {
	p := nftPolicy{supported: true, denied: map[string]bool{}, marks: map[string]uint32{}, forwarded: map[string]bool{}, guards: map[string]string{}, digest: hashJSON(string(raw))}
	var body struct {
		Entries []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &body) != nil || len(body.Entries) == 0 {
		p.supported = false
		return p
	}
	chain := false
	terminated := map[string]bool{}
	for _, entry := range body.Entries {
		if rawChain, ok := entry["chain"]; ok {
			chain = true
			var metadata struct {
				Hook string `json:"hook"`
			}
			if json.Unmarshal(rawChain, &metadata) != nil {
				p.supported = false
			}
			p.hook = metadata.Hook
		}
		data, ok := entry["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Expr []map[string]json.RawMessage `json:"expr"`
		}
		if json.Unmarshal(data, &rule) != nil {
			p.supported = false
			continue
		}
		source, destination, guardInterface := "", "", ""
		var mark uint32
		markSet, deny, accept := false, false, false
		known := true
		selectors := map[string]bool{}
		for _, expr := range rule.Expr {
			if len(expr) != 1 {
				known = false
				continue
			}
			for key, v := range expr {
				switch key {
				case "match":
					var m struct {
						Op   string `json:"op"`
						Left struct {
							Payload struct{ Protocol, Field string } `json:"payload"`
							Meta    struct{ Key string }             `json:"meta"`
						} `json:"left"`
						Right string `json:"right"`
					}
					if json.Unmarshal(v, &m) == nil && m.Op == "!=" && m.Left.Meta.Key == "oifname" && nativePattern.MatchString(m.Right) {
						if guardInterface != "" {
							known = false
						}
						guardInterface = m.Right
						continue
					}
					if json.Unmarshal(v, &m) != nil || m.Op != "==" || (m.Left.Payload.Protocol != "ip" && m.Left.Payload.Protocol != "ip6") {
						known = false
						continue
					}
					if selectors[m.Left.Payload.Field] {
						known = false
					}
					selectors[m.Left.Payload.Field] = true
					if m.Left.Payload.Field == "saddr" {
						source = m.Right
					} else if m.Left.Payload.Field == "daddr" {
						destination = m.Right
					} else {
						known = false
					}
				case "mangle":
					var m struct {
						Key struct {
							Meta struct{ Key string } `json:"meta"`
						} `json:"key"`
						Value uint32 `json:"value"`
					}
					if json.Unmarshal(v, &m) != nil || m.Key.Meta.Key != "mark" {
						known = false
					} else {
						mark = m.Value
						markSet = true
					}
				case "drop", "reject":
					deny = true
				case "accept":
					accept = true
				case "counter": // aggregate counters are never causal proof
				default:
					known = false
				}
			}
		}
		if !known {
			p.supported = false
			continue
		}
		if destination == "" && (deny || accept || markSet) {
			p.supported = false
			continue
		}
		if destination != target {
			continue
		}
		if source == "" {
			p.supported = false
			continue
		}
		if terminated[source] {
			continue
		}
		if (deny && accept) || (guardInterface != "" && (!deny || markSet)) {
			p.supported = false
			continue
		}
		if deny {
			if guardInterface != "" {
				p.guards[source] = guardInterface
			} else {
				p.denied[source] = true
				terminated[source] = true
			}
		}
		if accept {
			terminated[source] = true
			p.forwarded[source] = true
		}
		if markSet {
			p.marks[source] = mark
		}
	}
	p.supported = p.supported && chain
	p.digest = hashJSON(struct {
		Hook      string
		Supported bool
		Denied    map[string]bool
		Marks     map[string]uint32
		Forwarded map[string]bool
		Guards    map[string]string
	}{p.hook, p.supported, p.denied, p.marks, p.forwarded, p.guards})
	return p
}
func (c *collector) policy(ctx context.Context, gateway Object, target string) (nftPolicy, error) {
	b := gateway.Binding
	if b.NftFamily == "" || b.NftTable == "" || b.NftChain == "" {
		return nftPolicy{}, ErrMissing
	}
	raw, e := c.read(ctx, b, "nft", "-j", "list", "chain", b.NftFamily, b.NftTable, b.NftChain)
	if e != nil {
		return nftPolicy{}, e
	}
	return normalizeNFT(raw, target), nil
}
func (c *collector) routeOwned(ctx context.Context, owner, source Object, target, iface string, mark uint32) (bool, error) {
	if target == "" || iface == "" {
		return false, ErrMissing
	}
	family := "-4"
	if addr, e := netip.ParseAddr(target); e == nil && !addr.Is4() {
		family = "-6"
	}
	args := []string{"-j", family, "route", "get", target}
	if source.Binding.Address != "" {
		args = append(args, "from", source.Binding.Address)
	}
	if source.Binding.Ingress != "" {
		args = append(args, "iif", source.Binding.Ingress)
	}
	if mark != 0 {
		args = append(args, "mark", strconv.FormatUint(uint64(mark), 10))
	}
	raw, e := c.read(ctx, owner.Binding, "ip", args...)
	if e != nil {
		return false, e
	}
	var routes []struct {
		Dev  string `json:"dev"`
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &routes) != nil || len(routes) != 1 {
		return false, ErrUnsupported
	}
	return routes[0].Dev == iface && routes[0].Type != "blackhole" && routes[0].Type != "unreachable", nil
}
func (c *collector) collect(ctx context.Context, q Question) Collection {
	result := Collection{Cleanup: true}
	if c.permit == nil || c.permit(ctx, "network.read") != nil {
		result.Missing = []string{"network.read"}
		return result
	}
	switch q.Request.Operation {
	case "access", "isolation":
		return c.collectDNS(ctx, q)
	case "gateway":
		b := q.Target.Binding
		if b.Context == "" {
			return result
		}
		id, e := namespaceIdentity(b.Namespace)
		if e == nil {
			result.Facts = append(result.Facts, c.fact("gateway.binding", q, nil, id == b.Context))
		}
		bound, e := c.interfaceBinding(ctx, q.Target)
		if e == nil {
			result.Facts = append(result.Facts, c.fact("gateway.interface_binding", q, nil, bound))
		}
		p, e := c.policy(ctx, q.Target, b.Target)
		if e == nil {
			result.Facts = append(result.Facts, c.fact("gateway.reader", q, nil, true))
			if p.supported {
				result.Facts = append(result.Facts, c.fact("gateway.policy_scope", q, nil, true))
			}
		}
	case "vpn":
		if q.Target.Binding.Protocol != "wireguard" {
			return result
		}
		bound, e := c.interfaceBinding(ctx, q.Target)
		if e == nil {
			result.Facts = append(result.Facts, c.fact("vpn.binding", q, nil, bound))
		}
		raw, e := c.read(ctx, q.Target.Binding, "wg", "show", q.Target.Binding.Interface, "allowed-ips")
		if e == nil {
			result.Facts = append(result.Facts, c.fact("vpn.peer_binding", q, nil, peerOwns(raw, q.Target.Binding.Peer, q.Target.Binding.Target)))
		}
		raw, e = c.read(ctx, q.Target.Binding, "wg", "show", q.Target.Binding.Interface, "latest-handshakes")
		if e == nil {
			at, ok := peerHandshake(raw, q.Target.Binding.Peer)
			if ok && !at.After(time.Now()) {
				result.Facts = append(result.Facts, c.sessionFact(q, at, time.Now().UTC()))
			}
		}
		owner := q.Target
		source := Object{Binding: Binding{Address: q.Target.Binding.Address}}
		route, e := c.routeOwned(ctx, owner, source, q.Target.Binding.Target, q.Target.Binding.Interface, 0)
		if e == nil {
			result.Facts = append(result.Facts, c.fact("vpn.route_ownership", q, nil, route))
		}
		// Selection/guard require closed effective-policy coverage, not one plausible chain.
		if c.closed[q.Gateway.Binding.Context] {
			p, e := c.policy(ctx, q.Gateway, q.Target.Binding.Target)
			if e == nil && p.supported {
				if q.Target.Binding.FailClosed && p.hook == "forward" && p.guards[q.Source.Binding.Address] == q.Target.Binding.Interface {
					result.Facts = append(result.Facts, c.fact("vpn.fail_closed_guard", q, nil, true))
				}
				if q.Target.Binding.RequirePath {
					mark := uint32(0)
					if p.hook == "prerouting" || p.hook == "output" {
						mark = p.marks[q.Source.Binding.Address]
					}
					owned, e := c.routeOwned(ctx, q.Gateway, q.Source, q.Target.Binding.Target, q.Target.Binding.Interface, mark)
					if e == nil {
						result.Facts = append(result.Facts, c.fact("vpn.path_selection", q, nil, owned))
					}
				}
			}
		}
	}
	return result
}
