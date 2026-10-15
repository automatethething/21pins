// Package netpolicy is separate from execution grants, the LLM proxy and SSH authority.
package netpolicy

import (
	"errors"
	"net/netip"
	"regexp"
)

type Kind string

const (
	Gateway Kind = "network_gateway"
	Network Kind = "network"
	VPN     Kind = "vpn"
	Service Kind = "service"
)

var (
	ErrInvalid     = errors.New("network_invalid_metadata")
	ErrUnsafe      = errors.New("network_unsafe_state")
	ErrMissing     = errors.New("network_missing_binding")
	ErrStale       = errors.New("network_stale_binding")
	ErrConflict    = errors.New("network_scope_conflict")
	ErrUnsupported = errors.New("network_unsupported")
)
var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
var nativePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

type Ref struct {
	ID       string `json:"id"`
	Revision uint64 `json:"binding_revision"`
}
type Binding struct {
	Namespace   string   `json:"namespace,omitempty"`
	Context     string   `json:"context,omitempty"`
	Interface   string   `json:"interface,omitempty"`
	Ingress     string   `json:"ingress,omitempty"`
	Address     string   `json:"address,omitempty"`
	Peer        string   `json:"peer,omitempty"`
	Target      string   `json:"target,omitempty"`
	Port        uint16   `json:"port,omitempty"`
	Realm       string   `json:"realm,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	Transports  []string `json:"transports,omitempty"`
	AccessModes []string `json:"access_modes,omitempty"`
	Gateway     Ref      `json:"gateway,omitempty"`
	VPN         Ref      `json:"vpn,omitempty"`
	Source      Ref      `json:"source,omitempty"`
	Control     Ref      `json:"control,omitempty"`
	NftFamily   string   `json:"nft_family,omitempty"`
	NftTable    string   `json:"nft_table,omitempty"`
	NftChain    string   `json:"nft_chain,omitempty"`
	RequirePath bool     `json:"require_path,omitempty"`
	FailClosed  bool     `json:"fail_closed,omitempty"`
}
type Object struct {
	Ref     Ref     `json:"ref"`
	Kind    Kind    `json:"kind"`
	Alias   string  `json:"alias"`
	Binding Binding `json:"binding"`
}

func validObject(o Object) bool {
	if !namePattern.MatchString(o.Alias) {
		return false
	}
	switch o.Kind {
	case Gateway, Network, VPN, Service:
	default:
		return false
	}
	for _, v := range []string{o.Binding.Namespace, o.Binding.Interface, o.Binding.Ingress, o.Binding.NftTable, o.Binding.NftChain, o.Binding.Realm} {
		if v != "" && !nativePattern.MatchString(v) {
			return false
		}
	}
	if len(o.Binding.Context) > 128 || len(o.Binding.Interface) > 15 || len(o.Binding.Peer) > 128 {
		return false
	}
	if o.Binding.NftFamily != "" && o.Binding.NftFamily != "inet" && o.Binding.NftFamily != "ip" && o.Binding.NftFamily != "ip6" {
		return false
	}
	for _, v := range []string{o.Binding.Address, o.Binding.Target} {
		if v != "" {
			if _, e := netip.ParseAddr(v); e != nil {
				return false
			}
		}
	}
	if o.Kind == Service && (o.Binding.Target == "" || o.Binding.Port == 0 || o.Binding.Realm == "") {
		return false
	}
	seenModes := map[string]bool{}
	for _, mode := range o.Binding.AccessModes {
		if (mode != "direct" && mode != "mediated") || seenModes[mode] {
			return false
		}
		seenModes[mode] = true
	}
	for _, transport := range o.Binding.Transports {
		if transport != "udp" && transport != "tcp" {
			return false
		}
	}
	if o.Binding.Protocol != "" && o.Binding.Protocol != "wireguard" && o.Binding.Protocol != "dns" {
		return false
	}
	return true
}
