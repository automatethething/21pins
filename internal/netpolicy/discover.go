package netpolicy

import (
	"os/exec"
	"strconv"
)

type Candidate struct {
	Name         string       `json:"name"`
	Kind         Kind         `json:"kind"`
	Ref          Ref          `json:"ref"`
	Registered   bool         `json:"registered"`
	Confidence   string       `json:"confidence"`
	Capabilities []Capability `json:"capabilities"`
	Missing      []string     `json:"missing"`
}

func Discover(r *Registry, present func(string) bool) ([]Candidate, error) {
	if present == nil {
		present = func(name string) bool { _, e := exec.LookPath(name); return e == nil }
	}
	objects, e := r.Objects()
	if e != nil {
		return nil, e
	}
	if len(objects) > 62 {
		return nil, ErrUnsupported
	}
	out := make([]Candidate, 0, len(objects)+2)
	names := map[string]bool{}
	for _, o := range objects {
		names[o.Alias] = true
		out = append(out, Candidate{Name: o.Alias, Kind: o.Kind, Ref: o.Ref, Registered: true, Confidence: "declared_not_verified", Missing: []string{"live_evidence"}, Capabilities: []Capability{{Operation: "inspect_metadata", Support: Supported, Scope: []Ref{o.Ref}}}})
	}
	for _, client := range []struct {
		binary, name string
		kind         Kind
	}{{"ip", "linux-gateway", Gateway}, {"wg", "wireguard-vpn", VPN}} {
		if !present(client.binary) {
			continue
		}
		name := client.name
		for n := 2; names[name]; n++ {
			name = client.name + "-" + strconv.Itoa(n)
		}
		names[name] = true
		out = append(out, Candidate{Name: name, Kind: client.kind, Confidence: "unverified_candidate", Missing: []string{"confirmed_registration", "live_read_authority", "native_binding"}, Capabilities: []Capability{{Operation: "status", Support: Unknown}}})
	}
	return out, nil
}
