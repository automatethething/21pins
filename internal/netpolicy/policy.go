package netpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"

	"github.com/petrichor/21pins-cli/internal/policy"
)

type Tuple struct {
	Source    Ref    `json:"source"`
	Endpoint  Ref    `json:"endpoint"`
	Realm     string `json:"realm"`
	Family    string `json:"family"`
	Transport string `json:"transport"`
	Port      uint16 `json:"port"`
	Mode      string `json:"access_mode"`
}
type Rule struct {
	Ref        Ref     `json:"ref"`
	Alias      string  `json:"alias"`
	Decision   string  `json:"decision"`
	Tuples     []Tuple `json:"tuples"`
	Path       Ref     `json:"path,omitempty"`
	FailClosed bool    `json:"fail_closed,omitempty"`
	Filtering  bool    `json:"filtering,omitempty"`
}
type ResolvedTuple struct {
	Tuple      Tuple  `json:"tuple"`
	Policy     Ref    `json:"policy"`
	Decision   string `json:"decision"`
	Path       Ref    `json:"path"`
	FailClosed bool   `json:"fail_closed"`
	Filtering  bool   `json:"filtering"`
}
type ObservationRequest struct {
	Operation      string              `json:"operation"`
	Target         Ref                 `json:"target"`
	Source         Ref                 `json:"source"`
	Objects        []Ref               `json:"objects"`
	Policies       []Ref               `json:"policies"`
	Tuples         []Tuple             `json:"tuples"`
	Required       []string            `json:"required_properties"`
	TupleRequired  map[string][]string `json:"tuple_required_properties,omitempty"`
	MetadataDigest string              `json:"metadata_digest"`
}

func hashJSON(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (q ObservationRequest) Digest(capability string) string {
	// Canonical order prevents input ordering or friendly renames from changing admission.
	q.Objects = append([]Ref(nil), q.Objects...)
	q.Policies = append([]Ref(nil), q.Policies...)
	q.Required = append([]string(nil), q.Required...)
	q.Tuples = append([]Tuple(nil), q.Tuples...)
	sort.Slice(q.Objects, func(i, j int) bool { return hashJSON(q.Objects[i]) < hashJSON(q.Objects[j]) })
	sort.Slice(q.Policies, func(i, j int) bool { return hashJSON(q.Policies[i]) < hashJSON(q.Policies[j]) })
	sort.Strings(q.Required)
	sort.Slice(q.Tuples, func(i, j int) bool { return hashJSON(q.Tuples[i]) < hashJSON(q.Tuples[j]) })
	return "network:" + hashJSON(struct {
		Request        ObservationRequest
		Capability     string
		MaximumSeconds int
	}{q, capability, 100})
}
func canonicalTuple(objects []Object, t Tuple) (Tuple, error) {
	s, e := find(objects, Network, t.Source.ID)
	if e != nil {
		return t, e
	}
	endpoint, e := find(objects, Service, t.Endpoint.ID)
	if e != nil {
		return t, e
	}
	if (t.Source.Revision != 0 && t.Source != s.Ref) || (t.Endpoint.Revision != 0 && t.Endpoint != endpoint.Ref) {
		return t, ErrStale
	}
	if (t.Family != "ipv4" && t.Family != "ipv6") || (t.Transport != "udp" && t.Transport != "tcp") || (t.Mode != "direct" && t.Mode != "mediated") || t.Port != endpoint.Binding.Port {
		return t, ErrInvalid
	}
	address, e := netip.ParseAddr(endpoint.Binding.Target)
	if e != nil || (t.Family == "ipv4") != address.Is4() {
		return t, ErrInvalid
	}
	realm := "realm_" + hashJSON(struct {
		Endpoint Ref
		Name     string
	}{endpoint.Ref, endpoint.Binding.Realm})
	if t.Realm != endpoint.Binding.Realm && t.Realm != realm {
		return t, ErrInvalid
	}
	t.Source = s.Ref
	t.Endpoint = endpoint.Ref
	t.Realm = realm
	return t, nil
}
func normalizeRule(objects []Object, rule Rule) (Rule, error) {
	if !namePattern.MatchString(rule.Alias) || (rule.Decision != "allow" && rule.Decision != "deny") || len(rule.Tuples) == 0 || len(rule.Tuples) > 256 {
		return rule, ErrInvalid
	}
	rule.Tuples = append([]Tuple(nil), rule.Tuples...)
	seen := map[Tuple]bool{}
	for i, t := range rule.Tuples {
		c, e := canonicalTuple(objects, t)
		if e != nil {
			return rule, e
		}
		if seen[c] {
			return rule, ErrConflict
		}
		seen[c] = true
		rule.Tuples[i] = c
	}
	if rule.Path.ID != "" {
		o, e := find(objects, VPN, rule.Path.ID)
		if e != nil {
			return rule, e
		}
		if rule.Path.Revision != 0 && rule.Path != o.Ref {
			return rule, ErrStale
		}
		rule.Path = o.Ref
	}
	return rule, nil
}
func overlap(rules []Rule) error {
	seen := map[Tuple]bool{}
	for _, r := range rules {
		for _, t := range r.Tuples {
			if seen[t] {
				return ErrConflict
			}
			seen[t] = true
		}
	}
	return nil
}
func putRule(s *registryState, rule Rule) (Rule, error) {
	if rule.Ref.ID != "" || rule.Ref.Revision != 0 {
		return rule, ErrInvalid
	}
	normalized, e := normalizeRule(s.Objects, rule)
	if e != nil {
		return rule, e
	}
	normalized.Ref = Ref{policy.NewID("npol"), 1}
	found := false
	for i, old := range s.Policies {
		if old.Alias == rule.Alias {
			normalized.Ref = Ref{old.Ref.ID, old.Ref.Revision + 1}
			s.Policies[i] = normalized
			found = true
			break
		}
	}
	if !found {
		s.Policies = append(s.Policies, normalized)
	}
	if e = overlap(s.Policies); e != nil {
		return rule, e
	}
	return normalized, nil
}
func (r *Registry) PutPolicy(rule Rule) (Rule, error) {
	var result Rule
	e := r.mutate(func(s *registryState) error { var e error; result, e = putRule(s, rule); return e })
	return result, e
}
func (r *Registry) Policies() ([]Rule, error) { s, e := r.load(); return s.Policies, e }
func (r *Registry) ResolveTuples(tuples []Tuple) ([]ResolvedTuple, error) {
	s, e := r.load()
	if e != nil {
		return nil, e
	}
	if len(tuples) == 0 || len(tuples) > 256 {
		return nil, ErrInvalid
	}
	var result []ResolvedTuple
	for _, input := range tuples {
		t, e := canonicalTuple(s.Objects, input)
		if e != nil {
			return nil, e
		}
		count := 0
		var match ResolvedTuple
		for _, rule := range s.Policies {
			for _, declared := range rule.Tuples {
				scope, scopeErr := canonicalTuple(s.Objects, declared)
				if scopeErr != nil {
					src, _ := find(s.Objects, Network, declared.Source.ID)
					endpoint, _ := find(s.Objects, Service, declared.Endpoint.ID)
					if src.Ref.ID == t.Source.ID && endpoint.Ref.ID == t.Endpoint.ID && declared.Transport == t.Transport && declared.Port == t.Port && declared.Family == t.Family && declared.Mode == t.Mode {
						return nil, ErrStale
					}
					continue
				}
				if scope != t {
					continue
				}
				normalized, e := normalizeRule(s.Objects, rule)
				if e != nil {
					return nil, e
				}
				count++
				match = ResolvedTuple{t, normalized.Ref, normalized.Decision, normalized.Path, normalized.FailClosed, normalized.Filtering}
			}
		}
		if count != 1 {
			return nil, ErrConflict
		}
		result = append(result, match)
	}
	return result, nil
}
