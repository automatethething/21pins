package netpolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/petrichor/21pins-cli/internal/policy"
)

type Verdict string

const (
	Verified   Verdict = "VERIFIED"
	Violated   Verdict = "VIOLATED"
	Unverified Verdict = "UNVERIFIED"
)

type PropertyResult struct {
	Property  string   `json:"property"`
	Tuple     *Tuple   `json:"tuple,omitempty"`
	State     string   `json:"state"`
	Evidence  []string `json:"evidence_refs,omitempty"`
	Assurance []string `json:"assurance,omitempty"`
}
type Assessment struct {
	ID         string             `json:"verification_id"`
	Verdict    Verdict            `json:"verdict"`
	Request    ObservationRequest `json:"request"`
	Properties []PropertyResult   `json:"properties"`
	Missing    []string           `json:"missing,omitempty"`
	Excluded   []string           `json:"excluded"`
	Evidence   []Fact             `json:"evidence"`
	CreatedAt  time.Time          `json:"created_at"`
	Cleanup    bool               `json:"cleanup"`
	Synthetic  bool               `json:"synthetic"`
}

func Properties(operation string, b Binding) []string {
	switch operation {
	case "gateway":
		return []string{"gateway.binding", "gateway.interface_binding", "gateway.reader", "gateway.policy_scope"}
	case "vpn":
		p := []string{"vpn.binding", "vpn.peer_binding", "vpn.session_freshness", "vpn.route_ownership"}
		if b.RequirePath {
			p = append(p, "vpn.path_selection")
		}
		if b.FailClosed {
			p = append(p, "vpn.fail_closed_guard")
		}
		return p
	}
	return nil
}
func profileValid(q ObservationRequest) bool {
	if q.Operation != "gateway" && q.Operation != "vpn" {
		return true
	}
	b := Binding{}
	for _, p := range q.Required {
		if p == "vpn.path_selection" {
			b.RequirePath = true
		}
		if p == "vpn.fail_closed_guard" {
			b.FailClosed = true
		}
	}
	return reflect.DeepEqual(q.Required, Properties(q.Operation, b)) && len(q.Tuples) == 0
}
func Evaluate(q ObservationRequest, facts []Fact, now time.Time, cleanup, fixture bool) Assessment {
	a := Assessment{ID: policy.NewID("nver"), Request: q, Verdict: Verified, CreatedAt: now, Cleanup: cleanup, Synthetic: fixture, Excluded: []string{"unrequested_objects", "unrequested_families_transports_modes", "universal_network_health"}}
	if q.Operation == "gateway" || q.Operation == "vpn" {
		a.Excluded = append(a.Excluded, "attached_access_policies", "end_to_end_service_health")
	}
	if len(q.Required) == 0 || !profileValid(q) {
		a.Missing = append(a.Missing, "finite_profile")
		a.Verdict = Unverified
		return a
	}
	tuples := q.Tuples
	if len(tuples) == 0 {
		tuples = []Tuple{{}}
	}
	for _, tuple := range tuples {
		var scoped *Tuple
		if len(q.Tuples) > 0 {
			copy := tuple
			scoped = &copy
		}
		for _, property := range q.Required {
			result := PropertyResult{Property: property, Tuple: scoped, State: "missing"}
			for _, f := range facts {
				if f.Property != property || !validFact(f, q, now, fixture) || !reflect.DeepEqual(f.Tuple, scoped) {
					continue
				}
				if f.Tuple != nil && f.Tuple.Mode != "direct" {
					continue
				}
				a.Evidence = append(a.Evidence, f)
				result.Evidence = append(result.Evidence, f.ID)
				result.Assurance = append(result.Assurance, f.Assurance)
				if !f.Value {
					result.State = "contradicted"
					a.Verdict = Violated
				} else if result.State != "contradicted" {
					result.State = "pass"
				}
			}
			if result.State == "missing" {
				a.Missing = append(a.Missing, property)
				if a.Verdict != Violated {
					a.Verdict = Unverified
				}
			}
			a.Properties = append(a.Properties, result)
		}
	}
	if !cleanup {
		a.Missing = append(a.Missing, "cleanup")
		if a.Verdict != Violated {
			a.Verdict = Unverified
		}
	}
	return a
}
func validReceiptID(id string) bool {
	return strings.HasPrefix(id, "nver_") && nativePattern.MatchString(id) && len(id) > 5
}
func SaveAssessment(dir string, a Assessment) error {
	if !validReceiptID(a.ID) {
		return ErrInvalid
	}
	if os.MkdirAll(dir, 0700) != nil {
		return ErrUnsafe
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return ErrUnsafe
	}
	data, e := json.Marshal(a)
	if e != nil {
		return ErrInvalid
	}
	f, e := os.CreateTemp(dir, ".assessment-")
	if e != nil {
		return ErrUnsafe
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return ErrUnsafe
	}
	// Hard-link publishes the complete synced record atomically without replacement.
	if os.Link(name, filepath.Join(dir, a.ID+".json")) != nil {
		return ErrUnsafe
	}
	parent, e := os.Open(dir)
	if e != nil {
		return ErrUnsafe
	}
	defer parent.Close()
	if parent.Sync() != nil {
		return ErrUnsafe
	}
	return nil
}
func ReadAssessment(dir, id string) (Assessment, error) {
	var a Assessment
	if !validReceiptID(id) {
		return a, ErrInvalid
	}
	e := readSafe(filepath.Join(dir, id+".json"), &a)
	return a, e
}
func PruneAssessments(dir string, now time.Time) error {
	entries, e := os.ReadDir(dir)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return ErrUnsafe
	}
	if len(entries) > 4096 {
		return ErrUnsupported
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !validReceiptID(id) {
			continue
		}
		a, e := ReadAssessment(dir, id)
		if e != nil {
			return e
		}
		if a.Cleanup && now.Sub(a.CreatedAt) > 30*24*time.Hour {
			if os.Remove(filepath.Join(dir, entry.Name())) != nil {
				return ErrUnsafe
			}
		}
	}
	return nil
}
