package netpolicy

import (
	"sort"
	"time"
)

type Support string

const (
	Supported   Support = "supported"
	Partial     Support = "partial"
	Unsupported Support = "unsupported"
	Unknown     Support = "unknown"
)

type Capability struct {
	Operation string   `json:"operation"`
	Support   Support  `json:"support"`
	Scope     []Ref    `json:"scope"`
	Missing   []string `json:"missing,omitempty"`
}
type Fact struct {
	ID             string    `json:"evidence_id"`
	Property       string    `json:"property"`
	Target         Ref       `json:"target"`
	Tuple          *Tuple    `json:"tuple,omitempty"`
	Value          bool      `json:"value"`
	Scope          []Ref     `json:"object_revisions"`
	Policies       []Ref     `json:"policy_revisions"`
	ObservedAt     time.Time `json:"observed_at"`
	ValidUntil     time.Time `json:"valid_until"`
	WindowStart    time.Time `json:"window_start,omitempty"`
	WindowEnd      time.Time `json:"window_end,omitempty"`
	Assurance      string    `json:"assurance"`
	RuntimeBinding string    `json:"runtime_binding,omitempty"`
	validated      bool
}

func newFact(property string, q ObservationRequest, tuple *Tuple, value bool, now time.Time, assurance string) Fact {
	if tuple != nil {
		copy := *tuple
		tuple = &copy
	}
	return Fact{ID: "ev_" + hashJSON(struct {
		P  string
		Q  ObservationRequest
		T  *Tuple
		At time.Time
	}{property, q, tuple, now}), Property: property, Target: q.Target, Tuple: tuple, Value: value, Scope: append([]Ref(nil), q.Objects...), Policies: append([]Ref(nil), q.Policies...), ObservedAt: now, ValidUntil: now.Add(10 * time.Minute), Assurance: assurance, validated: true}
}
func sameRefs(a, b []Ref) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]Ref(nil), a...)
	y := append([]Ref(nil), b...)
	sort.Slice(x, func(i, j int) bool { return hashJSON(x[i]) < hashJSON(x[j]) })
	sort.Slice(y, func(i, j int) bool { return hashJSON(y[i]) < hashJSON(y[j]) })
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
func validFact(f Fact, q ObservationRequest, now time.Time, fixture bool) bool {
	if !f.validated || f.Target != q.Target || !sameRefs(f.Scope, q.Objects) || !sameRefs(f.Policies, q.Policies) || f.ObservedAt.After(now) || f.ValidUntil.Before(now) || f.ValidUntil.After(f.ObservedAt.Add(10*time.Minute)) {
		return false
	}
	if f.Assurance == "synthetic_runtime" && !fixture {
		return false
	}
	if f.Assurance != "runtime_validated" && f.Assurance != "synthetic_runtime" && f.Assurance != "operator_attested" {
		return false
	}
	if !f.WindowEnd.IsZero() && (f.WindowStart.IsZero() || f.WindowEnd.Before(f.WindowStart) || f.WindowEnd.After(f.ObservedAt)) {
		return false
	}
	return true
}

type Inspection struct {
	Ref             Ref    `json:"ref"`
	Kind            Kind   `json:"kind"`
	Alias           string `json:"alias"`
	Implementation  string `json:"implementation,omitempty"`
	EndpointDisplay string `json:"endpoint_display"`
}

func InspectObject(o Object) Inspection {
	// No confirmation mechanism ships in v1. There is deliberately NO public override.
	return Inspection{Ref: o.Ref, Kind: o.Kind, Alias: o.Alias, Implementation: o.Binding.Protocol, EndpointDisplay: "suppressed"}
}
