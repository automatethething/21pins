package netpolicy

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/petrichor/21pins-cli/internal/identity"
	"github.com/petrichor/21pins-cli/internal/policy"
)

// ReadGrantProjection never constructs a Store or provider/signing-key objects.
func ReadGrantProjection(path, id string) (policy.Grant, error) {
	before, e := os.Lstat(path)
	if e != nil {
		return policy.Grant{}, ErrMissing
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || !ownedFile(before) || before.Size() > maxStateBytes {
		return policy.Grant{}, ErrUnsafe
	}
	f, e := os.Open(path)
	if e != nil {
		return policy.Grant{}, ErrUnsafe
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) || after.Size() > maxStateBytes {
		return policy.Grant{}, ErrUnsafe
	}
	var projection struct {
		Grants []policy.Grant `json:"grants"`
	}
	// Unknown encoded fields pass through the decoder but are not materialized.
	d := json.NewDecoder(io.LimitReader(f, maxStateBytes+1))
	if d.Decode(&projection) != nil {
		return policy.Grant{}, ErrInvalid
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return policy.Grant{}, ErrInvalid
	}
	var found policy.Grant
	count := 0
	for _, g := range projection.Grants {
		if g.ID == id {
			found = g
			count++
		}
	}
	if count != 1 {
		return policy.Grant{}, ErrMissing
	}
	return found, nil
}
func Authorize(ctx context.Context, path, id string, request ObservationRequest, capability string, now time.Time, actor func(context.Context) ([]byte, error)) error {
	g, e := ReadGrantProjection(path, id)
	if e != nil {
		return e
	}
	if capability != "network.read" && capability != "network.probe" {
		return ErrInvalid
	}
	if actor == nil {
		actor = func(parent context.Context) ([]byte, error) {
			c, cancel := context.WithTimeout(parent, 10*time.Second)
			defer cancel()
			return exec.CommandContext(c, "ck", "whoami").Output()
		}
	}
	subject, e := identity.ResolveSubject("", true, func() ([]byte, error) { return actor(ctx) })
	if e != nil {
		return ErrMissing
	}
	result := policy.EvaluateAction(g, policy.ActionRequest{Sub: subject, Capability: capability, DataClass: "network-metadata", Target: request.Digest(capability), CostCents: 0}, now)
	if result.Decision != policy.DecisionAllow {
		return ErrMissing
	}
	return nil
}
