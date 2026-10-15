package netpolicy

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"time"
)

type CLIEnv struct {
	RegistryPath, StatePath, ReceiptDir string
	Actor                               func(context.Context) ([]byte, error)
	Collect                             func(context.Context, Question, func(context.Context, string) error) Collection
	// Only the internal test coordinator sets this. No CLI/import switch exists.
	Fixture bool
}
type RequestDescriptor struct {
	Request ObservationRequest `json:"request"`
	Targets map[string]string  `json:"execution_targets"`
}

func output(w io.Writer, v any) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(v)
}
func Run(parent context.Context, args []string, env CLIEnv, stdout, stderr io.Writer) int {
	fail := func(e error) int { output(stderr, map[string]string{"error": safeError(e)}); return 3 }
	unknown := func(e error) int {
		output(stdout, map[string]any{"verdict": Unverified, "missing": []string{safeError(e)}})
		return 2
	}
	if len(args) == 0 {
		return fail(ErrInvalid)
	}
	ctx, cancel := context.WithTimeout(parent, 100*time.Second)
	defer cancel()
	r := NewRegistry(env.RegistryPath)
	switch args[0] {
	case "registry":
		if len(args) != 3 || args[1] != "import" {
			return fail(ErrInvalid)
		}
		info, e := os.Lstat(args[2])
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ownedFile(info) {
			return fail(ErrUnsafe)
		}
		f, e := os.Open(args[2])
		if e != nil {
			return fail(ErrInvalid)
		}
		defer f.Close()
		if e = r.Import(f); e != nil {
			return fail(e)
		}
		objects, e := r.Objects()
		if e != nil {
			return fail(e)
		}
		if output(stdout, map[string]any{"status": "imported", "objects": len(objects)}) != nil {
			return 3
		}
		return 0
	case "discover":
		if len(args) != 1 && !(len(args) == 2 && args[1] == "--json") {
			return fail(ErrInvalid)
		}
		candidates, e := Discover(r, nil)
		if e != nil {
			return fail(e)
		}
		if output(stdout, candidates) != nil {
			return 3
		}
		return 0
	case "inspect":
		if len(args) < 3 {
			return fail(ErrInvalid)
		}
		flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		flags.Bool("details", false, "")
		flags.Bool("json", false, "")
		if flags.Parse(args[3:]) != nil || flags.NArg() != 0 {
			return fail(ErrInvalid)
		}
		if args[1] == "tailscale" {
			return unknown(ErrUnsupported)
		}
		if args[1] == "policy" {
			rules, e := r.Policies()
			if e != nil {
				return fail(e)
			}
			for _, rule := range rules {
				if rule.Alias == args[2] || rule.Ref.ID == args[2] {
					if output(stdout, rule) != nil {
						return 3
					}
					return 0
				}
			}
			return fail(ErrMissing)
		}
		kind := Kind(args[1])
		if kind == "gateway" {
			kind = Gateway
		}
		if kind == "wireguard" {
			kind = VPN
		}
		o, e := r.Resolve(kind, args[2])
		if e != nil {
			return fail(e)
		}
		if args[1] == "wireguard" && o.Binding.Protocol != "wireguard" {
			return fail(ErrUnsupported)
		}
		if output(stdout, InspectObject(o)) != nil {
			return 3
		}
		return 0
	case "verify":
		if len(args) < 3 {
			return fail(ErrInvalid)
		}
		op := args[1]
		target, source := args[2], ""
		offset := 3
		if op == "isolation" {
			if len(args) < 4 {
				return fail(ErrInvalid)
			}
			source = args[2]
			target = args[3]
			offset = 4
		}
		if op != "gateway" && op != "vpn" && op != "access" && op != "isolation" {
			return fail(ErrInvalid)
		}
		flags := flag.NewFlagSet("verify", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		from := flags.String("from", source, "")
		grant := flags.String("grant", "", "")
		requestOnly := flags.Bool("request", false, "")
		baselineID := flags.String("baseline", "", "")
		flags.Bool("json", false, "")
		if flags.Parse(args[offset:]) != nil || flags.NArg() != 0 || (*requestOnly && *grant != "") {
			return fail(ErrInvalid)
		}
		var baseline *Assessment
		if *baselineID != "" {
			a, e := ReadAssessment(env.ReceiptDir, *baselineID)
			if e != nil {
				return unknown(e)
			}
			if a.Synthetic && !env.Fixture {
				return unknown(ErrUnsupported)
			}
			baseline = &a
		}
		q, e := r.Question(op, target, *from, baseline)
		if e != nil {
			if e == ErrInvalid {
				return fail(e)
			}
			return unknown(e)
		}
		if *requestOnly {
			if output(stdout, RequestDescriptor{q.Request, map[string]string{"network.read": q.Request.Digest("network.read"), "network.probe": q.Request.Digest("network.probe")}}) != nil {
				return 3
			}
			return 0
		}
		if *grant == "" {
			return unknown(ErrMissing)
		}
		// Rebuild from current metadata and re-read revocation before EVERY native operation.
		permit := func(c context.Context, capability string) error {
			current, e := r.Question(op, target, *from, baseline)
			if e != nil {
				return e
			}
			if current.Request.Digest(capability) != q.Request.Digest(capability) {
				return ErrStale
			}
			return Authorize(c, env.StatePath, *grant, q.Request, capability, time.Now(), env.Actor)
		}
		if e = permit(ctx, "network.read"); e != nil {
			return unknown(e)
		}
		collect := env.Collect
		if collect == nil {
			collect = CollectNative
		}
		collected := collect(ctx, q, permit)
		g, e := ReadGrantProjection(env.StatePath, *grant)
		if e != nil {
			collected.Missing = append(collected.Missing, "grant_changed")
			collected.Facts = nil
		} else {
			for i := range collected.Facts {
				if collected.Facts[i].ValidUntil.After(g.Pins.SpendPolicy.WindowEnd) {
					collected.Facts[i].ValidUntil = g.Pins.SpendPolicy.WindowEnd
				}
			}
		}
		a := Evaluate(q.Request, collected.Facts, time.Now().UTC(), collected.Cleanup, env.Fixture)
		a.Context = DisplayContext{Source: q.Source.Alias, Target: q.Target.Alias, VPN: q.VPN.Alias}
		a.ExecutionGrantID = *grant
		a.Missing = append(a.Missing, collected.Missing...)
		if len(collected.Missing) > 0 && a.Verdict == Verified {
			a.Verdict = Unverified
		}
		if e = PruneAssessments(env.ReceiptDir, time.Now().UTC()); e != nil {
			return fail(e)
		}
		if e = SaveAssessment(env.ReceiptDir, a); e != nil {
			return fail(e)
		}
		if output(stdout, a) != nil {
			return 3
		}
		if !a.Cleanup {
			return 3
		}
		if a.Verdict == Verified {
			return 0
		}
		if a.Verdict == Violated {
			return 1
		}
		return 2
	}
	return fail(ErrInvalid)
}
func safeError(e error) string {
	switch e {
	case ErrInvalid, ErrUnsafe, ErrMissing, ErrStale, ErrConflict, ErrUnsupported:
		return e.Error()
	}
	return "network_operational_error"
}
