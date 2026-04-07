package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/petrichor/21pins-cli/internal/config"
	"github.com/petrichor/21pins-cli/internal/gateway"
	"github.com/petrichor/21pins-cli/internal/policy"
	"github.com/petrichor/21pins-cli/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	st, err := store.New(config.StatePath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening store: %v\n", err)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		fmt.Printf("21pins initialized at %s\n", config.StatePath())
	case "key":
		handleKey(st, os.Args[2:])
	case "token":
		handleToken(st, os.Args[2:])
	case "grant":
		handleGrant(st, os.Args[2:])
	case "evaluate":
		handleEvaluate(st, os.Args[2:])
	case "receipts":
		handleReceipts(st, os.Args[2:])
	case "approvals":
		handleApprovals(st, os.Args[2:])
	case "serve":
		handleServe(st, os.Args[2:])
	case "status":
		handleStatus(st)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`21pins - local LLM key and gateway CLI

Commands:
  init
  status
  key providers
  key set <provider> --value <apiKey>
  key list
  token create <name> [--scopes proxy:chat,proxy:providers]
  token list
  token revoke <token>
  grant create --sub <ck_sub> --capabilities a,b --data-classes a,b --targets a,b [--budget-limit-cents 10000] [--budget-window-minutes 1440] [--approval-threshold-cents 0]
  grant inspect <grant-id>
  grant list
  grant revoke <grant-id>
  grant export <grant-id> [--ttl-minutes 15]
  evaluate --grant <grant-id> --sub <ck_sub> --capability <cap> --data-class <class> --target <vendor> [--cost-cents N] [--approval-id <id>] [--json]
  receipts get <receipt-id>
  receipts list [--grant <grant-id>]
  receipts export <receipt-id> [--out path]
  approvals get <approval-id>
  approvals list [--grant <grant-id>]
  approvals approve <approval-id> --approver-sub <ck_sub> [--reason text]
  approvals reject <approval-id> --approver-sub <ck_sub> [--reason text]
  serve [--port 8787]
`)
}

func handleStatus(st *store.Store) {
	fmt.Printf("State file: %s\n", config.StatePath())
	fmt.Printf("Providers configured: %d\n", len(st.ListProviders()))
	fmt.Printf("Tokens configured: %d\n", len(st.ListTokens()))
	fmt.Printf("Grants configured: %d\n", len(st.ListGrants()))
	fmt.Printf("Receipts recorded: %d\n", len(st.ListReceipts("")))
	fmt.Printf("Approvals recorded: %d\n", len(st.ListApprovals("")))
}

func handleKey(st *store.Store, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "key subcommand required: providers|set|list")
		os.Exit(1)
	}
	switch args[0] {
	case "providers":
		fmt.Println("Supported providers:")
		for _, p := range store.SupportedProviders() {
			fmt.Printf("- %s\n", p)
		}
		aliases := store.ProviderAliases()
		if len(aliases) > 0 {
			fmt.Println("\nAccepted aliases:")
			keys := make([]string, 0, len(aliases))
			for k := range aliases {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, alias := range keys {
				fmt.Printf("- %s -> %s\n", alias, aliases[alias])
			}
		}
	case "set":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: key set <provider> --value <apiKey>")
			os.Exit(1)
		}
		provider, aliasUsed := store.CanonicalProvider(args[1])
		if provider == "" {
			fmt.Fprintln(os.Stderr, "provider is required")
			os.Exit(1)
		}
		if aliasUsed {
			fmt.Fprintf(os.Stderr, "note: mapped provider alias %q to canonical provider %q\n", args[1], provider)
		}
		fs := flag.NewFlagSet("key set", flag.ExitOnError)
		value := fs.String("value", "", "provider API key")
		_ = fs.Parse(args[2:])
		if *value == "" {
			fmt.Fprintln(os.Stderr, "--value is required")
			os.Exit(1)
		}
		if err := st.SetProviderKey(provider, *value); err != nil {
			fmt.Fprintf(os.Stderr, "failed to set key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Saved key for provider: %s\n", provider)
	case "list":
		providers := st.ListProviders()
		if len(providers) == 0 {
			fmt.Println("No provider keys configured.")
			return
		}
		for _, p := range providers {
			fmt.Println(p)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown key subcommand")
		os.Exit(1)
	}
}

func handleToken(st *store.Store, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "token subcommand required: create|list|revoke")
		os.Exit(1)
	}
	switch args[0] {
	case "create":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: token create <name> [--scopes a,b]")
			os.Exit(1)
		}
		name := args[1]
		fs := flag.NewFlagSet("token create", flag.ExitOnError)
		scopesValue := fs.String("scopes", "proxy:*", "comma-separated scopes")
		_ = fs.Parse(args[2:])
		scopes := splitCSV(*scopesValue)
		tok, err := st.CreateToken(name, scopes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create token: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Token created for %s (copy now; only shown once):\n%s\n", name, tok)
	case "list":
		tokens := st.ListTokens()
		if len(tokens) == 0 {
			fmt.Println("No tokens configured.")
			return
		}
		for _, t := range tokens {
			revoked := "active"
			if t.RevokedAt != "" {
				revoked = "revoked"
			}
			fmt.Printf("%s  %s  scopes=%s  created=%s\n", t.Name, revoked, strings.Join(t.Scopes, ","), t.CreatedAt)
		}
	case "revoke":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: token revoke <token>")
			os.Exit(1)
		}
		if err := st.RevokeToken(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "failed to revoke token: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Token revoked.")
	default:
		fmt.Fprintln(os.Stderr, "unknown token subcommand")
		os.Exit(1)
	}
}

func handleGrant(st *store.Store, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "grant subcommand required: create|inspect|list|revoke|export")
		os.Exit(1)
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("grant create", flag.ExitOnError)
		sub := fs.String("sub", "", "ck subject")
		delegatedBy := fs.String("delegated-by", "", "delegator subject")
		authority := fs.String("authority-chain", "", "comma-separated authority chain")
		capabilities := fs.String("capabilities", "", "comma-separated capabilities")
		dataClasses := fs.String("data-classes", "", "comma-separated data classes")
		targets := fs.String("targets", "", "comma-separated execution targets")
		budgetLimit := fs.Int64("budget-limit-cents", 10000, "budget limit in cents")
		budgetWindowMinutes := fs.Int("budget-window-minutes", 1440, "budget window in minutes")
		approvalThreshold := fs.Int64("approval-threshold-cents", 0, "approval threshold in cents")
		_ = fs.Parse(args[1:])

		if strings.TrimSpace(*sub) == "" {
			fatalf("--sub is required")
		}
		if strings.TrimSpace(*capabilities) == "" || strings.TrimSpace(*dataClasses) == "" || strings.TrimSpace(*targets) == "" {
			fatalf("--capabilities, --data-classes, and --targets are required")
		}
		chain := splitCSV(*authority)
		if len(chain) == 0 {
			chain = []string{*sub}
		}
		now := time.Now().UTC()
		grant, err := st.CreateGrant(policy.Grant{
			Sub:         strings.TrimSpace(*sub),
			DelegatedBy: strings.TrimSpace(*delegatedBy),
			Pins: policy.Pins{
				Identity:         policy.IdentityPin{Sub: strings.TrimSpace(*sub)},
				Authority:        policy.AuthorityPin{Chain: chain},
				Capabilities:     policy.CapabilityPin{Allowed: splitCSV(*capabilities)},
				DataPolicy:       policy.DataPolicyPin{AllowedClasses: splitCSV(*dataClasses)},
				SpendPolicy:      policy.SpendPolicyPin{LimitCents: *budgetLimit, SpentCents: 0, WindowStart: now, WindowEnd: now.Add(time.Duration(*budgetWindowMinutes) * time.Minute)},
				ExecutionTargets: policy.ExecutionTargetPin{AllowedTargets: splitCSV(*targets)},
				ApprovalPolicy:   policy.ApprovalPolicyPin{ThresholdCents: *approvalThreshold},
			},
		})
		if err != nil {
			fatalf("create grant failed: %v", err)
		}
		printJSON(grant)
	case "inspect":
		if len(args) < 2 {
			fatalf("usage: grant inspect <grant-id>")
		}
		g, err := st.GetGrant(args[1])
		if err != nil {
			fatalf("inspect failed: %v", err)
		}
		printJSON(g)
	case "list":
		printJSON(st.ListGrants())
	case "revoke":
		if len(args) < 2 {
			fatalf("usage: grant revoke <grant-id>")
		}
		if err := st.RevokeGrant(args[1]); err != nil {
			fatalf("revoke failed: %v", err)
		}
		fmt.Println("Grant revoked.")
	case "export":
		if len(args) < 2 {
			fatalf("usage: grant export <grant-id> [--ttl-minutes 15]")
		}
		grantID := args[1]
		fs := flag.NewFlagSet("grant export", flag.ExitOnError)
		ttlMin := fs.Int("ttl-minutes", 15, "signed export ttl in minutes")
		_ = fs.Parse(args[2:])
		g, err := st.GetGrant(grantID)
		if err != nil {
			fatalf("grant export failed: %v", err)
		}
		_, priv, kid, err := st.SigningKeypair()
		if err != nil {
			fatalf("signing key unavailable: %v", err)
		}
		tok, err := policy.SignGrantExport(g, priv, kid, time.Now().UTC(), time.Duration(*ttlMin)*time.Minute)
		if err != nil {
			fatalf("sign export failed: %v", err)
		}
		fmt.Println(tok)
	default:
		fatalf("unknown grant subcommand")
	}
}

func handleEvaluate(st *store.Store, args []string) {
	fs := flag.NewFlagSet("evaluate", flag.ExitOnError)
	grantID := fs.String("grant", "", "grant id")
	sub := fs.String("sub", "", "ck subject")
	capability := fs.String("capability", "", "capability")
	dataClass := fs.String("data-class", "", "data class")
	target := fs.String("target", "", "execution target")
	cost := fs.Int64("cost-cents", 0, "cost in cents")
	approvalID := fs.String("approval-id", "", "approved approval id for gated actions")
	jsonOut := fs.Bool("json", false, "print machine-readable JSON")
	_ = fs.Parse(args)

	if *grantID == "" || *sub == "" || *capability == "" || *dataClass == "" || *target == "" {
		fatalf("required: --grant --sub --capability --data-class --target")
	}
	g, err := st.GetGrant(*grantID)
	if err != nil {
		fatalf("grant lookup failed: %v", err)
	}
	now := time.Now().UTC()
	approvalGranted := false
	if strings.TrimSpace(*approvalID) != "" {
		a, err := st.GetApproval(strings.TrimSpace(*approvalID))
		if err != nil {
			fatalf("approval lookup failed: %v", err)
		}
		if a.Status != policy.ApprovalApproved {
			fatalf("approval is not approved: %s", a.Status)
		}
		if a.GrantID != *grantID || a.Sub != *sub || a.Capability != *capability || a.DataClass != *dataClass || a.Target != *target || a.CostCents != *cost {
			fatalf("approval does not match action request")
		}
		approvalGranted = true
	}
	request := policy.ActionRequest{
		GrantID:         *grantID,
		Sub:             *sub,
		Capability:      *capability,
		DataClass:       *dataClass,
		Target:          *target,
		CostCents:       *cost,
		ApprovalID:      strings.TrimSpace(*approvalID),
		ApprovalGranted: approvalGranted,
	}
	result := policy.EvaluateAction(g, request, now)

	receipt := policy.NewReceipt(g, request, result, now)
	var createdApprovalID string
	if result.Decision == policy.DecisionRequireApproval {
		a, err := st.CreateApproval(policy.ApprovalRequest{
			GrantID:    *grantID,
			ReceiptID:  receipt.ID,
			Sub:        *sub,
			Capability: *capability,
			DataClass:  *dataClass,
			Target:     *target,
			CostCents:  *cost,
		})
		if err != nil {
			fatalf("failed to create approval request: %v", err)
		}
		createdApprovalID = a.ID
		receipt.ApprovalRef = a.ID
	}
	_, priv, keyID, err := st.SigningKeypair()
	if err != nil {
		fatalf("signing key unavailable: %v", err)
	}
	receipt, err = policy.SignReceipt(receipt, priv, keyID)
	if err != nil {
		fatalf("failed to sign receipt: %v", err)
	}
	if err := st.AddReceipt(receipt); err != nil {
		fatalf("failed to persist receipt: %v", err)
	}
	if result.Decision == policy.DecisionAllow && *cost > 0 {
		_ = st.AddGrantSpend(*grantID, *cost)
	}

	out := map[string]any{
		"decision":    result.Decision,
		"pin_states":  result.PinStates,
		"reasons":     result.Reasons,
		"receipt_id":  receipt.ID,
		"approval_id": createdApprovalID,
		"signature":   receipt.Signature,
	}
	if *jsonOut {
		printJSON(out)
		return
	}
	printEvaluation(result, receipt.ID, createdApprovalID)
}

func handleReceipts(st *store.Store, args []string) {
	if len(args) == 0 {
		fatalf("receipts subcommand required: get|list|export")
	}
	switch args[0] {
	case "get":
		if len(args) < 2 {
			fatalf("usage: receipts get <receipt-id>")
		}
		r, err := st.GetReceipt(args[1])
		if err != nil {
			fatalf("get receipt failed: %v", err)
		}
		artifact, err := receiptArtifact(st, r)
		if err != nil {
			fatalf("receipt artifact failed: %v", err)
		}
		printJSON(artifact)
	case "list":
		fs := flag.NewFlagSet("receipts list", flag.ExitOnError)
		grantID := fs.String("grant", "", "optional grant id")
		_ = fs.Parse(args[1:])
		receipts := st.ListReceipts(*grantID)
		out := make([]map[string]any, 0, len(receipts))
		for _, r := range receipts {
			artifact, err := receiptArtifact(st, r)
			if err != nil {
				fatalf("receipt artifact failed: %v", err)
			}
			out = append(out, artifact)
		}
		printJSON(out)
	case "export":
		if len(args) < 2 {
			fatalf("usage: receipts export <receipt-id> [--out path]")
		}
		receiptID := args[1]
		fs := flag.NewFlagSet("receipts export", flag.ExitOnError)
		outPath := fs.String("out", "", "optional output file path")
		_ = fs.Parse(args[2:])
		r, err := st.GetReceipt(receiptID)
		if err != nil {
			fatalf("get receipt failed: %v", err)
		}
		artifact, err := receiptArtifact(st, r)
		if err != nil {
			fatalf("receipt artifact failed: %v", err)
		}
		if strings.TrimSpace(*outPath) == "" {
			printJSON(artifact)
			return
		}
		b, err := json.MarshalIndent(artifact, "", "  ")
		if err != nil {
			fatalf("json encode failed: %v", err)
		}
		if err := os.WriteFile(strings.TrimSpace(*outPath), b, 0o600); err != nil {
			fatalf("write export failed: %v", err)
		}
		fmt.Printf("exported receipt artifact to %s\n", strings.TrimSpace(*outPath))
	default:
		fatalf("unknown receipts subcommand")
	}
}

func handleApprovals(st *store.Store, args []string) {
	if len(args) == 0 {
		fatalf("approvals subcommand required: get|list|approve|reject")
	}
	switch args[0] {
	case "get":
		if len(args) < 2 {
			fatalf("usage: approvals get <approval-id>")
		}
		a, err := st.GetApproval(args[1])
		if err != nil {
			fatalf("get approval failed: %v", err)
		}
		printJSON(a)
	case "list":
		fs := flag.NewFlagSet("approvals list", flag.ExitOnError)
		grantID := fs.String("grant", "", "optional grant id")
		_ = fs.Parse(args[1:])
		printJSON(st.ListApprovals(*grantID))
	case "approve", "reject":
		if len(args) < 2 {
			fatalf("usage: approvals %s <approval-id> --approver-sub <ck_sub> [--reason text]", args[0])
		}
		approvalID := args[1]
		fs := flag.NewFlagSet("approvals resolve", flag.ExitOnError)
		approverSub := fs.String("approver-sub", "", "approver ck subject")
		reason := fs.String("reason", "", "resolution reason")
		_ = fs.Parse(args[2:])
		if strings.TrimSpace(*approverSub) == "" {
			fatalf("--approver-sub is required")
		}
		status := policy.ApprovalApproved
		if args[0] == "reject" {
			status = policy.ApprovalRejected
		}
		a, err := st.ResolveApproval(approvalID, status, strings.TrimSpace(*approverSub), strings.TrimSpace(*reason))
		if err != nil {
			fatalf("resolve approval failed: %v", err)
		}
		printJSON(a)
	default:
		fatalf("unknown approvals subcommand")
	}
}

func handleServe(st *store.Store, args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.Int("port", 8787, "gateway port")
	_ = fs.Parse(args)

	srv := gateway.NewServer(st, gateway.Config{Port: *port})
	fmt.Printf("21pins gateway listening on http://127.0.0.1:%d\n", *port)
	fmt.Println("Use Authorization: Bearer <21pins-token>")
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "gateway error: %v\n", err)
		os.Exit(1)
	}
}

func receiptArtifact(st *store.Store, r policy.Receipt) (map[string]any, error) {
	pub, _, _, err := st.SigningKeypair()
	if err != nil {
		return nil, err
	}
	verified := policy.VerifyReceipt(r, pub) == nil
	return map[string]any{
		"receipt_id":         r.ID,
		"subject":            r.Sub,
		"grant_id":           r.GrantID,
		"authority_chain":    r.Authority,
		"capability":         r.Capability,
		"data_class":         r.DataClass,
		"cost_cents":         r.CostCents,
		"target":             r.Target,
		"pin_results":        r.PinStates,
		"decision":           strings.ToUpper(string(r.Decision)),
		"approval_id":        r.ApprovalRef,
		"signature":          r.Signature,
		"signature_key_id":   r.KeyID,
		"signature_verified": verified,
		"created_at":         r.CreatedAt,
	}, nil
}

func printEvaluation(result policy.EvaluationResult, receiptID, approvalID string) {
	fmt.Printf("Decision: %s\n", strings.ToUpper(string(result.Decision)))
	orderedPins := []string{"identity", "authority_chain", "capabilities", "data_policy", "spend_policy", "execution_targets", "approval"}
	for _, pin := range orderedPins {
		state := result.PinStates[pin]
		emoji := "✅"
		switch state {
		case policy.PinFail:
			emoji = "❌"
		case policy.PinRequiresApproval:
			emoji = "⚠️"
		}
		reason := result.Reasons[pin]
		if reason != "" {
			fmt.Printf("%s %-18s %s (%s)\n", emoji, pin, state, reason)
		} else {
			fmt.Printf("%s %-18s %s\n", emoji, pin, state)
		}
	}
	fmt.Printf("receipt_id: %s\n", receiptID)
	if approvalID != "" {
		fmt.Printf("approval_id: %s\n", approvalID)
		fmt.Println("Next step: approvals approve <approval_id> --approver-sub <ck_sub>")
	}
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{}
	}
	return out
}

func printJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatalf("json encode failed: %v", err)
	}
	fmt.Println(string(b))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
