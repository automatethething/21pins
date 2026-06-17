package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/petrichor/21pins-cli/internal/config"
	"github.com/petrichor/21pins-cli/internal/gateway"
	"github.com/petrichor/21pins-cli/internal/hosted"
	"github.com/petrichor/21pins-cli/internal/identity"
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
	case "models":
		handleModels(st, os.Args[2:])
	case "hosted":
		handleHosted(os.Args[2:])
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
  key history <provider>
  key rotate start <provider> --value <apiKey>
  key rotate verify <provider>
  key rotate commit <provider> [--keep-previous-hours 24]
  key rotate rollback <provider>
  key revoke <provider> --previous
  key revoke <provider> --key-id <id>
  token create <name> [--scopes proxy:chat,proxy:providers]
  token list
  token revoke <token>
  grant create --sub <ck_sub>|--ck-whoami|--ck-hosted --capabilities a,b --data-classes a,b --targets a,b [--hosted-url URL] [--budget-limit-cents 10000] [--budget-window-minutes 1440] [--approval-threshold-cents 0]
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
  approvals approve <approval-id> --ck-hosted [--hosted-url URL] [--reason text]
  approvals reject <approval-id> --ck-hosted [--hosted-url URL] [--reason text]
  models sync [--provider <provider>]
  models list [--provider <provider>] [--search text] [--json]
  models choose [--provider <provider>] [--search text] [--index N]
  hosted status [--json] [--hosted-url URL]
  hosted smoke [--json] [--hosted-url URL] [--key-id hosted-ed25519-v1] [--require-public-key]
  serve [--host 127.0.0.1] [--port 8787]
`)
}

func handleStatus(st *store.Store) {
	fmt.Printf("State file: %s\n", config.StatePath())
	fmt.Printf("Providers configured: %d\n", len(st.ListProviders()))
	fmt.Printf("Tokens configured: %d\n", len(st.ListTokens()))
	fmt.Printf("Grants configured: %d\n", len(st.ListGrants()))
	fmt.Printf("Receipts recorded: %d\n", len(st.ListReceipts("")))
	fmt.Printf("Approvals recorded: %d\n", len(st.ListApprovals("")))
	fmt.Printf("Model catalogs cached: %d\n", len(st.ListModelCatalogs()))
	hostedAttested := 0
	for _, g := range st.ListGrants() {
		if g.IdentityAttestation != nil {
			hostedAttested++
		}
	}
	fmt.Printf("Hosted identity attestations: %d\n", hostedAttested)
}

func handleHosted(args []string) {
	if len(args) == 0 {
		fatalf("hosted subcommand required: status|smoke")
	}
	switch args[0] {
	case "status":
		fs := flag.NewFlagSet("hosted status", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "print machine-readable JSON")
		hostedURL := fs.String("hosted-url", "", "hosted 21pins control plane URL")
		_ = fs.Parse(args[1:])
		baseURL := strings.TrimSpace(*hostedURL)
		if baseURL == "" {
			baseURL = hosted.DefaultBaseURL()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		client := hosted.Client{BaseURL: baseURL, HTTPClient: &http.Client{Timeout: 5 * time.Second}}
		status := client.Status(ctx)
		if *jsonOut {
			printJSON(status)
			return
		}
		fmt.Printf("Hosted URL: %s\n", status.URL)
		fmt.Printf("State: %s\n", status.State)
		fmt.Printf("CK attestation available: %t\n", status.CKAttestationAvailable)
		fmt.Printf("Checked at: %s\n", status.CheckedAt.Format(time.RFC3339))
		if status.Error != "" {
			fmt.Printf("Error: %s\n", status.Error)
		}
	case "smoke":
		fs := flag.NewFlagSet("hosted smoke", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "print machine-readable JSON")
		hostedURL := fs.String("hosted-url", "", "hosted 21pins control plane URL")
		keyID := fs.String("key-id", hosted.DefaultSmokeKeyID, "expected hosted signing key id")
		requirePublicKey := fs.Bool("require-public-key", false, "fail if pinned public key env is missing")
		_ = fs.Parse(args[1:])
		baseURL := strings.TrimSpace(*hostedURL)
		if baseURL == "" {
			baseURL = hosted.DefaultBaseURL()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		client := hosted.Client{BaseURL: baseURL, HTTPClient: &http.Client{Timeout: 10 * time.Second}}
		report, err := client.Smoke(ctx, *keyID)
		if *requirePublicKey && !report.PublicKeyLoaded {
			fatalf("pinned public key env %s not loaded", report.PublicKeyEnv)
		}
		if err != nil {
			if *jsonOut {
				printJSON(map[string]any{"ok": false, "report": report, "error": err.Error()})
			}
			fatalf("hosted smoke failed: %v", err)
		}
		if *jsonOut {
			printJSON(map[string]any{"ok": true, "report": report})
			return
		}
		fmt.Printf("Hosted URL: %s\n", report.URL)
		fmt.Printf("Health: %s\n", report.HealthState)
		fmt.Printf("Session ID: %s\n", report.SessionID)
		fmt.Printf("Poll status: %s\n", report.PollStatus)
		fmt.Printf("Public key env: %s (loaded=%t)\n", report.PublicKeyEnv, report.PublicKeyLoaded)
	default:
		fatalf("unknown hosted subcommand")
	}
}

func handleKey(st *store.Store, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "key subcommand required: providers|set|list|history|rotate|revoke")
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
	case "history":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: key history <provider>")
			os.Exit(1)
		}
		provider, _ := store.CanonicalProvider(args[1])
		history := st.ProviderKeyHistory(provider)
		if len(history) == 0 {
			fmt.Println("No key history for provider.")
			return
		}
		for _, rec := range history {
			exp := ""
			if rec.ExpiresAt != "" {
				exp = " expires=" + rec.ExpiresAt
			}
			fmt.Printf("%s  status=%s  created=%s%s\n", rec.ID, rec.Status, rec.CreatedAt, exp)
		}
	case "rotate":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: key rotate <start|verify|commit|rollback> ...")
			os.Exit(1)
		}
		switch args[1] {
		case "start":
			if len(args) < 3 {
				fmt.Fprintln(os.Stderr, "usage: key rotate start <provider> --value <apiKey>")
				os.Exit(1)
			}
			provider, _ := store.CanonicalProvider(args[2])
			fs := flag.NewFlagSet("key rotate start", flag.ExitOnError)
			value := fs.String("value", "", "new provider API key")
			_ = fs.Parse(args[3:])
			if *value == "" {
				fmt.Fprintln(os.Stderr, "--value is required")
				os.Exit(1)
			}
			id, err := st.RotateProviderKeyStart(provider, *value)
			if err != nil {
				fmt.Fprintf(os.Stderr, "rotate start failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Rotation started for %s. pending_key_id=%s\n", provider, id)
			fmt.Println("Next: key rotate verify <provider>")
		case "verify":
			if len(args) < 3 {
				fmt.Fprintln(os.Stderr, "usage: key rotate verify <provider>")
				os.Exit(1)
			}
			provider, _ := store.CanonicalProvider(args[2])
			id, err := st.RotateProviderKeyVerify(provider)
			if err != nil {
				fmt.Fprintf(os.Stderr, "rotate verify failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Pending key verified for %s. pending_key_id=%s\n", provider, id)
		case "commit":
			if len(args) < 3 {
				fmt.Fprintln(os.Stderr, "usage: key rotate commit <provider> [--keep-previous-hours 24]")
				os.Exit(1)
			}
			provider, _ := store.CanonicalProvider(args[2])
			fs := flag.NewFlagSet("key rotate commit", flag.ExitOnError)
			keep := fs.Int("keep-previous-hours", 24, "grace window for previous key")
			_ = fs.Parse(args[3:])
			if err := st.RotateProviderKeyCommit(provider, *keep); err != nil {
				fmt.Fprintf(os.Stderr, "rotate commit failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Rotation committed for %s. previous key grace window: %dh\n", provider, *keep)
		case "rollback":
			if len(args) < 3 {
				fmt.Fprintln(os.Stderr, "usage: key rotate rollback <provider>")
				os.Exit(1)
			}
			provider, _ := store.CanonicalProvider(args[2])
			if err := st.RotateProviderKeyRollback(provider); err != nil {
				fmt.Fprintf(os.Stderr, "rotate rollback failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Rollback complete for %s. Previous key is active again.\n", provider)
		default:
			fmt.Fprintln(os.Stderr, "unknown key rotate subcommand")
			os.Exit(1)
		}
	case "revoke":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: key revoke <provider> --previous | --key-id <id>")
			os.Exit(1)
		}
		provider, _ := store.CanonicalProvider(args[1])
		fs := flag.NewFlagSet("key revoke", flag.ExitOnError)
		previous := fs.Bool("previous", false, "revoke previous key")
		keyID := fs.String("key-id", "", "specific key id to revoke")
		_ = fs.Parse(args[2:])
		if *previous {
			if err := st.RevokePreviousProviderKey(provider); err != nil {
				fmt.Fprintf(os.Stderr, "revoke previous failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Previous key revoked for %s.\n", provider)
			return
		}
		if strings.TrimSpace(*keyID) == "" {
			fmt.Fprintln(os.Stderr, "--key-id required (or use --previous)")
			os.Exit(1)
		}
		if err := st.RevokeProviderKey(provider, *keyID); err != nil {
			fmt.Fprintf(os.Stderr, "revoke key failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Key %s revoked for %s.\n", *keyID, provider)
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
		ckWhoami := fs.Bool("ck-whoami", false, "read subject from `ck whoami` when --sub is omitted")
		ckHosted := fs.Bool("ck-hosted", false, "verify ConsentKeys identity through hosted 21pins control plane")
		hostedURL := fs.String("hosted-url", "", "hosted 21pins control plane URL")
		delegatedBy := fs.String("delegated-by", "", "delegator subject")
		authority := fs.String("authority-chain", "", "comma-separated authority chain")
		capabilities := fs.String("capabilities", "", "comma-separated capabilities")
		dataClasses := fs.String("data-classes", "", "comma-separated data classes")
		targets := fs.String("targets", "", "comma-separated execution targets")
		budgetLimit := fs.Int64("budget-limit-cents", 10000, "budget limit in cents")
		budgetWindowMinutes := fs.Int("budget-window-minutes", 1440, "budget window in minutes")
		approvalThreshold := fs.Int64("approval-threshold-cents", 0, "approval threshold in cents")
		_ = fs.Parse(args[1:])

		if strings.TrimSpace(*capabilities) == "" || strings.TrimSpace(*dataClasses) == "" || strings.TrimSpace(*targets) == "" {
			fatalf("--capabilities, --data-classes, and --targets are required")
		}

		var attestation *policy.IdentityAttestation
		var resolvedSub string
		if *ckHosted {
			if strings.TrimSpace(*sub) != "" || *ckWhoami {
				fatalf("--ck-hosted cannot be combined with --sub or --ck-whoami")
			}
			baseURL := strings.TrimSpace(*hostedURL)
			if baseURL == "" {
				baseURL = hosted.DefaultBaseURL()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			client := hosted.Client{BaseURL: baseURL, HTTPClient: &http.Client{Timeout: 10 * time.Second}}
			got, err := client.CompleteHostedAttestation(ctx, *budgetWindowMinutes, baseURL, time.Now().UTC(), os.Stderr)
			if err != nil {
				fatalf("hosted CK attestation failed: %v", err)
			}
			attestation = &got
			resolvedSub = got.Subject
		} else {
			var err error
			resolvedSub, err = identity.ResolveSubject(*sub, *ckWhoami, nil)
			if err != nil {
				fatalf("%v", err)
			}
		}
		chain := splitCSV(*authority)
		if len(chain) == 0 {
			chain = []string{resolvedSub}
		}
		now := time.Now().UTC()
		grant, err := st.CreateGrant(policy.Grant{
			Sub:                 resolvedSub,
			DelegatedBy:         strings.TrimSpace(*delegatedBy),
			IdentityAttestation: attestation,
			Pins: policy.Pins{
				Identity:         policy.IdentityPin{Sub: resolvedSub},
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

func validateApprovalForAction(a policy.ApprovalRequest, grantID, sub, capability, dataClass, target string, cost int64, now time.Time) error {
	if a.Status != policy.ApprovalApproved {
		return fmt.Errorf("approval is not approved: %s", a.Status)
	}
	if a.GrantID != grantID || a.Sub != sub || a.Capability != capability || a.DataClass != dataClass || a.Target != target || a.CostCents != cost {
		return fmt.Errorf("approval does not match action request")
	}
	if a.ApproverAttestation == nil || a.ApproverAttestation.Subject != a.ApproverSub {
		return fmt.Errorf("approval missing approver attestation")
	}
	if err := hosted.VerifyStoredAttestation(*a.ApproverAttestation, now); err != nil {
		return fmt.Errorf("invalid approver attestation: %w", err)
	}
	return nil
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
		if err := validateApprovalForAction(a, *grantID, *sub, *capability, *dataClass, *target, *cost, now); err != nil {
			fatalf("%v", err)
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
	usedApprovalID := strings.TrimSpace(*approvalID)
	if usedApprovalID != "" {
		receipt.ApprovalRef = usedApprovalID
	}
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
		"approval_ref": receipt.ApprovalRef,
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
			fatalf("usage: approvals %s <approval-id> --ck-hosted [--hosted-url URL] [--reason text]", args[0])
		}
		approvalID := args[1]
		fs := flag.NewFlagSet("approvals resolve", flag.ExitOnError)
		approverSub := fs.String("approver-sub", "", "approver ck subject (disabled without --ck-hosted)")
		ckHosted := fs.Bool("ck-hosted", false, "verify approver through hosted 21pins control plane")
		hostedURL := fs.String("hosted-url", "", "hosted 21pins control plane URL")
		reason := fs.String("reason", "", "resolution reason")
		_ = fs.Parse(args[2:])
		if !*ckHosted || strings.TrimSpace(*approverSub) != "" {
			fatalf("approvals %s requires --ck-hosted and does not accept raw --approver-sub", args[0])
		}
		baseURL := strings.TrimSpace(*hostedURL)
		if baseURL == "" {
			baseURL = hosted.DefaultBaseURL()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		client := hosted.Client{BaseURL: baseURL, HTTPClient: &http.Client{Timeout: 10 * time.Second}}
		att, err := client.CompleteHostedAttestation(ctx, 1440, baseURL, time.Now().UTC(), os.Stderr)
		if err != nil {
			fatalf("hosted approver attestation failed: %v", err)
		}
		status := policy.ApprovalApproved
		if args[0] == "reject" {
			status = policy.ApprovalRejected
		}
		a, err := st.ResolveApprovalWithAttestation(approvalID, status, att.Subject, strings.TrimSpace(*reason), att)
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
	host := fs.String("host", "127.0.0.1", "gateway bind host (use 0.0.0.0 for LAN)")
	port := fs.Int("port", 8787, "gateway port")
	_ = fs.Parse(args)

	srv := gateway.NewServer(st, gateway.Config{Host: *host, Port: *port})
	fmt.Printf("21pins gateway listening on http://%s:%d\n", *host, *port)
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
		fmt.Println("Next step: approvals approve <approval_id> --ck-hosted")
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
