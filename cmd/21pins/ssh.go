package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/petrichor/21pins-cli/internal/config"
	"github.com/petrichor/21pins-cli/internal/sshaccess"
	"github.com/petrichor/21pins-cli/internal/sshcommand"
	"github.com/petrichor/21pins-cli/internal/store"
)

type clientLease struct {
	Lease       sshaccess.Lease `json:"lease"`
	ValidBefore time.Time       `json:"certificate_expires_at"`
}

func sshDir() string {
	if p := os.Getenv("PINS21_SSH_DIR"); p != "" {
		return p
	}
	return filepath.Join(filepath.Dir(config.StatePath()), "ssh")
}
func runtimeDir() string {
	if p := os.Getenv("PINS21_SSH_RUNTIME_DIR"); p != "" {
		return p
	}
	p, _ := os.UserCacheDir()
	return filepath.Join(p, "21pins-ssh")
}
func sshActor(st *store.Store, approve bool) (sshaccess.Actor, error) {
	raw := os.Getenv("PINS21_TOKEN")
	if p := os.Getenv("PINS21_SSH_TOKEN_FILE"); p != "" {
		b, e := sshaccess.ReadPrivate(p)
		if e != nil {
			return sshaccess.Actor{}, errors.New("private SSH token file unavailable")
		}
		raw = strings.TrimSpace(string(b))
	}
	scope := "ssh:use"
	if approve {
		scope = "ssh:approve"
	}
	t, ok := st.ValidateSSHToken(raw, scope)
	if !ok {
		return sshaccess.Actor{}, errors.New("dedicated SSH token required; load through private token file or PINS21_TOKEN")
	}
	return sshaccess.Actor{ID: t.TokenHash, Name: t.Name, CanApprove: approve}, nil
}
func handleSSH(st *store.Store, args []string) {
	if e := runSSH(st, args); e != nil {
		fmt.Fprintln(os.Stderr, "SSH operation failed:", e)
		os.Exit(1)
	}
}
func runSSH(st *store.Store, args []string) error {
	if len(args) == 0 {
		return errors.New("ssh subcommand required: ca|host|open|exec|connect|complete|cancel|revoke|approve|status|objective")
	}
	if args[0] == "gate" {
		return sshGate(args[1:])
	}
	if args[0] == "ca" {
		return sshCA(args[1:])
	}
	if args[0] == "host" {
		return sshHost(st, args[1:])
	}
	svc, actor, e := newSSHClient()
	if e != nil {
		return e
	}
	root := runtimeDir()
	if e = sshaccess.PrivateDir(root); e != nil {
		return e
	}
	if e = sweepClient(root, time.Now()); e != nil {
		return e
	}
	switch args[0] {
	case "open":
		fs := flag.NewFlagSet("ssh open", flag.ContinueOnError)
		host := fs.String("host", "", "logical host")
		role := fs.String("role", "", "role")
		objective := fs.String("objective", "", "immutable objective")
		purpose := fs.String("purpose", "", "purpose (no secrets)")
		agent := fs.String("agent", "pi", "harness class")
		estimate := fs.String("estimate", "", "advisory estimate")
		maximum := fs.String("max-lease", "", "policy-bounded window")
		_ = fs.Bool("json", false, "JSON metadata (never keys)")
		if e = fs.Parse(args[1:]); e != nil {
			return errors.New("invalid SSH flags")
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected SSH arguments")
		}
		tmp, e := os.MkdirTemp(root, "opening-")
		if e != nil {
			return e
		}
		keep := false
		defer func() {
			if !keep {
				os.RemoveAll(tmp)
			}
		}()
		pub, e := generateLeaseKey(tmp)
		if e != nil {
			return e
		}
		l, e := svc.Open(actor, sshaccess.OpenRequest{HostID: *host, RoleID: *role, AgentClass: *agent, ObjectiveID: *objective, Purpose: *purpose, EstimatedDuration: *estimate, MaxDuration: *maximum, PublicKey: pub})
		if e != nil {
			return e
		}
		dir := filepath.Join(root, l.ID)
		if e = os.Rename(tmp, dir); e != nil {
			_, _ = svc.Close(actor, l.ID, sshaccess.Cancelled, "lost_client")
			return errors.New("client state unavailable")
		}
		tmp = dir
		m := clientLease{Lease: l}
		if l.Status == sshaccess.Active {
			r, e := svc.Issue(actor, l.ID, pub)
			if e != nil {
				_, _ = svc.Close(actor, l.ID, sshaccess.Cancelled, "lost_client")
				return e
			}
			if e = sshaccess.AtomicPrivate(filepath.Join(dir, "id_ed25519-cert.pub"), []byte(r.Certificate+"\n")); e != nil {
				_, _ = svc.Close(actor, l.ID, sshaccess.Cancelled, "lost_client")
				return e
			}
			m.ValidBefore = r.Issuance.ValidBefore
		}
		if e = saveClient(dir, m); e != nil {
			_, _ = svc.Close(actor, l.ID, sshaccess.Cancelled, "lost_client")
			return e
		}
		keep = true
		printJSON(l)
		return nil
	case "objective":
		if len(args) != 3 || (args[1] != "complete" && args[1] != "cancel") {
			return errors.New("ssh objective complete|cancel <objective>")
		}
		leases, e := svc.List(actor, args[2])
		if e != nil {
			return e
		}
		var failed bool
		for _, l := range leases {
			state := sshaccess.Completed
			reason := "complete"
			if args[1] == "cancel" {
				state = sshaccess.Cancelled
				reason = "blocked"
			}
			_, e = svc.Close(actor, l.ID, state, reason)
			if cleanupLease(root, l.ID) != nil || e != nil {
				failed = true
			}
		}
		if failed {
			return errors.New("objective lease cleanup incomplete")
		}
		fmt.Println("objective leases closed")
		return nil
	}
	if len(args) < 2 || !validLeaseID(args[1]) {
		return errors.New("valid lease ID required")
	}
	id := args[1]
	dir := filepath.Join(root, id)
	switch args[0] {
	case "status":
		l, e := svc.Get(actor, id)
		if e == nil {
			if isTerminal(l.Status) {
				_ = cleanupLease(root, id)
			}
			printJSON(l)
		}
		return e
	case "approve":
		preview, e := svc.Get(actor, id)
		if e != nil {
			return e
		}
		confirmed := len(args) == 3 && args[2] == "--yes"
		if !confirmed {
			if len(args) != 2 {
				return errors.New("approve accepts optional --yes")
			}
			fmt.Fprintf(os.Stderr, "Approve %s role %s for objective %s, purpose %s, hard expiry %s? Type approve: ", preview.HostID, preview.RoleID, preview.ObjectiveID, preview.Purpose, preview.HardExpiresAt.Format(time.RFC3339))
			var answer string
			if _, e = fmt.Fscan(os.Stdin, &answer); e != nil || answer != "approve" {
				return errors.New("approval declined")
			}
		}
		l, e := svc.Approve(actor, id)
		if e == nil {
			printJSON(l)
		}
		return e
	case "complete", "cancel", "revoke":
		defer cleanupLease(root, id)
		state := sshaccess.Completed
		reason := "complete"
		if args[0] == "cancel" {
			state = sshaccess.Cancelled
			reason = "cancelled"
		}
		if args[0] == "revoke" {
			state = sshaccess.Revoked
			reason = "revoked"
		}
		l, e := svc.Close(actor, id, state, reason)
		if e == nil {
			printJSON(l)
		}
		return e
	case "exec", "connect":
		m, e := loadClient(dir)
		if e != nil {
			return e
		}
		l, e := svc.Get(actor, id)
		if e != nil || l.Status != sshaccess.Active {
			if e == nil && isTerminal(l.Status) {
				_ = cleanupLease(root, id)
			}
			return sshaccess.ErrDenied
		}
		if m.Lease.ID != l.ID || m.Lease.PublicKeyFingerprint != l.PublicKeyFingerprint {
			return errors.New("client lease mismatch")
		}
		renew, err := time.ParseDuration(l.RenewBefore)
		if err != nil || renew <= 0 {
			return errors.New("invalid certificate renewal policy")
		}
		if time.Until(m.ValidBefore) < renew {
			pub, e := os.ReadFile(filepath.Join(dir, "id_ed25519.pub"))
			if e != nil {
				return errors.New("local public key unavailable")
			}
			r, e := svc.Issue(actor, id, strings.TrimSpace(string(pub)))
			if e != nil {
				return e
			}
			if e = sshaccess.AtomicPrivate(filepath.Join(dir, "id_ed25519-cert.pub"), []byte(r.Certificate+"\n")); e != nil {
				return e
			}
			m.Lease = l
			m.ValidBefore = r.Issuance.ValidBefore
			if e = saveClient(dir, m); e != nil {
				return e
			}
		}
		if e = sshaccess.CheckPrivate(filepath.Join(dir, "id_ed25519")); e != nil {
			return errors.New("local private key unavailable")
		}
		resolved, e := resolveAlias(l.SSHAlias)
		if e != nil {
			return e
		}
		remote := args[2:]
		if len(remote) > 0 && remote[0] == "--" {
			remote = remote[1:]
		}
		interactive := args[0] == "connect"
		if !interactive && len(remote) == 0 {
			return errors.New("remote command required")
		}
		if interactive && len(remote) > 0 {
			return errors.New("connect takes no command")
		}
		argv, e := sshArgs(l, dir, resolved, interactive, remote)
		if e != nil {
			return e
		}
		fmt.Fprintln(os.Stderr, "21pins: credential expiry does not terminate established sessions or detached work; no data sandbox.")
		cmd := exec.Command("ssh", argv...)
		cmd.Env = withoutAgent(os.Environ())
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if cmd.Start() != nil {
			return errors.New("direct SSH command failed")
		}
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM, os.Interrupt)
		defer signal.Stop(signals)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				return errors.New("direct SSH command failed")
			}
			return nil
		case <-signals:
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				<-done
			}
			_, _ = svc.Close(actor, id, sshaccess.Cancelled, "shutdown")
			_ = cleanupLease(root, id)
			return errors.New("SSH session cancelled")
		}
	default:
		return errors.New("unknown SSH command")
	}
}
func sshGate(args []string) error {
	fs := flag.NewFlagSet("ssh gate", flag.ContinueOnError)
	policy := fs.String("policy", "", "root-owned policy")
	workspace := fs.String("workspace", "", "trusted workspace")
	host := fs.String("host", "", "trusted host")
	role := fs.String("role", "", "trusted role")
	username := fs.String("user", "", "signed Unix account")
	digest := fs.String("rules-digest", "", "signed allowlist version")
	fixture := fs.Bool("dev-fixture", false, "isolated synthetic fixture ONLY")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return sshcommand.Denied
	}
	return sshcommand.Run(*policy, *workspace, *host, *role, *username, *digest, os.Getenv("SSH_ORIGINAL_COMMAND"), *fixture)
}

func validLeaseID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func isTerminal(s sshaccess.Status) bool {
	return s != sshaccess.Active && s != sshaccess.PendingApproval
}
func generateLeaseKey(dir string) (string, error) {
	if e := sshaccess.PrivateDir(dir); e != nil {
		return "", e
	}
	p := filepath.Join(dir, "id_ed25519")
	if _, e := os.Lstat(p); !os.IsNotExist(e) {
		return "", errors.New("lease key already exists")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", p)
	cmd.Env = withoutAgent(os.Environ())
	if cmd.Run() != nil {
		return "", errors.New("ephemeral key generation failed")
	}
	if e := os.Chmod(p, 0600); e != nil {
		return "", e
	}
	if e := os.Chmod(p+".pub", 0600); e != nil {
		return "", e
	}
	b, e := os.ReadFile(p + ".pub")
	if e != nil {
		return "", e
	}
	pub := strings.TrimSpace(string(b))
	if _, e = sshaccess.PublicFingerprint(pub); e != nil {
		return "", e
	}
	return pub, nil
}
func saveClient(dir string, m clientLease) error {
	b, e := json.Marshal(m)
	if e != nil {
		return e
	}
	return sshaccess.AtomicPrivate(filepath.Join(dir, "lease.json"), b)
}
func loadClient(dir string) (clientLease, error) {
	var m clientLease
	if e := sshaccess.PrivateDir(dir); e != nil {
		return m, e
	}
	b, e := sshaccess.ReadPrivate(filepath.Join(dir, "lease.json"))
	if e != nil {
		return m, errors.New("local lease unavailable")
	}
	if json.Unmarshal(b, &m) != nil {
		return m, errors.New("local lease invalid")
	}
	return m, nil
}
func cleanupLease(root, id string) error {
	if !validLeaseID(id) {
		return errors.New("invalid cleanup ID")
	}
	p := filepath.Join(root, id)
	i, e := os.Lstat(p)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe client cleanup")
	}
	return os.RemoveAll(p)
}
func sweepClient(root string, now time.Time) error {
	entries, e := os.ReadDir(root)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if validLeaseID(entry.Name()) && entry.IsDir() {
			m, e := loadClient(filepath.Join(root, entry.Name()))
			if e != nil {
				return e
			}
			if isTerminal(m.Lease.Status) || !now.Before(m.Lease.HardExpiresAt) {
				if e = cleanupLease(root, entry.Name()); e != nil {
					return e
				}
			}
		} else if strings.HasPrefix(entry.Name(), "opening-") {
			info, e := entry.Info()
			if e == nil && now.Sub(info.ModTime()) > time.Hour {
				if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
					return errors.New("unsafe opening cache")
				}
				if e = os.RemoveAll(filepath.Join(root, entry.Name())); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
func withoutAgent(env []string) []string {
	out := []string{}
	for _, v := range env {
		if !strings.HasPrefix(v, "SSH_AUTH_SOCK=") && !strings.HasPrefix(v, "SSH_AGENT_PID=") {
			out = append(out, v)
		}
	}
	return out
}
func resolveAlias(alias string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	args := []string{"-G"}
	if file := os.Getenv("PINS21_SSH_CONFIG_FILE"); file != "" {
		args = append(args, "-F", file)
	}
	args = append(args, alias)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Env = withoutAgent(os.Environ())
	b, e := cmd.Output()
	if e != nil {
		return nil, errors.New("local SSH alias resolution failed")
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, " ")
		if ok {
			switch k {
			case "hostname", "port", "userknownhostsfile", "globalknownhostsfile", "hostkeyalias":
				out[k] = strings.TrimSpace(v)
			}
		}
	}
	return out, nil
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func sshArgs(l sshaccess.Lease, dir string, resolved map[string]string, interactive bool, remote []string) ([]string, error) {
	hostname := resolved["hostname"]
	if hostname == "" || strings.ContainsAny(hostname, "\r\n\x00") || strings.HasPrefix(hostname, "-") {
		return nil, errors.New("invalid alias hostname")
	}
	port, e := strconv.Atoi(resolved["port"])
	if e != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid alias port")
	}
	if interactive && !l.EffectivePolicy.PermitPTY {
		return nil, sshaccess.ErrDenied
	}
	args := []string{"-F", "/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "PermitLocalCommand=no", "-o", "ConnectTimeout=15", "-i", filepath.Join(dir, "id_ed25519"), "-o", "CertificateFile=" + filepath.Join(dir, "id_ed25519-cert.pub"), "-l", l.SSHUser, "-p", strconv.Itoa(port)}
	for _, field := range []struct{ k, opt string }{{"userknownhostsfile", "UserKnownHostsFile"}, {"globalknownhostsfile", "GlobalKnownHostsFile"}, {"hostkeyalias", "HostKeyAlias"}} {
		if v := resolved[field.k]; v != "" && v != "none" && !strings.ContainsAny(v, "\r\n\x00") {
			args = append(args, "-o", field.opt+"="+v)
		}
	}
	if interactive {
		args = append(args, "-tt")
	} else {
		args = append(args, "-T")
	}
	args = append(args, hostname)
	if len(remote) > 0 {
		quoted := make([]string, len(remote))
		for i, v := range remote {
			if strings.ContainsRune(v, 0) {
				return nil, errors.New("invalid remote argument")
			}
			quoted[i] = shellQuote(v)
		}
		args = append(args, strings.Join(quoted, " "))
	}
	return args, nil
}
func sshCA(args []string) error {
	if len(args) == 0 || args[0] != "init" {
		return errors.New("ssh ca init --dev OR --agent --public-key <file>")
	}
	fs := flag.NewFlagSet("ssh ca init", flag.ContinueOnError)
	dev := fs.Bool("dev", false, "explicit local development key only")
	agent := fs.Bool("agent", false, "native SSH-agent signing")
	pub := fs.String("public-key", "", "native-agent CA public file")
	socket := fs.String("agent-socket", "", "dedicated signer SSH-agent socket")
	if fs.Parse(args[1:]) != nil || *dev == *agent {
		return errors.New("choose explicit dev or native-agent mode")
	}
	dir := sshDir()
	if e := sshaccess.PrivateDir(dir); e != nil {
		return e
	}
	if _, e := os.Lstat(filepath.Join(dir, "config.json")); !os.IsNotExist(e) {
		return errors.New("SSH configuration already exists")
	}
	ca := sshaccess.CA{Mode: "agent", PublicKeyFile: *pub, AgentSocket: *socket}
	if *dev {
		keydir := filepath.Join(dir, "dev-ca")
		if e := sshaccess.PrivateDir(keydir); e != nil {
			return e
		}
		if _, e := generateLeaseKey(keydir); e != nil {
			return e
		}
		ca = sshaccess.CA{Mode: "dev", PublicKeyFile: filepath.Join(keydir, "id_ed25519.pub"), SecretRef: filepath.Join(keydir, "id_ed25519")}
	} else {
		b, e := os.ReadFile(*pub)
		if e != nil {
			return errors.New("CA public key unavailable")
		}
		if _, e = sshaccess.CAPublic(string(b)); e != nil {
			return e
		}
		if *socket == "" {
			return errors.New("dedicated CA agent socket required")
		}
	}
	public, e := os.ReadFile(ca.PublicKeyFile)
	if e != nil {
		return errors.New("CA public reference unavailable")
	}
	canonical, e := sshaccess.CAPublic(string(public))
	if e != nil {
		return e
	}
	ca.Fingerprint, e = sshaccess.PublicFingerprint(canonical)
	if e != nil {
		return e
	}
	c := sshaccess.Config{Workspace: "local", CA: ca, CertTTL: "15m", RenewBefore: "5m", ClockSkew: "30s", Hosts: map[string]sshaccess.Host{}}
	b, _ := json.MarshalIndent(c, "", "  ")
	if e := sshaccess.AtomicPrivate(filepath.Join(dir, "config.json"), b); e != nil {
		return e
	}
	fmt.Println("SSH CA reference initialized; no host trust installed")
	return nil
}
func sshHost(st *store.Store, args []string) error {
	if len(args) < 2 {
		return errors.New("ssh host add|bootstrap <logical-host>")
	}
	if _, e := sshActor(st, true); e != nil {
		return e
	}
	svc, e := sshaccess.Load(sshDir())
	if e != nil {
		return e
	}
	switch args[0] {
	case "bootstrap":
		fs := flag.NewFlagSet("host bootstrap", flag.ContinueOnError)
		out := fs.String("out", "", "private review bundle directory")
		dryRun := fs.Bool("dry-run", true, "review only; no host contact")
		validate := fs.String("validate-config", "", "optional locally prepared sshd candidate configuration")
		if fs.Parse(args[2:]) != nil || *out == "" {
			return errors.New("bootstrap --out required")
		}
		if !*dryRun {
			return errors.New("v1 emits a review bundle only; native admin trust installation is separate")
		}
		if e = sshaccess.BootstrapBundle(svc.Config, args[1], *out); e != nil {
			return e
		}
		if *validate != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if exec.CommandContext(ctx, "sshd", "-t", "-f", *validate).Run() != nil {
				return errors.New("native candidate sshd validation failed")
			}
		}
		fmt.Println("Public-only bootstrap bundle written; review and sshd validation required before trust installation")
		return nil
	case "add":
		fs := flag.NewFlagSet("host add", flag.ContinueOnError)
		alias := fs.String("alias", args[1], "local SSH alias")
		role := fs.String("role", "observe", "role")
		user := fs.String("user", "", "dedicated OS login")
		maximum := fs.String("max-lease", "1h", "authorization ceiling")
		def := fs.String("default-lease", "1h", "default window")
		cert := fs.String("max-cert-ttl", "15m", "credential ceiling")
		requester := fs.String("requester", "", "unambiguous SSH token app name")
		pre := fs.Bool("preapproved", false, "explicit matching-role preapproval")
		pty := fs.Bool("permit-pty", false, "explicit interactive role")
		explicit := fs.Bool("explicit-approval", true, "explicit risk approval")
		legacy := fs.Bool("legacy-auth-only", false, "explicit development-only authentication fixture")
		gateBinary := fs.String("gate-binary", "/usr/local/bin/21pins", "root-owned target gate binary")
		gatePolicy := fs.String("gate-policy", "/etc/ssh/21pins/commands.json", "root-owned target allowlist")
		allowlist := fs.String("command-allowlist", "", "private JSON fixed command/exec rule array")
		if fs.Parse(args[2:]) != nil {
			return errors.New("invalid host policy")
		}
		if _, ok := svc.Config.Hosts[args[1]]; ok {
			return errors.New("host binding already exists; review config updates separately")
		}
		mode := "approval"
		if *pre {
			mode = "preapproved"
			*explicit = false
		}
		r := sshaccess.Role{SSHUser: *user, DefaultLease: *def, MaxLease: *maximum, MaxCertTTL: *cert, Requesters: map[string]string{*requester: mode}, ExplicitApproval: *explicit, PermitPTY: *pty}
		if *legacy {
			if svc.Config.CA.Mode != "dev" {
				return errors.New("legacy authentication only for explicit development fixtures")
			}
		} else {
			rules := []sshcommand.Rule{{Command: []string{"status"}, Exec: []string{"/usr/bin/uptime"}}, {Command: []string{"platform"}, Exec: []string{"/usr/bin/uname", "-s"}}, {Command: []string{"identity"}, Exec: []string{"/usr/bin/id", "-u"}}}
			if *allowlist != "" {
				b, err := sshaccess.ReadPrivate(*allowlist)
				if err != nil {
					return err
				}
				d := json.NewDecoder(strings.NewReader(string(b)))
				d.DisallowUnknownFields()
				if d.Decode(&rules) != nil {
					return errors.New("invalid command allowlist")
				}
				var extra any
				if d.Decode(&extra) != io.EOF {
					return errors.New("extra command policy")
				}
			} else if *role != "observe" {
				return errors.New("non-observe role requires explicit command allowlist")
			}
			r.CommandAuthority = &sshcommand.Authority{Binary: *gateBinary, PolicyFile: *gatePolicy, Rules: rules}
		}
		svc.Config.Hosts[args[1]] = sshaccess.Host{Alias: *alias, Roles: map[string]sshaccess.Role{*role: r}}
		if _, e = sshaccess.New(svc.Dir, svc.Config, svc.Signer); e != nil {
			return e
		}
		b, _ := json.MarshalIndent(svc.Config, "", "  ")
		if e = sshaccess.AtomicPrivate(filepath.Join(svc.Dir, "config.json"), b); e != nil {
			return e
		}
		fmt.Println("Logical host/role policy registered; no remote host modified")
		return nil
	default:
		return errors.New("unknown host command")
	}
}
