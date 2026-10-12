// Package dnsadmin is a pinned, non-generic root helper. No requester argv reaches tools.
package dnsadmin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

var Denied = errors.New("dns-admin denied or verification failed")

const ManifestPath = "/etc/21pins/dns-admin.json"
const stateDir = "/var/lib/21pins/dns-admin"
const cidr = "10.66.66.5/32"
const resolver = "10.77.0.53"

var word = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$`)
var domain = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$`)

// DNS-only production authority: staged WireGuard helpers have no public dispatch/sudo grant.
var Operations = []string{"dns-query", "dns-test", "technitium-status", "technitium-filtering", "guest-isolation"}

type Manifest struct {
	Workspace          string `json:"workspace"`
	Host               string `json:"host"`
	Interface          string `json:"interface"`
	Peer               string `json:"peer_public_key"`
	Config             string `json:"wireguard_config"`
	Resolver           string `json:"resolver"`
	ControlDomain      string `json:"control_domain"`
	ControlA           string `json:"control_a"`
	BlockedDomain      string `json:"blocked_domain"`
	BlockedA           string `json:"blocked_a"`
	TechnitiumUnit     string `json:"technitium_unit"`
	ServiceConfigHash  string `json:"service_config_hash"`
	IsolationRulesHash string `json:"isolation_rules_hash"`
	IsolationProof     string `json:"isolation_proof"`
	GuestPrefix        string `json:"guest_prefix"`
	GuestIngress       string `json:"guest_ingress"`
}
type Result struct {
	Operation        string `json:"operation"`
	Verified         bool   `json:"verified"`
	State            string `json:"state"`
	PeerCount        int    `json:"peer_count,omitempty"`
	HandshakeRecent  bool   `json:"handshake_recent,omitempty"`
	HandshakeAt      int64  `json:"handshake_at,omitempty"`
	GuestPolicy      bool   `json:"guest_policy,omitempty"`
	GuestPacketProof bool   `json:"guest_packet_proof,omitempty"`
}
type engine struct {
	m    Manifest
	dir  string
	run  func(string, ...string) ([]byte, error)
	read func(string) ([]byte, error)
	now  func() time.Time
}
type journal struct {
	Original     []byte                    `json:"original"`
	PatchedHash  string                    `json:"patched_hash"`
	ManifestHash string                    `json:"manifest_hash"`
	PeerExisted  bool                      `json:"peer_existed"`
	OriginalLive map[string][]netip.Prefix `json:"original_live"`
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func valid(m Manifest) bool {
	// No live WG pins/authority exist: reject even dormant WG configuration in this profile.
	if m.Interface != "" || m.Peer != "" || m.Config != "" {
		return false
	}
	a, e := netip.ParseAddr(m.ControlA)
	h, e2 := hex.DecodeString(m.ServiceConfigHash)
	if e != nil || !a.Is4() || e2 != nil || len(h) != 32 || m.ServiceConfigHash != strings.ToLower(m.ServiceConfigHash) || m.Workspace != "local" || m.Host != "dns-primary" || m.Resolver != resolver || !domain.MatchString(m.ControlDomain) || m.TechnitiumUnit != "dns.service" {
		return false
	}
	if m.BlockedDomain != "" || m.BlockedA != "" {
		if !domain.MatchString(m.BlockedDomain) || m.BlockedDomain == m.ControlDomain || (m.BlockedA != "NXDOMAIN" && m.BlockedA != netip.IPv4Unspecified().String()) {
			return false
		}
	}
	if m.GuestPrefix == "" && m.GuestIngress == "" && m.IsolationRulesHash == "" && m.IsolationProof == "" {
		return true
	}
	g, e := netip.ParsePrefix(m.GuestPrefix)
	h, e2 = hex.DecodeString(m.IsolationRulesHash)
	return e == nil && g.Masked().String() == m.GuestPrefix && g.Addr().IsPrivate() && word.MatchString(m.GuestIngress) && e2 == nil && len(h) == 32 && m.IsolationProof == "/var/lib/21pins/dns-admin/guest-proof.json"
}

// Root ownership, nonsymlink regular file and nonwritable ancestors are checked before fd read.
func trustedFile(path string, private bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, Denied
	}
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		s, e := os.Lstat(p)
		if e != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm()&0022 != 0 || s.Sys().(*syscall.Stat_t).Uid != 0 {
			return nil, Denied
		}
		if p == "/" {
			break
		}
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, Denied
	}
	f := os.NewFile(uintptr(fd), path)
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Sys().(*syscall.Stat_t).Uid != 0 || s.Mode().Perm()&0022 != 0 || (private && (s.Mode().Perm()&0077 != 0 || s.Size() > 1<<20)) {
		f.Close()
		return nil, Denied
	}
	return f, nil
}
func trusted(path string, private bool) ([]byte, error) {
	f, e := trustedFile(path, private)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || s.Size() > 1<<20 {
		return nil, Denied
	}
	b := make([]byte, s.Size())
	if len(b) == 0 {
		return b, nil
	}
	if _, e = f.ReadAt(b, 0); e != nil {
		return nil, Denied
	}
	return b, nil
}
func native(tool string, args ...string) ([]byte, error) {
	f, e := trustedFile(tool, false)
	if e != nil {
		fmt.Fprintln(os.Stderr, "helper_tool_metadata_denied")
		return nil, Denied
	}
	f.Close()
	ctx, c := context.WithTimeout(context.Background(), 4*time.Second)
	defer c()
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LANG=C", "LC_ALL=C", "HOME=/"}
	cmd.Dir = "/"
	var out limited
	cmd.Stdout = &out
	cmd.Stderr = &limited{}
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "helper_tool_execution_denied")
		return nil, Denied
	}
	return out.b, nil
}

type limited struct{ b []byte }

func (l *limited) Write(p []byte) (int, error) {
	if len(l.b)+len(p) > 1<<20 {
		return 0, Denied
	}
	l.b = append(l.b, p...)
	return len(p), nil
}
func Run(args []string) (Result, error) {
	r := Result{State: "denied"}
	if os.Geteuid() != 0 || len(args) != 2 {
		return r, Denied
	}
	ok := false
	for _, op := range Operations {
		ok = ok || args[0] == op
	}
	if !ok {
		return r, Denied
	}
	b, e := trusted(ManifestPath, true)
	if e != nil || digest(b) != args[1] {
		return r, Denied
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&m) != nil || !valid(m) {
		return r, Denied
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		return r, Denied
	}
	// Installed root-only lock is never created by a read-only operation.
	s, err := os.Lstat(stateDir)
	if err != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm()&0077 != 0 || s.Sys().(*syscall.Stat_t).Uid != 0 {
		return r, Denied
	}
	lock := stateDir + "/lock"
	if _, e = trusted(lock, true); e != nil {
		return r, Denied
	}
	fd, e := syscall.Open(lock, syscall.O_RDWR|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return r, Denied
	}
	defer syscall.Close(fd)
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return r, Denied
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	x := engine{m: m, dir: stateDir, run: native, read: func(p string) ([]byte, error) { return trusted(p, p != "/etc/systemd/system/dns.service") }, now: time.Now}
	return x.operation(args[0])
}
func parsePeers(b []byte) (map[string][]netip.Prefix, error) {
	out := map[string][]netip.Prefix{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return nil, Denied
		}
		ips := strings.Join(f[1:], "")
		key, e := base64.StdEncoding.DecodeString(f[0])
		if e != nil || len(key) != 32 {
			return nil, Denied
		}
		if _, exists := out[f[0]]; exists {
			return nil, Denied
		}
		out[f[0]] = []netip.Prefix{}
		if ips == "(none)" {
			continue
		}
		for _, s := range strings.Split(ips, ",") {
			p, e := netip.ParsePrefix(s)
			if e != nil || p.Masked().String() != s {
				return nil, Denied
			}
			out[f[0]] = append(out[f[0]], p)
		}
	}
	return out, nil
}
func (x engine) live() (map[string][]netip.Prefix, error) {
	b, e := x.run("/usr/bin/wg", "show", x.m.Interface, "allowed-ips")
	if e != nil {
		return nil, Denied
	}
	return parsePeers(b)
}
func check(peers map[string][]netip.Prefix, key string) (bool, error) {
	want := netip.MustParsePrefix(cidr)
	for k, ps := range peers {
		for _, p := range ps {
			if k != key && p.Overlaps(want) {
				return false, Denied
			}
		}
	}
	p, ok := peers[key]
	if ok && (len(p) != 1 || p[0] != want) {
		return false, Denied
	}
	return ok, nil
}
func persistent(b []byte) (map[string][]netip.Prefix, error) {
	lines := strings.Split(string(b), "\n")
	peers := map[string][]netip.Prefix{}
	section := ""
	interfaceSeen := false
	key := ""
	ips := ""
	flush := func() error {
		if section != "Peer" {
			return nil
		}
		if key == "" || ips == "" {
			return Denied
		}
		if _, ok := peers[key]; ok {
			return Denied
		}
		m, e := parsePeers([]byte(key + " " + strings.ReplaceAll(ips, " ", "")))
		if e != nil {
			return e
		}
		peers[key] = m[key]
		return nil
	}
	for _, raw := range lines {
		s := strings.TrimSpace(raw)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if strings.HasPrefix(s, "[") {
			if flush() != nil {
				return nil, Denied
			}
			if s != "[Interface]" && s != "[Peer]" {
				return nil, Denied
			}
			if s == "[Interface]" {
				if interfaceSeen || section != "" {
					return nil, Denied
				}
				interfaceSeen = true
			} else if !interfaceSeen {
				return nil, Denied
			}
			section = strings.Trim(s, "[]")
			key = ""
			ips = ""
			continue
		}
		k, v, ok := strings.Cut(s, "=")
		if !ok || section == "" {
			return nil, Denied
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "SaveConfig" && v != "false" {
			return nil, Denied
		}
		if section == "Peer" {
			switch k {
			case "PublicKey":
				if key != "" {
					return nil, Denied
				}
				key = v
			case "AllowedIPs":
				if ips != "" {
					return nil, Denied
				}
				ips = v
			}
		}
	}
	if flush() != nil || !interfaceSeen {
		return nil, Denied
	}
	return peers, nil
}
func (x engine) verify() (Result, error) {
	r := Result{State: "not_enrolled"}
	if _, e := os.Lstat(x.dir + "/pending.json"); e == nil {
		return r, Denied
	} else if !os.IsNotExist(e) {
		return r, Denied
	}
	b, e := x.read(x.m.Config)
	if e != nil {
		return r, Denied
	}
	p, e := persistent(b)
	if e != nil {
		return r, Denied
	}
	a, e := x.live()
	if e != nil || !equalPeers(p, a) {
		return r, Denied
	}
	pOK, e := check(p, x.m.Peer)
	if e != nil {
		return r, e
	}
	aOK, e := check(a, x.m.Peer)
	if e != nil {
		return r, e
	}
	r.PeerCount = len(a)
	r.Verified = pOK && aOK
	if !r.Verified {
		return r, Denied
	}
	r.State = "configured"
	return r, nil
}
func atomic(path string, b []byte) error {
	// Only fixed already-reviewed directories; a private random file is fsynced before rename.
	f, e := os.CreateTemp(filepath.Dir(path), ".21pins-transaction-")
	if e != nil {
		return Denied
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if f.Chmod(0600) != nil {
		f.Close()
		return Denied
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return Denied
	}
	if f.Sync() != nil || f.Close() != nil {
		return Denied
	}
	if os.Rename(tmp, path) != nil {
		return Denied
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return Denied
	}
	defer d.Close()
	return d.Sync()
}
func (x engine) manifestHash() string { b, _ := json.Marshal(x.m); return digest(b) }
func (x engine) rollback(j journal) error {
	b, e := x.read(x.m.Config)
	if e != nil || (digest(b) != digest(j.Original) && digest(b) != j.PatchedHash) || j.ManifestHash != x.manifestHash() {
		return Denied
	}
	live, e := x.live()
	if e != nil {
		return Denied
	}
	exists, e := check(live, x.m.Peer)
	if e != nil {
		return Denied
	}
	if atomic(x.m.Config, j.Original) != nil {
		return Denied
	}
	if !j.PeerExisted && exists {
		if _, e = x.run("/usr/bin/wg", "set", x.m.Interface, "peer", x.m.Peer, "remove"); e != nil {
			return Denied
		}
	}
	after, e := x.live()
	if e != nil {
		return Denied
	}
	exists, e = check(after, x.m.Peer)
	if e != nil || exists != j.PeerExisted {
		return Denied
	}
	b, e = x.read(x.m.Config)
	if e != nil || digest(b) != digest(j.Original) || !equalPeers(after, j.OriginalLive) {
		return Denied
	}
	return os.Remove(x.dir + "/pending.json")
}

// Only this helper's private orphan temp files, under the exclusive installed lock.
func (x engine) cleanTemps() error {
	for _, dir := range []string{x.dir, filepath.Dir(x.m.Config)} {
		entries, e := os.ReadDir(dir)
		if e != nil {
			return Denied
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), ".21pins-transaction-") {
				continue
			}
			p := filepath.Join(dir, entry.Name())
			s, e := os.Lstat(p)
			if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0 || s.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
				return Denied
			}
			if os.Remove(p) != nil {
				return Denied
			}
		}
	}
	return nil
}
func (x engine) enroll() (Result, error) {
	r := Result{State: "denied"}
	if x.cleanTemps() != nil {
		return r, Denied
	}
	pending := x.dir + "/pending.json"
	if _, e := os.Lstat(pending); e == nil {
		b, e := x.read(pending)
		if e != nil {
			return r, Denied
		}
		var j journal
		if json.Unmarshal(b, &j) != nil || x.rollback(j) != nil {
			return Result{State: "rollback_failed"}, Denied
		}
	} else if !os.IsNotExist(e) {
		return r, Denied
	}
	old, e := x.read(x.m.Config)
	if e != nil {
		r.State = "persistence_unavailable"
		return r, Denied
	}
	p, e := persistent(old)
	if e != nil {
		r.State = "persistence_invalid"
		return r, e
	}
	live, e := x.live()
	if e != nil {
		r.State = "wireguard_unavailable"
		return r, e
	}
	pOK, e := check(p, x.m.Peer)
	if e != nil {
		return r, e
	}
	aOK, e := check(live, x.m.Peer)
	if e != nil || pOK != aOK || !equalPeers(p, live) {
		return r, Denied
	}
	if pOK {
		return x.verify()
	}
	patched := append(append([]byte{}, old...), []byte("\n[Peer]\nPublicKey = "+x.m.Peer+"\nAllowedIPs = "+cidr+"\n")...)
	j := journal{Original: old, PatchedHash: digest(patched), ManifestHash: x.manifestHash(), PeerExisted: false, OriginalLive: live}
	b, _ := json.Marshal(j)
	if atomic(pending, b) != nil {
		return r, Denied
	}
	if atomic(x.m.Config, patched) != nil {
		if x.rollback(j) != nil {
			return Result{State: "rollback_failed"}, Denied
		}
		return Result{State: "rolled_back"}, Denied
	}
	if _, e = x.run("/usr/bin/wg", "set", x.m.Interface, "peer", x.m.Peer, "allowed-ips", cidr); e != nil {
		if x.rollback(j) != nil {
			return Result{State: "rollback_failed"}, Denied
		}
		return Result{State: "rolled_back"}, Denied
	}
	current, e := x.read(x.m.Config)
	after, e2 := x.live()
	ok, e3 := check(after, x.m.Peer)
	if e != nil || digest(current) != digest(patched) || e2 != nil || e3 != nil || !ok || !preserved(live, after, x.m.Peer) {
		if x.rollback(j) != nil {
			return Result{State: "rollback_failed"}, Denied
		}
		return Result{State: "rolled_back"}, Denied
	}
	if os.Remove(pending) != nil {
		return Result{State: "pending_recovery"}, Denied
	}
	return x.verify()
}
func equalPeers(a, b map[string][]netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for k, p := range a {
		q, ok := b[k]
		if !ok || fmt.Sprint(p) != fmt.Sprint(q) {
			return false
		}
	}
	return true
}
func preserved(before, after map[string][]netip.Prefix, key string) bool {
	if len(after) != len(before)+1 {
		return false
	}
	for k, v := range before {
		if k == key {
			continue
		}
		a, ok := after[k]
		if !ok || fmt.Sprint(a) != fmt.Sprint(v) {
			return false
		}
	}
	return true
}
func (x engine) dns(name string, want string, extra ...string) bool {
	args := []string{"@" + resolver, name, "A", "+time=2", "+tries=1", "+noall", "+comments", "+answer"}
	b, e := x.run("/usr/bin/dig", append(args, extra...)...)
	if e != nil {
		return false
	}
	s := string(b)
	if want == "NXDOMAIN" {
		return strings.Contains(s, "status: NXDOMAIN,") && !strings.Contains(s, "\tA\t")
	}
	if !strings.Contains(s, "status: NOERROR,") {
		return false
	}
	found := false
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, ";") || strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 5 || f[0] != name+"." || f[2] != "IN" || f[3] != "A" || f[4] != want {
			return false
		}
		found = true
	}
	return found
}

// Proof is independently root-generated guest-origin evidence, not a fabricated local DNS probe.
type guestProof struct {
	RulesHash    string    `json:"rules_hash"`
	At           time.Time `json:"at"`
	GuestOrigin  bool      `json:"guest_origin"`
	GuestPrefix  string    `json:"guest_prefix"`
	GuestIngress string    `json:"guest_ingress"`
	UDPBlocked   bool      `json:"udp_blocked"`
	TCPBlocked   bool      `json:"tcp_blocked"`
}

func (x engine) operation(op string) (Result, error) {
	r := Result{Operation: op, State: "denied"}
	if (strings.HasPrefix(op, "peer-") || strings.HasPrefix(op, "wg-")) && x.m.Interface == "" {
		r.State = "wireguard_prerequisites_unavailable"
		return r, Denied
	}
	switch op {
	case "peer-enroll":
		r, e := x.enroll()
		r.Operation = op
		return r, e
	case "peer-verify":
		r, e := x.verify()
		r.Operation = op
		return r, e
	case "wg-state":
		p, e := x.live()
		if e != nil {
			return r, e
		}
		_, e = check(p, x.m.Peer)
		if e != nil {
			return r, e
		}
		r.PeerCount = len(p)
		r.Verified = true
		r.State = "inspected"
	case "wg-handshake":
		v, e := x.verify()
		if e != nil {
			return r, e
		}
		b, e := x.run("/usr/bin/wg", "show", x.m.Interface, "latest-handshakes")
		if e != nil {
			return r, e
		}
		seen := false
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			f := strings.Fields(line)
			if len(f) != 2 {
				return r, Denied
			}
			if f[0] != x.m.Peer {
				continue
			}
			if seen {
				return r, Denied
			}
			seen = true
			var stamp int64
			if _, e = fmt.Sscanf(f[1], "%d", &stamp); e != nil || fmt.Sprint(stamp) != f[1] {
				return r, Denied
			}
			age := x.now().Sub(time.Unix(stamp, 0))
			r.HandshakeRecent = stamp > 0 && age >= 0 && age <= 3*time.Minute
			if r.HandshakeRecent {
				r.HandshakeAt = stamp
			}
		}
		if !seen || !r.HandshakeRecent {
			return r, Denied
		}
		r.PeerCount = v.PeerCount
		r.Verified = true
		r.State = "recent_handshake"
	case "dns-query", "dns-test":
		r.Verified = x.dns(x.m.ControlDomain, x.m.ControlA)
		if op == "dns-test" {
			r.Verified = r.Verified && x.dns(x.m.ControlDomain, x.m.ControlA, "+tcp")
		}
		r.State = "dns_checked"
	case "technitium-status", "technitium-filtering":
		if op == "technitium-filtering" && (x.m.BlockedDomain == "" || x.m.BlockedA == "") {
			r.State = "filter_probe_unconfigured"
			return r, Denied
		}
		b, e := x.read("/etc/systemd/system/dns.service")
		if e != nil || digest(b) != x.m.ServiceConfigHash {
			return r, Denied
		}
		b, e = x.run("/usr/bin/systemctl", "show", "--property=DropInPaths", "--value", x.m.TechnitiumUnit)
		if e != nil || len(bytes.TrimSpace(b)) != 0 {
			return r, Denied
		}
		_, e = x.run("/usr/bin/systemctl", "is-active", "--quiet", x.m.TechnitiumUnit)
		r.Verified = e == nil
		if op == "technitium-filtering" {
			r.Verified = r.Verified && x.dns(x.m.ControlDomain, x.m.ControlA) && x.dns(x.m.ControlDomain, x.m.ControlA, "+tcp") && x.dns(x.m.BlockedDomain, x.m.BlockedA) && x.dns(x.m.BlockedDomain, x.m.BlockedA, "+tcp")
		}
		r.State = "technitium_checked"
	case "guest-isolation":
		if x.m.GuestPrefix == "" || x.m.IsolationProof == "" {
			r.State = "guest_origin_prerequisites_unavailable"
			return r, Denied
		}
		b, e := x.run("/usr/sbin/nft", "--stateless", "--json", "list", "ruleset")
		if e != nil {
			return r, e
		}
		r.GuestPolicy = digest(b) == x.m.IsolationRulesHash
		if !r.GuestPolicy {
			return r, Denied
		}
		b, e = x.read(x.m.IsolationProof)
		if e != nil {
			r.State = "guest_origin_proof_required"
			return r, Denied
		}
		var p guestProof
		if json.Unmarshal(b, &p) != nil {
			return r, Denied
		}
		age := x.now().Sub(p.At)
		r.GuestPacketProof = p.RulesHash == x.m.IsolationRulesHash && p.GuestOrigin && p.GuestPrefix == x.m.GuestPrefix && p.GuestIngress == x.m.GuestIngress && p.UDPBlocked && p.TCPBlocked && age >= 0 && age <= 2*time.Minute
		r.Verified = r.GuestPacketProof
		r.State = "guest_evidence_checked"
	default:
		return r, Denied
	}
	if !r.Verified {
		return r, Denied
	}
	return r, nil
}
