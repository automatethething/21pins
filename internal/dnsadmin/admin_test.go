package dnsadmin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func key(n byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32)) }

type fixture struct {
	x          engine
	peers      map[string][]netip.Prefix
	failSet    bool
	failRemove bool
	drift      bool
	handshake  int64
	service    bool
	calls      []string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	d := t.TempDir()
	f := &fixture{peers: map[string][]netip.Prefix{key(2): {netip.MustParsePrefix("10.66.66.6/32")}}, service: true, handshake: time.Now().Unix()}
	f.x = engine{m: Manifest{Workspace: "local", Host: "dns-primary", Interface: "wg0", Peer: key(1), Config: filepath.Join(d, "wg.conf"), Resolver: resolver, ControlDomain: "probe.example", ControlA: "10.77.0.53", BlockedDomain: "blocked.example", BlockedA: "NXDOMAIN", TechnitiumUnit: "dns.service", ServiceConfigHash: digest([]byte("technitium-unit")), IsolationRulesHash: digest([]byte("rules")), IsolationProof: filepath.Join(d, "proof.json"), GuestPrefix: "10.88.0.0/24", GuestIngress: "guest0"}, dir: d, read: func(p string) ([]byte, error) {
		if p == "/etc/systemd/system/dns.service" {
			return []byte("technitium-unit"), nil
		}
		return os.ReadFile(p)
	}, now: time.Now}
	os.WriteFile(f.x.m.Config, []byte("[Interface]\nPrivateKey = synthetic-never-display\n\n[Peer]\nPublicKey = "+key(2)+"\nAllowedIPs = 10.66.66.6/32\n"), 0600)
	f.x.run = func(tool string, a ...string) ([]byte, error) {
		f.calls = append(f.calls, tool+" "+strings.Join(a, " "))
		if tool == "/usr/bin/wg" {
			switch {
			case len(a) == 3 && a[0] == "show" && a[1] == "wg0" && a[2] == "allowed-ips":
				var out strings.Builder
				for k, ps := range f.peers {
					p := []string{}
					for _, v := range ps {
						p = append(p, v.String())
					}
					out.WriteString(k + "\t" + strings.Join(p, ", ") + "\n")
				}
				return []byte(out.String()), nil
			case len(a) == 3 && a[2] == "latest-handshakes":
				return []byte(f.x.m.Peer + "\t" + strconv.FormatInt(f.handshake, 10) + "\n"), nil
			case len(a) == 6 && a[0] == "set" && a[1] == "wg0" && a[2] == "peer" && a[3] == key(1) && a[4] == "allowed-ips" && a[5] == cidr:
				f.peers[key(1)] = []netip.Prefix{netip.MustParsePrefix(cidr)}
				if f.drift {
					f.peers[key(2)] = []netip.Prefix{netip.MustParsePrefix("10.66.66.7/32")}
				}
				if f.failSet {
					return nil, Denied
				}
				return nil, nil
			case len(a) == 5 && a[4] == "remove":
				if f.failRemove {
					return nil, Denied
				}
				delete(f.peers, key(1))
				return nil, nil
			}
			return nil, Denied
		}
		if tool == "/usr/bin/dig" && (len(a) == 8 || len(a) == 9) && a[0] == "@"+resolver {
			if a[1] == f.x.m.ControlDomain {
				return []byte(";; ->>HEADER<<- status: NOERROR,\nprobe.example. 30 IN A 10.77.0.53\n"), nil
			}
			return []byte(";; ->>HEADER<<- status: NXDOMAIN,\n"), nil
		}
		if tool == "/usr/bin/systemctl" && strings.Join(a, " ") == "show --property=DropInPaths --value dns.service" {
			return nil, nil
		}
		if tool == "/usr/bin/systemctl" && len(a) == 3 && a[2] == "dns.service" {
			if f.service {
				return nil, nil
			}
			return nil, Denied
		}
		if tool == "/usr/sbin/nft" {
			return []byte("rules"), nil
		}
		return nil, Denied
	}
	return f
}
func TestEnrollmentTransactionAndPrivilegeSurface(t *testing.T) {
	f := setup(t)
	old, _ := os.ReadFile(f.x.m.Config)
	r, e := f.x.operation("peer-enroll")
	if e != nil || !r.Verified {
		t.Fatal("enroll", e)
	}
	after, _ := os.ReadFile(f.x.m.Config)
	if !bytes.HasPrefix(after, old) || len(f.peers) != 2 {
		t.Fatal("unrelated state changed")
	}
	if r, e = f.x.operation("peer-enroll"); e != nil || !r.Verified {
		t.Fatal("idempotence")
	}
	again, _ := os.ReadFile(f.x.m.Config)
	if !bytes.Equal(again, after) {
		t.Fatal("duplicate persistence")
	}
	if _, e = os.Stat(f.x.dir + "/pending.json"); !os.IsNotExist(e) {
		t.Fatal("journal retained")
	}
	for _, op := range []string{"peer-verify", "wg-state", "wg-handshake", "dns-query", "dns-test", "technitium-status", "technitium-filtering"} {
		if r, e = f.x.operation(op); e != nil || !r.Verified {
			t.Fatal(op)
		}
	}
	for _, op := range []string{"sh", "peer-enroll --peer other", "peer-enroll;id", "sudo", "install", "wg set", "dns-query other"} {
		if _, e = f.x.operation(op); e == nil {
			t.Fatal("expanded privilege")
		}
	}
	out, _ := json.Marshal(r)
	for _, s := range []string{key(1), key(2), "synthetic-never-display", "10.66.66"} {
		if bytes.Contains(out, []byte(s)) {
			t.Fatal("diagnostic disclosure")
		}
	}
}
func TestRollbackConflictRecoveryAndFailClosed(t *testing.T) {
	for _, mode := range []string{"overlap", "wrong-own-range", "partial-tool-failure", "rollback-failure", "unrelated-drift", "crash-recovery", "tampered-journal"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			old, _ := os.ReadFile(f.x.m.Config)
			switch mode {
			case "overlap":
				f.peers[key(2)] = []netip.Prefix{netip.MustParsePrefix("10.66.66.0/24")}
			case "wrong-own-range":
				f.peers[key(1)] = []netip.Prefix{netip.MustParsePrefix("10.66.66.4/32")}
			case "partial-tool-failure":
				f.failSet = true
			case "rollback-failure":
				f.failSet = true
				f.failRemove = true
			case "unrelated-drift":
				f.drift = true
			case "crash-recovery", "tampered-journal":
				patched := append(append([]byte{}, old...), []byte("\n[Peer]\nPublicKey = "+key(1)+"\nAllowedIPs = "+cidr+"\n")...)
				j := journal{Original: old, PatchedHash: digest(patched), ManifestHash: f.x.manifestHash(), OriginalLive: f.peers}
				if mode == "tampered-journal" {
					j.ManifestHash = "wrong"
				}
				b, _ := json.Marshal(j)
				os.WriteFile(f.x.dir+"/pending.json", b, 0600)
				os.WriteFile(f.x.m.Config, patched, 0600)
			}
			r, e := f.x.operation("peer-enroll")
			if mode == "crash-recovery" {
				if e != nil || !r.Verified {
					t.Fatal("bounded recovery")
				}
				return
			}
			if e == nil {
				t.Fatal("unsafe enrollment succeeded")
			}
			b, _ := os.ReadFile(f.x.m.Config)
			if mode == "overlap" || mode == "wrong-own-range" || mode == "partial-tool-failure" {
				if !bytes.Equal(b, old) {
					t.Fatal("not restored")
				}
			}
			if mode == "partial-tool-failure" && len(f.peers) != 1 {
				t.Fatal("live rollback")
			}
			if mode == "rollback-failure" || mode == "unrelated-drift" {
				if r.State != "rollback_failed" {
					t.Fatal("false rollback claim")
				}
			}
		})
	}
}
func TestGuestIsolationNeedsFreshBoundGuestPacketProof(t *testing.T) {
	f := setup(t)
	r, e := f.x.operation("guest-isolation")
	if e == nil || !r.GuestPolicy || r.GuestPacketProof {
		t.Fatal("policy is not empirical proof")
	}
	for _, mode := range []string{"fresh", "stale", "wrong-rules", "wrong-guest", "dns-only"} {
		p := guestProof{RulesHash: f.x.m.IsolationRulesHash, At: time.Now(), GuestOrigin: true, GuestPrefix: f.x.m.GuestPrefix, GuestIngress: f.x.m.GuestIngress, UDPBlocked: true, TCPBlocked: true}
		switch mode {
		case "stale":
			p.At = p.At.Add(-3 * time.Minute)
		case "wrong-rules":
			p.RulesHash = "wrong"
		case "wrong-guest":
			p.GuestIngress = "other"
		case "dns-only":
			p.TCPBlocked = false
		}
		b, _ := json.Marshal(p)
		os.WriteFile(f.x.m.IsolationProof, b, 0600)
		r, e = f.x.operation("guest-isolation")
		if (e == nil) != (mode == "fresh") || r.Verified != (mode == "fresh") {
			t.Fatal(mode)
		}
	}
}
func TestManifestParsingAndRootBoundary(t *testing.T) {
	f := setup(t)
	m := f.x.m
	m.Interface, m.Peer, m.Config = "", "", ""
	m.IsolationProof = "/var/lib/21pins/dns-admin/guest-proof.json"
	if !valid(m) {
		t.Fatal("valid pins")
	}
	m.Peer = "arbitrary"
	if valid(m) {
		t.Fatal("bad public peer")
	}
	if _, e := Run([]string{"peer-enroll", "arbitrary", "extra"}); e == nil {
		t.Fatal("root helper extra args")
	}
	if _, e := trusted(f.x.m.Config, true); e == nil {
		t.Fatal("non-root/nontrusted ancestors accepted")
	}
	if _, e := persistent([]byte("[Interface]\nSaveConfig = true\n")); e == nil {
		t.Fatal("SaveConfig race")
	}
	if _, e := parsePeers([]byte(key(2) + "\t10.66.66.6/32, 10.66.66.7/32\n")); e != nil {
		t.Fatal("native multi-prefix output")
	}
	f.service = false
	if _, e := f.x.operation("technitium-filtering"); e == nil {
		t.Fatal("absent Technitium falsely verified")
	}
}
