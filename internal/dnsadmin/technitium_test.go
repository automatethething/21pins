package dnsadmin

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTechnitiumDNSOnlyProfile(t *testing.T) {
	unit := []byte("[Service]\nExecStart=/usr/bin/dotnet /opt/technitium/dns/DnsServerApp.dll\n")
	raw, _ := json.Marshal(map[string]string{"workspace": "local", "host": "dns-primary", "resolver": resolver, "control_domain": "localhost", "control_a": "127.0.0.1", "technitium_unit": "dns.service", "service_config_hash": digest(unit)})
	var m Manifest
	json.Unmarshal(raw, &m)
	if !valid(m) {
		t.Fatal("real DNS-only profile requires no invented WG/guest/filter pins")
	}
	f := setup(t)
	f.x.m = m
	f.x.read = func(p string) ([]byte, error) {
		if p == "/etc/systemd/system/dns.service" {
			return unit, nil
		}
		return nil, Denied
	}
	f.x.run = func(p string, a ...string) ([]byte, error) {
		f.calls = append(f.calls, p+" "+strings.Join(a, " "))
		if p == "/usr/bin/systemctl" && strings.Join(a, " ") == "show --property=DropInPaths --value dns.service" {
			return nil, nil
		}
		if p == "/usr/bin/systemctl" && strings.Join(a, " ") == "is-active --quiet dns.service" {
			return nil, nil
		}
		if p == "/usr/bin/dig" {
			return []byte(";; status: NOERROR,\nlocalhost. 30 IN A 127.0.0.1\n"), nil
		}
		return nil, Denied
	}
	for _, op := range []string{"dns-query", "dns-test", "technitium-status"} {
		r, e := f.x.operation(op)
		if e != nil || !r.Verified {
			t.Fatal(op, r, e)
		}
	}
	callsBeforeUnavailable := len(f.calls)
	for _, op := range []string{"peer-enroll", "peer-verify", "wg-state", "wg-handshake", "adguard-status", "adguard-filtering", "technitium-filtering", "guest-isolation"} {
		r, e := f.x.operation(op)
		if e == nil || r.Verified {
			t.Fatal("unavailable authority verified", op)
		}
	}
	if len(f.calls) != callsBeforeUnavailable {
		t.Fatal("missing selectors invoked native tools")
	}
	for _, c := range f.calls {
		if strings.Contains(c, "wg ") {
			t.Fatal("unavailable WG invoked")
		}
	}
	if !strings.Contains(strings.Join(f.calls, "\n"), "+tcp") {
		t.Fatal("DNS TCP not verified")
	}
	nativeRun := f.x.run
	f.x.run = func(p string, a ...string) ([]byte, error) {
		if strings.Contains(strings.Join(a, " "), "DropInPaths") {
			return []byte("/etc/systemd/system/dns.service.d/unreviewed.conf"), nil
		}
		return nativeRun(p, a...)
	}
	if _, e := f.x.operation("technitium-status"); e == nil {
		t.Fatal("unreviewed service override accepted")
	}
	f.x.run = nativeRun
	f.x.m.ServiceConfigHash = strings.Repeat("b", 64)
	if _, e := f.x.operation("technitium-status"); e == nil {
		t.Fatal("service identity drift")
	}
}
