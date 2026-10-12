package sshcommand

import (
	"reflect"
	"testing"
)

func TestLiteralArgvAndExactAllowlist(t *testing.T) {
	policy := RolePolicy{User: "pins-agent", Rules: []Rule{{Command: []string{"status"}, Exec: []string{"/usr/bin/uptime"}}, {Command: []string{"platform"}, Exec: []string{"/usr/bin/uname", "-s"}}}}
	for _, input := range []string{"status", "'status'", "  'platform'  "} {
		argv, e := Parse(input)
		if e != nil {
			t.Fatal(e)
		}
		out, e := Authorize(policy, argv)
		if e != nil || len(out) == 0 {
			t.Fatal("allowed operation denied")
		}
	}
	for _, input := range []string{"", "sh -c id", "status; id", "status && id", "status | id", "$(id)", "`id`", "status > /tmp/out", "status\nid", "status extra", "'status;id'", "/usr/bin/uptime", "/usr/local/bin/21pins ssh gate --role dns-admin", "sftp", "status\\;id", "\"status\"", "'plat\x01form'", "'plat\x7fform'", "'plat\u202eform'"} {
		argv, e := Parse(input)
		if e == nil {
			_, e = Authorize(policy, argv)
		}
		if e == nil {
			t.Fatal("escape allowed", input)
		}
	}
	for _, input := range []string{"'plat\x01form'", "'plat\x7fform'", "'plat\u202eform'"} {
		if _, e := Parse(input); e == nil {
			t.Fatal("control accepted by literal parser")
		}
	}
	argv, e := Parse("'one' 'two words' 'a'\"'\"'b'")
	if e != nil || !reflect.DeepEqual(argv, []string{"one", "two words", "a'b"}) {
		t.Fatal("literal CLI quoting unsupported")
	}
}
func TestScopeAndPolicyValidation(t *testing.T) {
	p := Policy{Workspace: "local", Host: "alpha", Roles: map[string]RolePolicy{"observe": {User: "pins-agent", Rules: []Rule{{Command: []string{"status"}, Exec: []string{"/usr/bin/uptime"}}}}}}
	if p.Validate() != nil {
		t.Fatal("valid policy")
	}
	if _, e := p.Role("local", "alpha", "observe", "pins-agent"); e != nil {
		t.Fatal(e)
	}
	for _, q := range [][4]string{{"local", "beta", "observe", "pins-agent"}, {"other", "alpha", "observe", "pins-agent"}, {"local", "alpha", "dns-admin", "pins-agent"}, {"local", "alpha", "observe", "root"}} {
		if _, e := p.Role(q[0], q[1], q[2], q[3]); e == nil {
			t.Fatal("scope bypass")
		}
	}
	p.Roles["dns-admin"] = RolePolicy{User: "pins-agent", Rules: []Rule{{Command: []string{"enroll"}, Exec: []string{"/usr/local/libexec/fixed-helper"}}}}
	if p.Validate() == nil {
		t.Fatal("shared Unix user crosses command roles")
	}
}
