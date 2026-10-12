package dnsadmin

import (
	"encoding/hex"
	"github.com/petrichor/21pins-cli/internal/sshcommand"
	"strings"
)

// Rules bind root manifest contents as well as the literal operation into signed authority.
func Rules(manifestDigest string) ([]sshcommand.Rule, error) {
	b, e := hex.DecodeString(manifestDigest)
	if e != nil || len(b) != 32 || strings.ToLower(manifestDigest) != manifestDigest {
		return nil, Denied
	}
	words := [][]string{{"dns", "query"}, {"dns", "test"}, {"technitium", "status"}, {"technitium", "filtering"}, {"guest", "isolation"}}
	rules := make([]sshcommand.Rule, len(Operations))
	for i, op := range Operations {
		rules[i] = sshcommand.Rule{Command: words[i], Exec: []string{"/usr/bin/sudo", "-n", "/usr/local/bin/21pins", "dns-admin", op, manifestDigest}}
	}
	return rules, nil
}
func Sudoers(manifestDigest string) (string, error) {
	rules, e := Rules(manifestDigest)
	if e != nil {
		return "", e
	}
	commands := []string{}
	for _, r := range rules {
		commands = append(commands, strings.Join(r.Exec[2:], " "))
	}
	return "Defaults:pins-dns-agent env_reset, !setenv, !requiretty, secure_path=/usr/sbin:/usr/bin\npins-dns-agent ALL=(root) NOPASSWD: NOSETENV: " + strings.Join(commands, ", ") + "\n", nil
}
