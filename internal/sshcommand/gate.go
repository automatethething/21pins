// Package sshcommand authorizes literal operation argv, never shell programs.
package sshcommand

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

var Denied = errors.New("SSH command denied")
var id = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
var pathWord = regexp.MustCompile(`^/[a-zA-Z0-9_./-]+$`)

type Rule struct {
	Command []string `json:"command"`
	Exec    []string `json:"exec"`
}
type RolePolicy struct {
	User  string `json:"user"`
	Rules []Rule `json:"allow"`
}
type Policy struct {
	Workspace string                `json:"workspace_id"`
	Host      string                `json:"host_id"`
	Roles     map[string]RolePolicy `json:"roles"`
}
type Authority struct {
	Binary     string `json:"binary"`
	PolicyFile string `json:"policy_file"`
	Rules      []Rule `json:"allow"`
	Fixture    bool   `json:"dev_fixture,omitempty"`
}

func (a Authority) Validate() error {
	if !cleanPath(a.Binary) || !cleanPath(a.PolicyFile) || len(a.Rules) == 0 {
		return Denied
	}
	return validateRules(a.Rules)
}
func cleanPath(s string) bool {
	return pathWord.MatchString(s) && filepath.Clean(s) == s && !strings.Contains(s, "//")
}
func validateRules(rules []Rule) error {
	if len(rules) == 0 || len(rules) > 32 {
		return Denied
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if len(r.Command) == 0 || len(r.Command) > 8 || len(r.Exec) == 0 || len(r.Exec) > 16 || !cleanPath(r.Exec[0]) {
			return Denied
		}
		switch filepath.Base(r.Exec[0]) {
		case "sh", "bash", "dash", "zsh", "ksh", "csh", "fish", "env", "python", "python3", "node", "perl", "ruby":
			return Denied
		}
		for _, v := range append(append([]string{}, r.Command...), r.Exec...) {
			if v == "" || len(v) > 256 || unsafeText(v) {
				return Denied
			}
		}
		for _, v := range r.Command {
			if strings.ContainsAny(v, ";$`|&<>\\(){}") {
				return Denied
			}
		}
		key := strings.Join(r.Command, "\x00")
		if seen[key] {
			return Denied
		}
		seen[key] = true
	}
	return nil
}
func (p Policy) Validate() error {
	if !id.MatchString(p.Workspace) || !id.MatchString(p.Host) || len(p.Roles) == 0 || len(p.Roles) > 32 {
		return Denied
	}
	users := map[string]bool{}
	for role, r := range p.Roles {
		if !id.MatchString(role) || !id.MatchString(r.User) || r.User == "root" || users[r.User] || validateRules(r.Rules) != nil {
			return Denied
		}
		users[r.User] = true
	}
	return nil
}
func (p Policy) Role(workspace, host, role, username string) (RolePolicy, error) {
	if p.Validate() != nil || p.Workspace != workspace || p.Host != host {
		return RolePolicy{}, Denied
	}
	r, ok := p.Roles[role]
	if !ok || r.User != username {
		return RolePolicy{}, Denied
	}
	return r, nil
}
func (a Authority) ForcedCommand(workspace, host, role, username string) (string, error) {
	if a.Validate() != nil || !id.MatchString(workspace) || !id.MatchString(host) || !id.MatchString(role) || !id.MatchString(username) || username == "root" {
		return "", Denied
	}
	s := a.Binary + " ssh gate --policy " + a.PolicyFile + " --workspace " + workspace + " --host " + host + " --role " + role + " --user " + username + " --rules-digest " + RulesDigest(a.Rules)
	if a.Fixture {
		s += " --dev-fixture"
	}
	return s, nil
}

// Parse accepts only literal words/single quotes plus the CLI's literal-quote escape.
// ponytail: bounded 2048-byte literal grammar, no shell library/evaluation or passthrough.
func unsafeText(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}
func Parse(s string) ([]string, error) {
	if len(s) == 0 || len(s) > 2048 || unsafeText(s) {
		return nil, Denied
	}
	out := []string{}
	i := 0
	for i < len(s) {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if i == len(s) {
			break
		}
		word := ""
		started := false
		for i < len(s) && s[i] != ' ' {
			started = true
			switch s[i] {
			case '\'':
				i++
				begin := i
				for i < len(s) && s[i] != '\'' {
					i++
				}
				if i == len(s) {
					return nil, Denied
				}
				word += s[begin:i]
				i++
			case '"':
				if i+2 >= len(s) || s[i:i+3] != "\"'\"" {
					return nil, Denied
				}
				word += "'"
				i += 3
			default:
				c := s[i]
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/_.,:@%+=-", rune(c))) {
					return nil, Denied
				}
				word += string(c)
				i++
			}
		}
		if !started || len(word) > 256 || len(out) >= 8 {
			return nil, Denied
		}
		out = append(out, word)
	}
	if len(out) == 0 {
		return nil, Denied
	}
	return out, nil
}
func Authorize(r RolePolicy, argv []string) ([]string, error) {
	if validateRules(r.Rules) != nil {
		return nil, Denied
	}
	for _, rule := range r.Rules {
		if reflect.DeepEqual(rule.Command, argv) {
			return append([]string{}, rule.Exec...), nil
		}
	}
	return nil, Denied
}

// Fixture relaxes only ownership for a synthetic nonprivileged dev-CA test.
// Never enable in production policy, principal files or server configuration.
func trustedOpen(path string, fixture bool) (*os.File, error) {
	if !cleanPath(path) {
		return nil, Denied
	}
	if !fixture {
		for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
			s, e := os.Lstat(dir)
			if e != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm()&0022 != 0 {
				return nil, Denied
			}
			stat, ok := s.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 {
				return nil, Denied
			}
			if dir == "/" {
				break
			}
		}
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, Denied
	}
	f := os.NewFile(uintptr(fd), path)
	s, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, Denied
	}
	stat, ok := s.Sys().(*syscall.Stat_t)
	expected := uint32(0)
	if fixture {
		expected = uint32(os.Getuid())
	}
	if !ok || !s.Mode().IsRegular() || s.Mode().Perm()&0022 != 0 || (stat.Uid != expected && !(fixture && stat.Uid == 0)) {
		f.Close()
		return nil, Denied
	}
	return f, nil
}
func Load(path string, fixture bool) (Policy, error) {
	var p Policy
	f, e := trustedOpen(path, fixture)
	if e != nil {
		return p, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(b) > 65536 {
		return p, Denied
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return p, Denied
	}
	var extra any
	if d.Decode(&extra) != io.EOF || p.Validate() != nil {
		return p, Denied
	}
	return p, nil
}
func RulesDigest(rules []Rule) string {
	b, _ := json.Marshal(rules)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func Run(policyPath, workspace, host, role, username, digest, original string, fixture bool) error {
	if os.Geteuid() == 0 && !fixture {
		return Denied
	}
	self, e := os.Executable()
	if e != nil {
		return Denied
	}
	selfFile, e := trustedOpen(self, fixture)
	if e != nil {
		return e
	}
	selfFile.Close()
	who, e := user.Current()
	if e != nil || who.Username != username || who.Uid != strconv.Itoa(os.Getuid()) {
		return Denied
	}
	p, e := Load(policyPath, fixture)
	if e != nil {
		return e
	}
	r, e := p.Role(workspace, host, role, who.Username)
	if e != nil || len(digest) != 64 || digest != RulesDigest(r.Rules) {
		return Denied
	}
	argv, e := Parse(original)
	if e != nil {
		return e
	}
	execArgv, e := Authorize(r, argv)
	if e != nil {
		return e
	}
	f, e := trustedOpen(execArgv[0], fixture)
	if e != nil {
		return e
	}
	s, statErr := f.Stat()
	f.Close()
	if statErr != nil || s.Mode().Perm()&0111 == 0 {
		return Denied
	}
	if os.Chdir("/") != nil {
		return Denied
	}
	return syscall.Exec(execArgv[0], execArgv, []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/"})
}
