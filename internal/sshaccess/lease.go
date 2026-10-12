// Package sshaccess manages authorization, never the SSH data plane.
package sshaccess

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/petrichor/21pins-cli/internal/sshcommand"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode"
)

type Status string

const (
	PendingApproval Status = "PENDING_APPROVAL"
	Active          Status = "ACTIVE"
	Completed       Status = "COMPLETED"
	Cancelled       Status = "CANCELLED"
	Revoked         Status = "REVOKED"
	Expired         Status = "EXPIRED"
)

var ErrDenied = errors.New("SSH authorization denied")
var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

type Actor struct {
	ID         string
	Name       string
	CanApprove bool
}
type Role struct {
	SSHUser               string                `json:"ssh_user"`
	DefaultLease          string                `json:"default_lease"`
	MaxLease              string                `json:"max_lease"`
	MaxCertTTL            string                `json:"max_cert_ttl"`
	Requesters            map[string]string     `json:"requesters"` // exact app names: approval or preapproved
	RequesterMaxLease     map[string]string     `json:"requester_max_lease,omitempty"`
	ExplicitApproval      bool                  `json:"explicit_approval"`
	PermitPTY             bool                  `json:"permit_pty"`
	PermitPortForwarding  bool                  `json:"permit_port_forwarding"`
	PermitAgentForwarding bool                  `json:"permit_agent_forwarding"`
	PermitX11             bool                  `json:"permit_x11"`
	CommandAuthority      *sshcommand.Authority `json:"command_authority,omitempty"`
}
type Host struct {
	Alias     string          `json:"ssh_alias"`
	JumpAlias string          `json:"ssh_jump_alias,omitempty"`
	Roles     map[string]Role `json:"roles"`
}
type CA struct {
	Mode          string `json:"mode"`
	PublicKeyFile string `json:"public_key_file"`
	SecretRef     string `json:"private_key_secret_ref,omitempty"`
	AgentSocket   string `json:"agent_socket,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
}
type Config struct {
	Workspace   string          `json:"workspace_id"`
	CA          CA              `json:"ca"`
	CertTTL     string          `json:"cert_ttl"`
	RenewBefore string          `json:"renew_before"`
	ClockSkew   string          `json:"clock_skew"`
	Hosts       map[string]Host `json:"hosts"`
}
type OpenRequest struct {
	HostID            string `json:"host_id"`
	RoleID            string `json:"role_id"`
	AgentClass        string `json:"agent_class"`
	ObjectiveID       string `json:"objective_id"`
	Purpose           string `json:"purpose"`
	EstimatedDuration string `json:"estimated_duration,omitempty"`
	MaxDuration       string `json:"max_duration,omitempty"`
	PublicKey         string `json:"public_key"`
}
type Lease struct {
	ID                   string     `json:"lease_id"`
	Workspace            string     `json:"workspace_id"`
	RequesterID          string     `json:"requester_id"`
	Requester            string     `json:"requester"`
	AgentClass           string     `json:"agent_class"`
	HostID               string     `json:"host_id"`
	RoleID               string     `json:"role_id"`
	SSHUser              string     `json:"ssh_user"`
	SSHAlias             string     `json:"ssh_alias"`
	SSHJumpAlias         string     `json:"ssh_jump_alias,omitempty"`
	RenewBefore          string     `json:"renew_before"`
	ObjectiveID          string     `json:"objective_id"`
	Purpose              string     `json:"purpose"`
	PublicKeyFingerprint string     `json:"public_key_fingerprint"`
	Principal            string     `json:"principal"`
	EstimatedDuration    string     `json:"estimated_duration,omitempty"`
	PolicyDigest         string     `json:"policy_digest"`
	OpenedAt             time.Time  `json:"opened_at"`
	HardExpiresAt        time.Time  `json:"hard_expires_at"`
	ClosedAt             *time.Time `json:"closed_at,omitempty"`
	Status               Status     `json:"state"`
	TerminationReason    string     `json:"termination_reason,omitempty"`
	ApprovedBy           string     `json:"approved_by,omitempty"`
	EffectivePolicy      Role       `json:"effective_policy"`
}
type Issuance struct {
	LeaseID     string    `json:"lease_id"`
	Serial      uint64    `json:"serial"`
	Fingerprint string    `json:"certificate_fingerprint"`
	ValidAfter  time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
	IssuedAt    time.Time `json:"issued_at"`
}
type IssueResult struct {
	Lease       Lease    `json:"lease"`
	Certificate string   `json:"certificate"`
	Issuance    Issuance `json:"issuance"`
}
type SignRequest struct {
	PublicKey                                                         string
	LeaseID                                                           string
	Serial                                                            uint64
	Principal                                                         string
	KeyID                                                             string
	ValidAfter, ValidBefore                                           time.Time
	ForceCommand                                                      string
	PermitPTY, PermitPortForwarding, PermitAgentForwarding, PermitX11 bool
}
type Signer interface {
	Sign(SignRequest) (string, error)
}
type diskState struct {
	NextSerial uint64           `json:"next_serial"`
	Leases     map[string]Lease `json:"leases"`
	Issuances  []Issuance       `json:"issuances"`
}
type Service struct {
	Dir        string
	Config     Config
	Signer     Signer
	Now        func() time.Time
	Authorize  func(Actor) bool
	liveConfig bool
}

func New(dir string, c Config, signer Signer) (*Service, error) {
	if err := validateConfig(c); err != nil {
		return nil, err
	}
	if err := PrivateDir(dir); err != nil {
		return nil, err
	}
	return &Service{Dir: dir, Config: c, Signer: signer, Now: func() time.Time { return time.Now().UTC().Truncate(time.Second) }}, nil
}
func Load(dir string) (*Service, error) {
	b, e := ReadPrivate(filepath.Join(dir, "config.json"))
	if e != nil {
		return nil, errors.New("SSH configuration unavailable")
	}
	var c Config
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return nil, errors.New("invalid SSH configuration")
	}
	if c.CA.PublicKeyFile != "" {
		public, err := os.ReadFile(c.CA.PublicKeyFile)
		if err != nil {
			return nil, errors.New("SSH CA public reference unavailable")
		}
		canonical, err := CAPublic(string(public))
		if err != nil {
			return nil, err
		}
		fingerprint, err := PublicFingerprint(canonical)
		if err != nil {
			return nil, err
		}
		if c.CA.Fingerprint != "" && c.CA.Fingerprint != fingerprint {
			return nil, errors.New("SSH CA changed; explicit rotation required")
		}
		c.CA.Fingerprint = fingerprint
	}
	service, err := New(dir, c, NativeSigner{CA: c.CA})
	if err == nil {
		service.liveConfig = true
	}
	return service, err
}
func duration(v string) (time.Duration, error) {
	d, e := time.ParseDuration(v)
	if e != nil || d <= 0 || d > 30*24*time.Hour {
		return 0, errors.New("invalid bounded duration")
	}
	return d, nil
}
func validateConfig(c Config) error {
	if !identifier.MatchString(c.Workspace) {
		return errors.New("invalid workspace")
	}
	ttl, e := duration(c.CertTTL)
	if e != nil {
		return e
	}
	renew, e := duration(c.RenewBefore)
	if e != nil || renew >= ttl {
		return errors.New("invalid renewal threshold")
	}
	skew, e := time.ParseDuration(c.ClockSkew)
	if e != nil || skew < 0 || skew > 2*time.Minute {
		return errors.New("invalid clock skew")
	}
	for h, v := range c.Hosts {
		if !identifier.MatchString(h) || !identifier.MatchString(v.Alias) || (v.JumpAlias != "" && !identifier.MatchString(v.JumpAlias)) {
			return errors.New("logical host/alias required")
		}
		users := map[string]bool{}
		gatePolicy := ""
		gateBinary := ""
		for name, r := range v.Roles {
			if c.CA.Mode == "agent" && r.CommandAuthority == nil {
				return errors.New("production role requires command authority")
			}
			if r.CommandAuthority != nil {
				if gatePolicy != "" && (gatePolicy != r.CommandAuthority.PolicyFile || gateBinary != r.CommandAuthority.Binary) {
					return errors.New("one host command policy and gate binary required")
				}
				gatePolicy = r.CommandAuthority.PolicyFile
				gateBinary = r.CommandAuthority.Binary
				if r.CommandAuthority.Validate() != nil || r.SSHUser == "root" || users[r.SSHUser] || r.PermitPTY || r.PermitPortForwarding || r.PermitAgentForwarding || r.PermitX11 || (r.CommandAuthority.Fixture && c.CA.Mode != "dev") {
					return errors.New("invalid gated role")
				}
				users[r.SSHUser] = true
			}
			if !identifier.MatchString(name) || !identifier.MatchString(r.SSHUser) {
				return errors.New("invalid role/login")
			}
			max, e := duration(r.MaxLease)
			if e != nil {
				return e
			}
			def, e := duration(r.DefaultLease)
			if e != nil || def > max {
				return errors.New("invalid default lease")
			}
			cap, e := duration(r.MaxCertTTL)
			if e != nil || cap > max {
				return errors.New("invalid role certificate ceiling")
			}
			for user, v := range r.RequesterMaxLease {
				d, e := duration(v)
				if e != nil || d > max || r.Requesters[user] == "" {
					return errors.New("invalid requester lease ceiling")
				}
			}
			for user, mode := range r.Requesters {
				if !identifier.MatchString(user) || (mode != "approval" && mode != "preapproved") {
					return errors.New("invalid requester policy")
				}
				if r.SSHUser == "root" && !r.ExplicitApproval {
					return errors.New("root requires explicit approval")
				}
			}
		}
	}
	return nil
}

// CAPublic strips non-authoritative comments before public trust distribution.
func CAPublic(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) > 4096 || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("single CA public key required")
	}
	parts := strings.Fields(value)
	if len(parts) < 2 {
		return "", errors.New("CA public key required")
	}
	canonical := strings.Join(parts[:2], " ")
	if _, e := PublicFingerprint(canonical); e != nil {
		return "", e
	}
	return canonical, nil
}

func PublicFingerprint(pub string) (string, error) {
	if len(pub) > 256 || strings.ContainsAny(pub, "\r\n") || strings.Contains(pub, "PRIVATE") {
		return "", errors.New("only a single Ed25519 public key is accepted")
	}
	f := strings.Fields(pub)
	if len(f) != 2 || f[0] != "ssh-ed25519" {
		return "", errors.New("raw Ed25519 public key required (no options/comments)")
	}
	b, e := base64.StdEncoding.DecodeString(f[1])
	if e != nil || len(b) != 51 || binary.BigEndian.Uint32(b[:4]) != 11 || string(b[4:15]) != "ssh-ed25519" || binary.BigEndian.Uint32(b[15:19]) != 32 {
		return "", errors.New("invalid Ed25519 public key")
	}
	h := sha256.Sum256(b)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:]), nil
}
func scopeDigest(c Config, host, role string) string {
	h := c.Hosts[host]
	r := h.Roles[role]
	b, _ := json.Marshal(struct {
		Workspace, Host, Role, Alias string
		Jump                         string `json:",omitempty"`
		Policy                       Role
		CA                           CA
		TTL, Skew                    string
	}{c.Workspace, host, role, h.Alias, h.JumpAlias, r, c.CA, c.CertTTL, c.ClockSkew})
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func randomID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic("random source unavailable")
	}
	return hex.EncodeToString(b)
}
func (s *Service) role(a Actor, h, r string) (Role, error) {
	host, ok := s.Config.Hosts[h]
	if !ok {
		return Role{}, ErrDenied
	}
	role, ok := host.Roles[r]
	if !ok || a.ID == "" || role.Requesters[a.Name] == "" {
		return Role{}, ErrDenied
	}
	if limit := role.RequesterMaxLease[a.Name]; limit != "" {
		ceiling, e := duration(limit)
		if e != nil {
			return Role{}, ErrDenied
		}
		role.MaxLease = limit
		def, e := duration(role.DefaultLease)
		if e != nil {
			return Role{}, ErrDenied
		}
		if def > ceiling {
			role.DefaultLease = limit
		}
		cert, e := duration(role.MaxCertTTL)
		if e != nil {
			return Role{}, ErrDenied
		}
		if cert > ceiling {
			role.MaxCertTTL = limit
		}
	}
	return role, nil
}
func (s *Service) Open(a Actor, q OpenRequest) (Lease, error) {
	var result Lease
	fp, e := PublicFingerprint(q.PublicKey)
	if e != nil {
		return result, e
	}
	if !identifier.MatchString(q.AgentClass) || !identifier.MatchString(q.ObjectiveID) || len(q.Purpose) < 1 || len(q.Purpose) > 256 || strings.ContainsFunc(q.Purpose, func(r rune) bool { return unicode.IsControl(r) || unicode.In(r, unicode.Cf) }) {
		return result, errors.New("bounded objective/purpose required")
	}
	r, e := s.role(a, q.HostID, q.RoleID)
	if e != nil {
		return result, e
	}
	max, _ := duration(r.MaxLease)
	window, _ := duration(r.DefaultLease)
	if q.MaxDuration != "" {
		window, e = duration(q.MaxDuration)
		if e != nil || window > max {
			return result, ErrDenied
		}
	}
	if q.EstimatedDuration != "" {
		if _, e = duration(q.EstimatedDuration); e != nil {
			return result, e
		}
	}
	e = s.transaction(func(d *diskState) error {
		now := s.Now()
		for _, existing := range d.Leases {
			if existing.PublicKeyFingerprint == fp {
				if existing.RequesterID == a.ID && existing.HostID == q.HostID && existing.RoleID == q.RoleID && existing.ObjectiveID == q.ObjectiveID && existing.Purpose == q.Purpose && existing.AgentClass == q.AgentClass && existing.PolicyDigest == scopeDigest(s.Config, q.HostID, q.RoleID) && (existing.Status == Active || existing.Status == PendingApproval) && now.Before(existing.HardExpiresAt) {
					result = existing
					return nil
				}
				return ErrDenied
			}
		}
		state := PendingApproval
		if r.Requesters[a.Name] == "preapproved" && !r.ExplicitApproval {
			state = Active
		}
		renewWindow, _ := duration(s.Config.RenewBefore)
		certificateTTL, _ := duration(s.Config.CertTTL)
		if capTTL, e := duration(r.MaxCertTTL); e == nil && capTTL < certificateTTL {
			certificateTTL = capTTL
		}
		if renewWindow >= certificateTTL {
			renewWindow = certificateTTL / 3
		}
		result = Lease{ID: randomID(), Workspace: s.Config.Workspace, RequesterID: a.ID, Requester: a.Name, AgentClass: q.AgentClass, HostID: q.HostID, RoleID: q.RoleID, SSHUser: r.SSHUser, SSHAlias: s.Config.Hosts[q.HostID].Alias, SSHJumpAlias: s.Config.Hosts[q.HostID].JumpAlias, RenewBefore: renewWindow.String(), ObjectiveID: q.ObjectiveID, Purpose: q.Purpose, PublicKeyFingerprint: fp, Principal: "21pins:" + s.Config.Workspace + ":" + q.HostID + ":" + q.RoleID, EstimatedDuration: q.EstimatedDuration, PolicyDigest: scopeDigest(s.Config, q.HostID, q.RoleID), OpenedAt: now, HardExpiresAt: now.Add(window), Status: state, EffectivePolicy: r}
		d.Leases[result.ID] = result
		return nil
	})
	return result, e
}
func expire(l Lease, now time.Time) Lease {
	if (l.Status == Active || l.Status == PendingApproval) && !now.Before(l.HardExpiresAt) {
		l.Status = Expired
		l.ClosedAt = &now
		l.TerminationReason = "authorization_window_expired"
	}
	return l
}
func (s *Service) Get(a Actor, id string) (Lease, error) {
	var out Lease
	e := s.transaction(func(d *diskState) error {
		l, ok := d.Leases[id]
		if !ok || (l.RequesterID != a.ID && !a.CanApprove) {
			return ErrDenied
		}
		l = expire(l, s.Now())
		d.Leases[id] = l
		out = l
		return nil
	})
	return out, e
}
func (s *Service) List(a Actor, objective string) ([]Lease, error) {
	var out []Lease
	e := s.transaction(func(d *diskState) error {
		for id, l := range d.Leases {
			if (l.RequesterID == a.ID || a.CanApprove) && (objective == "" || objective == l.ObjectiveID) {
				l = expire(l, s.Now())
				d.Leases[id] = l
				out = append(out, l)
			}
		}
		return nil
	})
	return out, e
}
func (s *Service) Approve(a Actor, id string) (Lease, error) {
	var out Lease
	e := s.transaction(func(d *diskState) error {
		l, ok := d.Leases[id]
		if !ok || !a.CanApprove || a.ID == l.RequesterID || (s.Authorize != nil && !s.Authorize(a)) {
			return ErrDenied
		}
		l = expire(l, s.Now())
		if l.Status != PendingApproval {
			return ErrDenied
		}
		if l.PolicyDigest != scopeDigest(s.Config, l.HostID, l.RoleID) {
			return ErrDenied
		}
		l.Status = Active
		l.ApprovedBy = a.ID
		d.Leases[id] = l
		out = l
		return nil
	})
	return out, e
}
func (s *Service) Close(a Actor, id string, state Status, reason string) (Lease, error) {
	var out Lease
	if state != Completed && state != Cancelled && state != Revoked {
		return out, ErrDenied
	}
	if state == Revoked && !a.CanApprove {
		return out, ErrDenied
	}
	if reason != "complete" && reason != "cancelled" && reason != "revoked" && reason != "blocked" && reason != "shutdown" && reason != "lost_client" {
		return out, errors.New("invalid termination reason")
	}
	e := s.transaction(func(d *diskState) error {
		l, ok := d.Leases[id]
		if !ok || (l.RequesterID != a.ID && !a.CanApprove) {
			return ErrDenied
		}
		l = expire(l, s.Now())
		if l.Status == Active || l.Status == PendingApproval {
			now := s.Now()
			l.Status = state
			l.ClosedAt = &now
			l.TerminationReason = reason
		}
		d.Leases[id] = l
		out = l
		return nil
	})
	return out, e
}
func (s *Service) Issue(a Actor, id, pub string) (IssueResult, error) {
	var out IssueResult
	fp, e := PublicFingerprint(pub)
	if e != nil {
		return out, e
	}
	e = s.transaction(func(d *diskState) error {
		l, ok := d.Leases[id]
		if !ok || l.RequesterID != a.ID {
			return ErrDenied
		}
		now := s.Now()
		l = expire(l, now)
		d.Leases[id] = l
		if l.Status != Active || l.PublicKeyFingerprint != fp {
			return ErrDenied
		}
		current := s.Config
		if s.liveConfig {
			fresh, err := Load(s.Dir)
			if err != nil {
				return ErrDenied
			}
			current = fresh.Config
		}
		checker := *s
		checker.Config = current
		r, e := checker.role(a, l.HostID, l.RoleID)
		if (s.Authorize != nil && !s.Authorize(a)) || e != nil || l.PolicyDigest != scopeDigest(current, l.HostID, l.RoleID) {
			return ErrDenied
		}
		ttl, _ := duration(s.Config.CertTTL)
		cap, _ := duration(r.MaxCertTTL)
		if cap < ttl {
			ttl = cap
		}
		before := now.Add(ttl).Truncate(time.Second)
		if l.HardExpiresAt.Before(before) {
			before = l.HardExpiresAt.Truncate(time.Second)
		}
		if !before.After(now) {
			return ErrDenied
		}
		skew, _ := time.ParseDuration(s.Config.ClockSkew)
		if d.NextSerial == ^uint64(0) {
			return errors.New("certificate serial exhausted")
		}
		d.NextSerial++
		serial := d.NextSerial
		// Reserve before signing; a failed signer/save consumes a serial, never reuses it.
		if e := s.save(d); e != nil {
			return e
		}
		if s.Signer == nil {
			return errors.New("SSH signer unavailable")
		}
		force := ""
		if r.CommandAuthority != nil {
			force, e = r.CommandAuthority.ForcedCommand(l.Workspace, l.HostID, l.RoleID, l.SSHUser)
			if e != nil {
				return ErrDenied
			}
		}
		cert, e := s.Signer.Sign(SignRequest{PublicKey: pub, LeaseID: id, Serial: serial, Principal: l.Principal, KeyID: "21pins:" + id + ":" + l.AgentClass + ":" + l.ObjectiveID, ValidAfter: now.Add(-skew), ValidBefore: before, PermitPTY: r.PermitPTY, PermitPortForwarding: r.PermitPortForwarding, PermitAgentForwarding: r.PermitAgentForwarding, PermitX11: r.PermitX11, ForceCommand: force})
		if e != nil {
			return errors.New("SSH certificate signing failed")
		}
		final := s.Config
		if s.liveConfig {
			fresh, err := Load(s.Dir)
			if err != nil {
				return ErrDenied
			}
			final = fresh.Config
		}
		if !s.Now().Before(before) || (s.Authorize != nil && !s.Authorize(a)) || l.PolicyDigest != scopeDigest(final, l.HostID, l.RoleID) {
			return ErrDenied
		}
		h := sha256.Sum256([]byte(cert))
		i := Issuance{LeaseID: id, Serial: serial, Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:]), ValidAfter: now.Add(-skew), ValidBefore: before, IssuedAt: now}
		d.Issuances = append(d.Issuances, i)
		out = IssueResult{Lease: l, Certificate: cert, Issuance: i}
		return nil
	})
	return out, e
}
func (s *Service) transaction(fn func(*diskState) error) error {
	if err := PrivateDir(s.Dir); err != nil {
		return err
	}
	lock, e := privateOpen(filepath.Join(s.Dir, "leases.lock"), os.O_CREATE|os.O_RDWR)
	if e != nil {
		return e
	}
	defer lock.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			break
		}
		if e != syscall.EWOULDBLOCK || time.Now().After(deadline) {
			return errors.New("SSH state writer unavailable")
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	d := diskState{Leases: map[string]Lease{}}
	p := filepath.Join(s.Dir, "leases.json")
	b, e := ReadPrivate(p)
	if e == nil {
		if json.Unmarshal(b, &d) != nil || d.Leases == nil {
			return errors.New("SSH lease state invalid")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = fn(&d); e != nil {
		return e
	}
	return s.save(&d)
}
func (s *Service) save(d *diskState) error {
	b, e := json.MarshalIndent(d, "", "  ")
	if e != nil {
		return e
	}
	if len(b) > 16<<20 {
		return errors.New("SSH metadata capacity reached")
	}
	return AtomicPrivate(filepath.Join(s.Dir, "leases.json"), b)
}
func PrivateDir(dir string) error {
	info, e := os.Lstat(dir)
	if errors.Is(e, os.ErrNotExist) {
		if e = os.MkdirAll(dir, 0700); e != nil {
			return e
		}
		info, e = os.Lstat(dir)
	}
	if e != nil {
		return e
	}
	owner, owned := info.Sys().(*syscall.Stat_t)
	if !owned || owner.Uid != uint32(os.Getuid()) || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("private directory required (0700, no symlink)")
	}
	return nil
}
func privateOpen(p string, flags int) (*os.File, error) {
	fd, e := syscall.Open(p, flags|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), p)
	i, e := f.Stat()
	owned := false
	if e == nil {
		if owner, ok := i.Sys().(*syscall.Stat_t); ok {
			owned = owner.Uid == uint32(os.Getuid())
		}
	}
	if e != nil || !owned || !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, errors.New("private regular file required")
	}
	return f, nil
}
func CheckPrivate(p string) error {
	f, e := privateOpen(p, os.O_RDONLY)
	if e != nil {
		return e
	}
	return f.Close()
}

func ReadPrivate(p string) ([]byte, error) {
	f, e := privateOpen(p, os.O_RDONLY)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil || i.Size() > 16<<20 {
		return nil, errors.New("private file too large")
	}
	return io.ReadAll(io.LimitReader(f, 16<<20))
}
func AtomicPrivate(p string, b []byte) error {
	if i, e := os.Lstat(p); e == nil {
		if !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 {
			return errors.New("nonregular state file")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(p), ".ssh-state-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(name, p)
}
