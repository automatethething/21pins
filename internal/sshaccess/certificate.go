package sshaccess

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

// Verify native signer output before it crosses the control-plane boundary.
// No private-key parser or SSH implementation: only this fixed Ed25519 cert format.
func verifyCertificate(cert, caPublic string, r SignRequest) error {
	fields := strings.Fields(cert)
	if len(fields) < 2 || fields[0] != "ssh-ed25519-cert-v01@openssh.com" {
		return errors.New("invalid certificate")
	}
	b, e := base64.StdEncoding.DecodeString(fields[1])
	if e != nil || len(b) > 8192 {
		return errors.New("invalid certificate")
	}
	p := 0
	str := func() ([]byte, bool) {
		if p+4 > len(b) {
			return nil, false
		}
		n := int(binary.BigEndian.Uint32(b[p : p+4]))
		p += 4
		if n < 0 || n > len(b)-p {
			return nil, false
		}
		v := b[p : p+n]
		p += n
		return v, true
	}
	number := func(n int) (uint64, bool) {
		if p+n > len(b) {
			return 0, false
		}
		var v uint64
		if n == 8 {
			v = binary.BigEndian.Uint64(b[p : p+8])
		} else {
			v = uint64(binary.BigEndian.Uint32(b[p : p+4]))
		}
		p += n
		return v, true
	}
	kind, ok := str()
	if !ok || string(kind) != "ssh-ed25519-cert-v01@openssh.com" {
		return errors.New("invalid certificate kind")
	}
	if _, ok = str(); !ok {
		return errors.New("invalid nonce")
	}
	pub, ok := str()
	if !ok || len(pub) != 32 {
		return errors.New("invalid certificate key")
	}
	fp, e := PublicFingerprint(r.PublicKey)
	if e != nil {
		return e
	}
	wire := append([]byte{0, 0, 0, 11}, []byte("ssh-ed25519")...)
	wire = append(wire, 0, 0, 0, 32)
	wire = append(wire, pub...)
	sum := sha256.Sum256(wire)
	if fp != "SHA256:"+base64.RawStdEncoding.EncodeToString(sum[:]) {
		return errors.New("certificate key mismatch")
	}
	serial, ok := number(8)
	if !ok || serial != r.Serial {
		return errors.New("certificate serial mismatch")
	}
	typ, ok := number(4)
	if !ok || typ != 1 {
		return errors.New("not a user certificate")
	}
	id, ok := str()
	if !ok || string(id) != r.KeyID {
		return errors.New("certificate key ID mismatch")
	}
	principal, ok := str()
	if !ok || len(principal) != len(r.Principal)+4 || binary.BigEndian.Uint32(principal[:4]) != uint32(len(r.Principal)) || string(principal[4:]) != r.Principal {
		return errors.New("certificate principal mismatch")
	}
	after, ok := number(8)
	if !ok || after != uint64(r.ValidAfter.Unix()) {
		return errors.New("certificate validity mismatch")
	}
	before, ok := number(8)
	if !ok || before != uint64(r.ValidBefore.Unix()) {
		return errors.New("certificate expiry mismatch")
	}
	critical, ok := str()
	if !ok || len(critical) != 0 {
		return errors.New("unexpected critical options")
	}
	extensions, ok := str()
	if !ok {
		return errors.New("invalid extensions")
	}
	allowed := map[string]bool{}
	if r.PermitPTY {
		allowed["permit-pty"] = true
	}
	if r.PermitPortForwarding {
		allowed["permit-port-forwarding"] = true
	}
	if r.PermitAgentForwarding {
		allowed["permit-agent-forwarding"] = true
	}
	if r.PermitX11 {
		allowed["permit-X11-forwarding"] = true
	}
	for len(extensions) > 0 {
		if len(extensions) < 4 {
			return errors.New("invalid extension")
		}
		n := int(binary.BigEndian.Uint32(extensions[:4]))
		if n > len(extensions)-8 {
			return errors.New("invalid extension")
		}
		name := string(extensions[4 : 4+n])
		extensions = extensions[4+n:]
		size := int(binary.BigEndian.Uint32(extensions[:4]))
		if size != 0 || !allowed[name] {
			return errors.New("unexpected extension")
		}
		delete(allowed, name)
		extensions = extensions[4:]
	}
	if len(allowed) != 0 {
		return errors.New("missing certificate extension")
	}
	reserved, ok := str()
	if !ok || len(reserved) != 0 {
		return errors.New("unexpected reserved data")
	}
	ca, ok := str()
	if !ok {
		return errors.New("missing CA")
	}
	caFields := strings.Fields(caPublic)
	if len(caFields) != 2 {
		return errors.New("CA key invalid")
	}
	expected, e := base64.StdEncoding.DecodeString(caFields[1])
	if e != nil || !bytes.Equal(ca, expected) {
		return errors.New("CA mismatch")
	}
	signedEnd := p
	signature, ok := str()
	if !ok || p != len(b) || len(signature) != 4+11+4+64 || binary.BigEndian.Uint32(signature[:4]) != 11 || string(signature[4:15]) != "ssh-ed25519" || binary.BigEndian.Uint32(signature[15:19]) != 64 {
		return errors.New("invalid CA signature")
	}
	if len(ca) != 51 || !ed25519.Verify(ed25519.PublicKey(ca[19:]), b[:signedEnd], signature[19:]) {
		return errors.New("CA signature rejected")
	}
	return nil
}
