package netpolicy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

type dnsResult struct {
	valid, filter bool
	rcode         uint16
}

func dnsQuery(domain string) ([]byte, uint16, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if len(domain) > 253 || len(domain) == 0 {
		return nil, 0, ErrInvalid
	}
	var random [2]byte
	if _, e := rand.Read(random[:]); e != nil {
		return nil, 0, ErrUnsupported
	}
	id := binary.BigEndian.Uint16(random[:])
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q, id)
	binary.BigEndian.PutUint16(q[2:4], 0x100)
	binary.BigEndian.PutUint16(q[4:6], 1)
	binary.BigEndian.PutUint16(q[10:12], 1)
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, 0, ErrInvalid
		}
		for _, v := range []byte(label) {
			if (v < 'a' || v > 'z') && (v < '0' || v > '9') && v != '-' {
				return nil, 0, ErrInvalid
			}
		}
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	q = append(q, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0)
	return q, id, nil
}
func dnsName(data []byte, off int) (string, int, error) {
	var labels []string
	end := -1
	seen := map[int]bool{}
	for count := 0; count < 128; count++ {
		if off < 0 || off >= len(data) || seen[off] {
			return "", 0, ErrInvalid
		}
		seen[off] = true
		n := int(data[off])
		if n&192 == 192 {
			if off+1 >= len(data) {
				return "", 0, ErrInvalid
			}
			if end < 0 {
				end = off + 2
			}
			off = (n&63)<<8 | int(data[off+1])
			continue
		}
		if n&192 != 0 || off+1+n > len(data) {
			return "", 0, ErrInvalid
		}
		off++
		if n == 0 {
			if end < 0 {
				end = off
			}
			name := strings.ToLower(strings.Join(labels, "."))
			if len(name) > 253 {
				return "", 0, ErrInvalid
			}
			return name, end, nil
		}
		for _, v := range data[off : off+n] {
			if v < 33 || v > 126 {
				return "", 0, ErrInvalid
			}
		}
		labels = append(labels, string(data[off:off+n]))
		off += n
	}
	return "", 0, ErrInvalid
}
func parseDNS(data []byte, id uint16, domain string) (dnsResult, error) {
	bad := dnsResult{}
	if len(data) < 12 || binary.BigEndian.Uint16(data[:2]) != id {
		return bad, ErrInvalid
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	qd := binary.BigEndian.Uint16(data[4:6])
	an := int(binary.BigEndian.Uint16(data[6:8]))
	ns := int(binary.BigEndian.Uint16(data[8:10]))
	ar := int(binary.BigEndian.Uint16(data[10:12]))
	if flags&0x8000 == 0 || flags&0x7a40 != 0 || qd != 1 || an+ns+ar > 128 {
		return bad, ErrInvalid
	}
	name, off, e := dnsName(data, 12)
	if e != nil || name != strings.ToLower(domain) || off+4 > len(data) || binary.BigEndian.Uint16(data[off:off+2]) != 1 || binary.BigEndian.Uint16(data[off+2:off+4]) != 1 {
		return bad, ErrInvalid
	}
	off += 4
	opt := false
	filtered := false
	for i := 0; i < an+ns+ar; i++ {
		rrname, next, e := dnsName(data, off)
		if e != nil || next+10 > len(data) {
			return bad, ErrInvalid
		}
		off = next
		typ := binary.BigEndian.Uint16(data[off : off+2])
		ttl := binary.BigEndian.Uint32(data[off+4 : off+8])
		length := int(binary.BigEndian.Uint16(data[off+8 : off+10]))
		off += 10
		end := off + length
		if end > len(data) {
			return bad, ErrInvalid
		}
		if typ == 41 {
			if opt || rrname != "" || i < an+ns || ttl>>16 != 0 {
				return bad, ErrInvalid
			}
			opt = true
			for pos := off; pos < end; {
				if pos+4 > end {
					return bad, ErrInvalid
				}
				code := binary.BigEndian.Uint16(data[pos : pos+2])
				n := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
				pos += 4
				if pos+n > end {
					return bad, ErrInvalid
				}
				if code == 15 && n >= 2 {
					ede := binary.BigEndian.Uint16(data[pos : pos+2])
					filtered = filtered || ede == 15 || ede == 17
				}
				pos += n
			}
		}
		off = end
	}
	if off != len(data) {
		return bad, ErrInvalid
	}
	return dnsResult{valid: true, filter: filtered, rcode: flags & 15}, nil
}

type probeResult struct {
	responded, silent, filtered, usable bool
	start, end                          time.Time
}

func probeDNS(ctx context.Context, source Binding, service Binding, transport, domain string) (probeResult, error) {
	result := probeResult{start: time.Now().UTC()}
	q, id, e := dnsQuery(domain)
	if e != nil {
		return result, e
	}
	e = withinNamespace(ctx, source, func() error {
		address, e := netip.ParseAddr(source.Address)
		if e != nil {
			return ErrMissing
		}
		destination, e := netip.ParseAddr(service.Target)
		if e != nil || address.Is4() != destination.Is4() {
			return ErrUnsupported
		}
		dialer := net.Dialer{Timeout: 700 * time.Millisecond}
		if transport == "udp" {
			dialer.LocalAddr = &net.UDPAddr{IP: net.IP(address.AsSlice())}
		} else if transport == "tcp" {
			dialer.LocalAddr = &net.TCPAddr{IP: net.IP(address.AsSlice())}
		} else {
			return ErrUnsupported
		}
		connection, e := dialer.DialContext(ctx, transport, netip.AddrPortFrom(destination, service.Port).String())
		if e != nil {
			if ctx.Err() != nil {
				return ErrUnsupported
			}
			result.silent = true
			return nil
		}
		defer connection.Close()
		deadline := time.Now().Add(700 * time.Millisecond)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		connection.SetDeadline(deadline)
		message := q
		if transport == "tcp" {
			message = make([]byte, len(q)+2)
			binary.BigEndian.PutUint16(message, uint16(len(q)))
			copy(message[2:], q)
		}
		if _, e = connection.Write(message); e != nil {
			result.silent = true
			return nil
		}
		var data []byte
		if transport == "tcp" {
			var size [2]byte
			if _, e = io.ReadFull(connection, size[:]); e == nil {
				n := int(binary.BigEndian.Uint16(size[:]))
				if n < 12 || n > 4096 {
					return ErrInvalid
				}
				data = make([]byte, n)
				_, e = io.ReadFull(connection, data)
			}
		} else {
			data = make([]byte, 4096)
			var n int
			n, e = connection.Read(data)
			data = data[:n]
		}
		if e != nil {
			if ctx.Err() != nil {
				return ErrUnsupported
			}
			result.silent = true
			return nil
		}
		response, e := parseDNS(data, id, domain)
		if e != nil {
			return e
		}
		result.responded = response.valid
		result.filtered = response.filter && (response.rcode == 0 || response.rcode == 3)
		result.usable = response.rcode == 0 || response.rcode == 3
		return nil
	})
	result.end = time.Now().UTC()
	return result, e
}
func challenge() string {
	var data [12]byte
	if _, e := rand.Read(data[:]); e != nil {
		return ""
	}
	return "pins-" + hex.EncodeToString(data[:]) + ".invalid"
}
