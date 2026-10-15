//go:build linux

package netpolicy

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestKernelChallengeFilter(t *testing.T) {
	src, dst := netip.MustParseAddr(fixtureIP(2)).As4(), netip.MustParseAddr(fixtureIP(53)).As4()
	nonce := "pins-test.invalid"
	filter, e := scopedPacketFilter(src, dst, 53, nonce)
	if e != nil {
		t.Fatal(e)
	}
	evaluate := func(packet []byte) uint32 {
		var a, x uint32
		for pc := 0; pc < len(filter); pc++ {
			f := filter[pc]
			at := int(f.K)
			switch f.Code {
			case 0x30:
				if at >= len(packet) {
					return 0
				}
				a = uint32(packet[at])
			case 0x54:
				a &= f.K
			case 0x74:
				a >>= f.K
			case 0x0c:
				a += x
			case 0x1c:
				a -= x
			case 0x07:
				x = a
			case 0x15:
				if a == f.K {
					pc += int(f.Jt)
				} else {
					pc += int(f.Jf)
				}
			case 0x35:
				if a >= f.K {
					pc += int(f.Jt)
				} else {
					pc += int(f.Jf)
				}
			case 0x3d:
				if a >= x {
					pc += int(f.Jt)
				} else {
					pc += int(f.Jf)
				}
			case 0x20:
				if at+4 > len(packet) {
					return 0
				}
				a = binary.BigEndian.Uint32(packet[at:])
			case 0x28:
				if at+2 > len(packet) {
					return 0
				}
				a = uint32(binary.BigEndian.Uint16(packet[at:]))
			case 0x45:
				if a&f.K != 0 {
					pc += int(f.Jt)
				} else {
					pc += int(f.Jf)
				}
			case 0xb1:
				if at >= len(packet) {
					return 0
				}
				x = uint32(packet[at]&15) * 4
			case 0x40:
				at += int(x)
				if at+4 > len(packet) {
					return 0
				}
				a = binary.BigEndian.Uint32(packet[at:])
			case 0x48:
				at += int(x)
				if at+2 > len(packet) {
					return 0
				}
				a = uint32(binary.BigEndian.Uint16(packet[at:]))
			case 0x50:
				at += int(x)
				if at >= len(packet) {
					return 0
				}
				a = uint32(packet[at])
			case 0x06:
				return f.K
			default:
				t.Fatal("unhandled real filter instruction")
			}
		}
		return 0
	}
	query, _, _ := dnsQuery(nonce)
	packet := make([]byte, 28+len(query))
	packet[0] = 0x45
	packet[9] = 17
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[22:24], 53)
	copy(packet[28:], query)
	if evaluate(packet) != 4096 {
		t.Fatal("registered UDP challenge excluded")
	}
	packet[43] ^= 1
	if evaluate(packet) != 0 {
		t.Fatal("unrelated DNS name captured")
	}
	packet[43] ^= 1
	binary.BigEndian.PutUint16(packet[22:24], 5353)
	if evaluate(packet) != 0 {
		t.Fatal("unrelated port captured")
	}
	binary.BigEndian.PutUint16(packet[6:8], 0x2000)
	if evaluate(packet) != 1 {
		t.Fatal("fragment payload captured or coverage silently hidden")
	}
	if _, matched, complete := packetChallenge(packet[:1], nonce); matched || complete {
		t.Fatal("fragment prelude became complete absence evidence")
	}
	binary.BigEndian.PutUint16(packet[6:8], 0)
	packet[0] = 0x65
	if evaluate(packet) != 0 {
		t.Fatal("unsupported family admitted")
	}
	packet[0] = 0x45
	packet[12] ^= 1
	if evaluate(packet) != 0 {
		t.Fatal("unrelated source captured")
	}
	tcp := make([]byte, 42+len(query))
	tcp[0] = 0x45
	tcp[9] = 6
	copy(tcp[12:16], src[:])
	copy(tcp[16:20], dst[:])
	binary.BigEndian.PutUint16(tcp[2:4], uint16(len(tcp)))
	binary.BigEndian.PutUint16(tcp[22:24], 53)
	tcp[32] = 0x50
	binary.BigEndian.PutUint16(tcp[40:42], uint16(len(query)))
	copy(tcp[42:], query)
	if evaluate(tcp) != 4096 {
		t.Fatal("registered TCP challenge excluded")
	}
	tcp[57] ^= 1
	if evaluate(tcp) != 0 {
		t.Fatal("unrelated TCP DNS name captured")
	}
	tcp[57] ^= 1
	binary.BigEndian.PutUint16(tcp[2:4], 45)
	if evaluate(tcp) != 1 {
		t.Fatal("split TCP query silently hidden")
	}
	binary.BigEndian.PutUint16(tcp[2:4], 40)
	if evaluate(tcp) != 0 {
		t.Fatal("empty TCP metadata unnecessarily collected")
	}
}
