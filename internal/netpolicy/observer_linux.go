//go:build linux

package netpolicy

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type packetMonitor struct {
	cancel context.CancelFunc
	done   chan observation
	once   sync.Once
	result observation
}

func (m *packetMonitor) stop() observation {
	m.once.Do(func() {
		m.cancel()
		select {
		case m.result = <-m.done:
		case <-time.After(time.Second):
			m.result.Complete = false
		}
	})
	return m.result
}
func interfaceIndex(name string) (int, error) {
	if !nativePattern.MatchString(name) || len(name) > 15 {
		return 0, ErrInvalid
	}
	fd, e := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if e != nil {
		return 0, ErrUnsupported
	}
	defer syscall.Close(fd)
	var req struct {
		Name    [16]byte
		Index   int32
		Padding [20]byte
	}
	copy(req.Name[:], name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.SIOCGIFINDEX), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return 0, ErrUnsupported
	}
	return int(req.Index), nil
}
func scopedPacketFilter(src, dst [4]byte, port uint16, nonce string) ([]syscall.SockFilter, error) {
	query, _, e := dnsQuery(nonce)
	if e != nil {
		return nil, e
	}
	question := query[12 : len(query)-11]
	if len(question) > 96 {
		return nil, ErrUnsupported
	}
	f := []syscall.SockFilter{
		{Code: 0x30, K: 0}, {Code: 0x54, K: 0xf0}, {Code: 0x15, K: 0x40},
		{Code: 0x20, K: 12}, {Code: 0x15, K: binary.BigEndian.Uint32(src[:])},
		{Code: 0x20, K: 16}, {Code: 0x15, K: binary.BigEndian.Uint32(dst[:])},
		{Code: 0x30, K: 9}, {Code: 0x15, Jt: 1, K: 17}, {Code: 0x15, K: 6},
		{Code: 0x28, K: 6}, {Code: 0x45, K: 0x3fff},
		{Code: 0xb1, K: 0}, {Code: 0x48, K: 2}, {Code: 0x15, K: uint32(port)},
		{Code: 0x30, K: 9}, {Code: 0x15, K: 17},
	}
	dropFalse := []int{2, 4, 6, 9, 14}
	dropTrue := []int{}
	metaTrue := []int{11}
	metaFalse := []int{}
	emit := func(code uint16, k uint32) int {
		i := len(f)
		f = append(f, syscall.SockFilter{Code: code, K: k})
		return i
	}
	match := func(offset uint32) {
		for pos := 0; pos < len(question); {
			width := 4
			code := uint16(0x40)
			var value uint32
			if len(question)-pos >= 4 {
				value = binary.BigEndian.Uint32(question[pos:])
			} else if len(question)-pos >= 2 {
				width = 2
				code = 0x48
				value = uint32(binary.BigEndian.Uint16(question[pos:]))
			} else {
				width = 1
				code = 0x50
				value = uint32(question[pos])
			}
			emit(code, offset+uint32(pos))
			dropFalse = append(dropFalse, emit(0x15, value))
			pos += width
		}
		emit(0x06, 4096)
	}
	// TCP: X becomes IP+TCP header size; no payload is irrelevant, partial payload is unknown.
	emit(0x50, 12)
	emit(0x54, 0xf0)
	emit(0x74, 2)
	metaFalse = append(metaFalse, emit(0x35, 20))
	emit(0x0c, 0)
	emit(0x07, 0)
	emit(0x28, 2)
	metaFalse = append(metaFalse, emit(0x3d, 0))
	emit(0x1c, 0)
	dropTrue = append(dropTrue, emit(0x15, 0))
	metaFalse = append(metaFalse, emit(0x35, uint32(14+len(question))))
	match(14)
	udp := len(f)
	emit(0x28, 2)
	metaFalse = append(metaFalse, emit(0x3d, 0))
	emit(0x1c, 0)
	metaFalse = append(metaFalse, emit(0x35, uint32(20+len(question))))
	match(20)
	drop := emit(0x06, 0)
	// ponytail: no fragment/TCP reassembly; one payloadless version byte invalidates coverage.
	// Rejecting fragments silently could manufacture a complete absence claim; never copy their payload.
	meta := emit(0x06, 1)
	if len(f) > 255 {
		return nil, ErrUnsupported
	}
	f[16].Jt = uint8(udp - 17)
	for _, i := range dropFalse {
		f[i].Jf = uint8(drop - i - 1)
	}
	for _, i := range dropTrue {
		f[i].Jt = uint8(drop - i - 1)
	}
	for _, i := range metaTrue {
		f[i].Jt = uint8(meta - i - 1)
	}
	for _, i := range metaFalse {
		f[i].Jf = uint8(meta - i - 1)
	}
	return f, nil
}

func startMonitor(parent context.Context, b Binding, source, target string, port uint16, nonce string) (monitor, error) {
	from, e := netip.ParseAddr(source)
	if e != nil || !from.Is4() {
		return nil, ErrUnsupported
	}
	to, e := netip.ParseAddr(target)
	if e != nil || !to.Is4() {
		return nil, ErrUnsupported
	}
	src, dst := from.As4(), to.As4()
	filters, e := scopedPacketFilter(src, dst, port, nonce)
	if e != nil {
		return nil, e
	}
	fd := -1
	e = withinNamespace(parent, b, func() error {
		index, e := interfaceIndex(b.Interface)
		if e != nil {
			return e
		}
		// Protocol0 disables reception until the exact filter is installed and bind activates it.
		fd, e = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
		if e != nil {
			return ErrUnsupported
		}
		// Cooked L3 only: no Ethernet/MAC, promiscuous mode, or packet persistence.
		// ETH_P_ALL is required for egress delivery; the kernel filter still admits only scoped IPv4 L3 packets.
		program := syscall.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
		_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER, uintptr(unsafe.Pointer(&program)), unsafe.Sizeof(program), 0)
		if errno != 0 {
			return ErrUnsupported
		}
		if syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 100000}) != nil || syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, 40, 1) != nil {
			return ErrUnsupported
		}
		if syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: 768, Ifindex: index}) != nil {
			return ErrUnsupported
		}
		return nil
	})
	if e != nil {
		if fd >= 0 {
			syscall.Close(fd)
		}
		return nil, e
	}
	ctx, cancel := context.WithCancel(parent)
	m := &packetMonitor{cancel: cancel, done: make(chan observation, 1)}
	start := time.Now().UTC()
	go func() {
		result := observation{Start: start, Seen: map[string]int{}, Complete: true}
		defer func() {
			// Final kernel statistics catch tail drops even when no later packet carries SO_RXQ_OVFL.
			stats := struct{ Packets, Drops uint32 }{}
			length := uint32(unsafe.Sizeof(stats))
			_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), 263, 6, uintptr(unsafe.Pointer(&stats)), uintptr(unsafe.Pointer(&length)), 0)
			if errno != 0 || length != uint32(unsafe.Sizeof(stats)) || stats.Drops != 0 {
				result.Complete = false
			}
			if syscall.Close(fd) != nil {
				result.Complete = false
			} else {
				result.Closed = true
			}
			result.End = time.Now().UTC()
			m.done <- result
		}()
		data := make([]byte, 4096)
		oob := make([]byte, 128)
		for ctx.Err() == nil {
			n, on, flags, _, err := syscall.Recvmsg(fd, data, oob, 0)
			if err != nil {
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
					continue
				}
				result.Complete = false
				break
			}
			if flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
				result.Complete = false
			}
			messages, e := syscall.ParseSocketControlMessage(oob[:on])
			if e != nil {
				result.Complete = false
			}
			for _, message := range messages {
				if message.Header.Level == syscall.SOL_SOCKET && message.Header.Type == 40 && len(message.Data) >= 4 && binary.NativeEndian.Uint32(message.Data[:4]) != 0 {
					result.Complete = false
				}
			}
			transport, matched, complete := packetChallenge(data[:n], nonce)
			if !complete {
				result.Complete = false
			}
			if matched {
				result.Seen[transport]++
			}
		}
	}()
	return m, nil
}
func packetChallenge(packet []byte, nonce string) (string, bool, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return "", false, false
	}
	h := int(packet[0]&15) * 4
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if h < 20 || total > len(packet) || total < h || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return "", false, false
	}
	packet = packet[:total]
	var payload []byte
	transport := ""
	switch packet[9] {
	case 17:
		transport = "udp"
		if len(packet) < h+8 {
			return transport, false, false
		}
		payload = packet[h+8:]
	case 6:
		transport = "tcp"
		if len(packet) < h+20 {
			return transport, false, false
		}
		header := int(packet[h+12]>>4) * 4
		if header < 20 || len(packet) < h+header {
			return transport, false, false
		}
		payload = packet[h+header:]
		if len(payload) == 0 {
			return transport, false, true
		}
		if len(payload) < 2 {
			return transport, false, false
		}
		n := int(binary.BigEndian.Uint16(payload[:2]))
		if n < 12 || n > len(payload)-2 {
			return transport, false, false
		}
		payload = payload[2 : 2+n]
	default:
		return "", false, false
	}
	if len(payload) < 12 {
		return transport, false, false
	}
	if binary.BigEndian.Uint16(payload[2:4])&0x8000 != 0 {
		return transport, false, true
	}
	name, _, e := dnsName(payload, 12)
	if e != nil {
		return transport, false, false
	}
	return transport, name == nonce, true
}
