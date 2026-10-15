package netpolicy

import (
	"encoding/binary"
	"testing"
)

func TestDNSWire(t *testing.T) {
	q, id, e := dnsQuery("pins-fixture.invalid")
	if e != nil {
		t.Fatal(e)
	}
	response := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(response[2:4], 0x8183)
	got, e := parseDNS(response, id, "pins-fixture.invalid")
	if e != nil || !got.valid || got.filter {
		t.Fatal("valid NXDOMAIN malformed", e)
	}
	if _, e = parseDNS(response, id+1, "pins-fixture.invalid"); e == nil {
		t.Fatal("wrong transaction accepted")
	}
	if _, e = parseDNS(response, id, "different.invalid"); e == nil {
		t.Fatal("wrong question accepted")
	}
	if _, e = parseDNS(append(response, 1), id, "pins-fixture.invalid"); e == nil {
		t.Fatal("trailing garbage")
	}
	// One OPT EDE blocked code, not text matching or NXDOMAIN inference.
	ede := append([]byte(nil), q[:len(q)-11]...)
	binary.BigEndian.PutUint16(ede[2:4], 0x8183)
	binary.BigEndian.PutUint16(ede[10:12], 1)
	ede = append(ede, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 6, 0, 15, 0, 2, 0, 15)
	got, e = parseDNS(ede, id, "pins-fixture.invalid")
	if e != nil || !got.filter {
		t.Fatal("binary EDE not validated", e)
	}
	ede[len(ede)-1] = 1
	got, e = parseDNS(ede, id, "pins-fixture.invalid")
	if e != nil || got.filter {
		t.Fatal("non-policy EDE accepted")
	}
	truncated := append([]byte(nil), response...)
	binary.BigEndian.PutUint16(truncated[2:4], 0x8383)
	if _, e = parseDNS(truncated, id, "pins-fixture.invalid"); e == nil {
		t.Fatal("truncated response completed")
	}
}
