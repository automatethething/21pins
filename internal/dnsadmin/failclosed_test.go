package dnsadmin

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMissingStaleFutureHandshakeAndNativeFailures(t *testing.T) {
	for _, stamp := range []int64{0, time.Now().Add(-4 * time.Minute).Unix(), time.Now().Add(time.Minute).Unix()} {
		f := setup(t)
		if _, e := f.x.enroll(); e != nil {
			t.Fatal(e)
		}
		f.handshake = stamp
		if _, e := f.x.operation("wg-handshake"); e == nil {
			t.Fatal("handshake fabricated")
		}
	}
	f := setup(t)
	f.x.run = func(string, ...string) ([]byte, error) { return nil, Denied }
	for _, op := range Operations {
		if _, e := f.x.operation(op); e == nil {
			t.Fatal("missing backend falsely passes", op)
		}
	}
}
func TestOrphanSensitiveTempsAndMalformedPersistence(t *testing.T) {
	f := setup(t)
	p := filepath.Join(f.x.dir, ".21pins-transaction-orphan")
	if os.WriteFile(p, []byte("synthetic-private-snapshot"), 0600) != nil {
		t.Fatal("fixture")
	}
	if _, e := f.x.enroll(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("orphan sensitive file retained")
	}
	for _, b := range []string{"[Peer]\nPublicKey = invalid\nAllowedIPs = 10.66.66.5/32\n", "[Interface]\n[Interface]\n", "unparsed"} {
		if _, e := persistent([]byte(b)); e == nil {
			t.Fatal("malformed persistence accepted")
		}
	}
}
