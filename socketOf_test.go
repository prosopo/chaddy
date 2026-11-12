package caddy_clienthello

import (
	"net"
	"syscall"
	"testing"
)

type rawWrapper struct {
	net.Conn
	inner net.Conn
}

func (w rawWrapper) Raw() net.Conn { return w.inner }

type netConnWrapper struct {
	net.Conn
	inner net.Conn
}

func (w netConnWrapper) NetConn() net.Conn { return w.inner }

type plainConn struct{ net.Conn }

func dialedTCP(t *testing.T) *net.TCPConn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn.(*net.TCPConn)
}

func TestSocketOfUnwraps(t *testing.T) {
	tcp := dialedTCP(t)
	cases := map[string]net.Conn{
		"bare":    tcp,
		"raw":     rawWrapper{inner: tcp},
		"netconn": netConnWrapper{inner: tcp},
		"nested":  rawWrapper{inner: netConnWrapper{inner: tcp}},
	}
	for name, conn := range cases {
		var got syscall.Conn = socketOf(conn)
		if got != syscall.Conn(tcp) {
			t.Errorf("%s: got %v", name, got)
		}
	}
}

func TestSocketOfOpaqueConnIsNil(t *testing.T) {
	if got := socketOf(plainConn{}); got != nil {
		t.Errorf("got %v", got)
	}
}

func TestIsNoRecord(t *testing.T) {
	if !isNoRecord([]byte(`{"v":2,"hit":false,"reason":"no_record"}`)) {
		t.Error("no_record not recognised")
	}
	if isNoRecord([]byte(`{"v":2,"hit":true}`)) {
		t.Error("hit read as a miss")
	}
}

func TestLookupV2ByAddressRejectsBadAddress(t *testing.T) {
	if _, err := lookupV2ByAddress("/nonexistent", "not-an-address"); err == nil {
		t.Error("expected an error")
	}
}
