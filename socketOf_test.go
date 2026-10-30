package chaddy

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

func tcpConn(t *testing.T) *net.TCPConn {
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
	tcp := tcpConn(t)
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
