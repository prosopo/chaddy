package caddy_clienthello

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/http"
	"path/filepath"
	"syscall"
	"testing"
)

// serveOne answers one lookup and reports how many fds it received.
func serveOne(t *testing.T, path string, answer []byte) <-chan int {
	t.Helper()
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	fds := make(chan int, 1)
	go func() {
		c, err := l.AcceptUnix()
		if err != nil {
			return
		}
		defer c.Close()
		req, oob := make([]byte, 8), make([]byte, 64)
		_, oobn, _, _, _ := c.ReadMsgUnix(req, oob)
		msgs, _ := syscall.ParseSocketControlMessage(oob[:oobn])
		count := 0
		for i := range msgs {
			got, _ := syscall.ParseUnixRights(&msgs[i])
			for _, fd := range got {
				syscall.Close(fd)
			}
			count += len(got)
		}
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(answer)))
		c.Write(append(n[:], answer...))
		fds <- count
	}()
	return fds
}

func tcpConn(t *testing.T) *net.TCPConn {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c.(*net.TCPConn)
}

func TestLookupV2PassesExactlyOneFd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	want := []byte(`{"v":2,"hit":true}`)
	fds := serveOne(t, path, want)
	got, err := lookupV2(path, tcpConn(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %s", got)
	}
	if n := <-fds; n != 1 {
		t.Fatalf("sidecar received %d fds", n)
	}
}

func TestLookupV2FailsWhenSidecarIsAbsent(t *testing.T) {
	if _, err := lookupV2(filepath.Join(t.TempDir(), "none"), tcpConn(t)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestStripForgedHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-TCP-Probe", "forged")
	h.Set("X-TLS-Syn-Ns", "1")
	h.Set("X-TLS-ClientHello", "forged")
	h.Set("X-Other", "kept")
	stripForgedHeaders(h)
	if len(h) != 1 || h.Get("X-Other") != "kept" {
		t.Fatalf("left %v", h)
	}
}

func TestEncodeProbeIsUnpaddedBase64URL(t *testing.T) {
	got, err := base64.RawURLEncoding.DecodeString(encodeProbe(v2Unavailable))
	if err != nil || !bytes.Equal(got, v2Unavailable) {
		t.Fatalf("got %s, %v", got, err)
	}
}
