package caddy_clienthello

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// TcpProbeHeader carries the probe's JSON answer, base64url encoded. It is set on
// every request, including misses, so downstream can tell "no record" from a
// client that reached it some other way. New signals need no chaddy release.
const TcpProbeHeader = "X-TCP-Probe"

const (
	v2Deadline = 50 * time.Millisecond
	// Far above a full answer; bounds what a misbehaving sidecar can make us read.
	v2MaxResponse = 64 * 1024
)

var (
	v2Request     = []byte{'T', 'P', 'v', '2', 0, 0, 0, 0}
	v2Unavailable = []byte(`{"v":2,"hit":false,"reason":"unavailable"}`)
)

// lookupV2 passes the connection's own socket to tcp-probe, so the answer belongs
// to exactly this connection and cannot be another client's. A fresh lookup per
// request is deliberate: counters such as tcp_info change over the connection.
func lookupV2(socketPath string, conn syscall.Conn) ([]byte, error) {
	sidecar, err := net.DialTimeout("unix", socketPath, v2Deadline)
	if err != nil {
		return nil, err
	}
	defer sidecar.Close()
	unixConn, ok := sidecar.(*net.UnixConn)
	if !ok {
		return nil, errors.New("sidecar is not a unix socket")
	}
	if err := unixConn.SetDeadline(time.Now().Add(v2Deadline)); err != nil {
		return nil, err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var sendErr error
	if err := raw.Control(func(fd uintptr) {
		_, _, sendErr = unixConn.WriteMsgUnix(v2Request, syscall.UnixRights(int(fd)), nil)
	}); err != nil {
		return nil, err
	}
	if sendErr != nil {
		return nil, sendErr
	}
	var length [4]byte
	if _, err := io.ReadFull(unixConn, length[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(length[:])
	if n > v2MaxResponse {
		return nil, fmt.Errorf("tcp-probe response of %d bytes", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(unixConn, body); err != nil {
		return nil, err
	}
	return body, nil
}

// stripForgedHeaders removes everything downstream treats as observed by us. It
// runs on every request: these headers are trusted, and a client can send them.
func stripForgedHeaders(h http.Header) {
	for name := range h {
		if name == http.CanonicalHeaderKey(TcpProbeHeader) || strings.HasPrefix(name, "X-Tls-") {
			delete(h, name)
		}
	}
}

func encodeProbe(body []byte) string {
	return base64.RawURLEncoding.EncodeToString(body)
}
