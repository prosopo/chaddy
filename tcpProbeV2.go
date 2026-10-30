package caddy_clienthello

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
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
	v2Request            = []byte{'T', 'P', 'v', '2', 0, 0, 0, 0}
	v2FlagByAddress byte = 1
	v2Unavailable        = []byte(`{"v":2,"hit":false,"reason":"unavailable"}`)
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
	return readV2Response(unixConn)
}

// isNoRecord is the answer for a socket the probe never saw. Behind Caddy's own
// layer4 PROXY-protocol hop that is the loopback socket, not the client's.
func isNoRecord(answer []byte) bool {
	return bytes.Contains(answer, []byte(`"reason":"no_record"`))
}

// lookupV2ByAddress names the client that the PROXY header reported, which only
// the local hop can set: proxy_protocol is restricted to 127.0.0.1.
func lookupV2ByAddress(socketPath, remoteAddr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("bad client ip %q", host)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	req := append([]byte{}, v2Request[:7]...)
	req = append(req, v2FlagByAddress)
	req = append(req, ip.To16()...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))

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
	if _, err := unixConn.Write(req); err != nil {
		return nil, err
	}
	return readV2Response(unixConn)
}

func readV2Response(unixConn *net.UnixConn) ([]byte, error) {
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
