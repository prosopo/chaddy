package caddy_clienthello

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const echoBody = "order={http.request.header.X-Header-Order};tls={http.request.tls.version};proto={http.request.proto}"

func selfSignedPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certPEM), string(keyPEM)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

var echoRoute = map[string]any{
	"handle": []map[string]any{
		{"handler": "client_hello"},
		{"handler": "static_response", "body": echoBody},
	},
}

func startCaddy(t *testing.T, routes []map[string]any, firstBytesTimeout string) string {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	certPEM, keyPEM := selfSignedPEM(t)
	addr := freeAddr(t)
	wrapper := map[string]any{"wrapper": "header_order"}
	if firstBytesTimeout != "" {
		wrapper["timeout"] = firstBytesTimeout
	}
	config := map[string]any{
		"admin":   map[string]any{"disabled": true},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "ERROR"}}},
		"apps": map[string]any{
			"tls": map[string]any{
				"certificates": map[string]any{
					"load_pem": []map[string]any{{"certificate": certPEM, "key": keyPEM}},
				},
			},
			"http": map[string]any{
				"servers": map[string]any{
					"test": map[string]any{
						"listen":                  []string{addr},
						"protocols":               []string{"h1", "h2"},
						"listener_wrappers":       []map[string]any{wrapper},
						"tls_connection_policies": []map[string]any{{}},
						"automatic_https":         map[string]any{"disable": true},
						"routes":                  routes,
					},
				},
			},
		},
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(raw, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })
	return addr
}

func dialTLS(t *testing.T, addr string, alpn string) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "localhost", InsecureSkipVerify: true, NextProtos: []string{alpn}})
	if err != nil {
		t.Fatal(err)
	}
	if got := conn.ConnectionState().NegotiatedProtocol; got != alpn {
		t.Fatalf("negotiated %q, want %q", got, alpn)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func h2Request(t *testing.T, conn *tls.Conn, framer *http2.Framer, encoder *hpack.Encoder, block *bytes.Buffer, streamID uint32, fields []testField) string {
	t.Helper()
	fragment := encodeBlock(t, encoder, block, fields)
	if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: fragment, EndHeaders: true, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var body bytes.Buffer
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := framer.WriteSettingsAck(); err != nil {
					t.Fatal(err)
				}
			}
		case *http2.DataFrame:
			if f.StreamID != streamID {
				continue
			}
			body.Write(f.Data())
			if f.StreamEnded() {
				return body.String()
			}
		case *http2.HeadersFrame:
			if f.StreamID == streamID && f.StreamEnded() {
				return body.String()
			}
		case *http2.GoAwayFrame:
			t.Fatalf("server sent GOAWAY: %v", f.ErrCode)
		}
	}
}

func TestCaddyForwardsHTTP2HeaderOrder(t *testing.T) {
	addr := startCaddy(t, []map[string]any{echoRoute}, "")
	conn := dialTLS(t, addr, "h2")
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	if err := framer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)

	first := []testField{
		{":method", "GET"},
		{":authority", "localhost"},
		{":scheme", "https"},
		{":path", "/one?q=1"},
		{"sec-ch-ua-platform", `"macOS"`},
		{"user-agent", "Mozilla/5.0"},
		{"x-header-order", "spoofed"},
		{"sec-ch-ua", `"Chromium";v="152"`},
		{"accept", "*/*"},
		{"priority", "u=1, i"},
	}
	got := h2Request(t, conn, framer, encoder, &block, 1, first)
	want := "order=" + strings.Join(names(first), ",") + ";tls=tls1.3;proto=HTTP/2.0"
	if got != want {
		t.Fatalf("first request\n got: %s\nwant: %s", got, want)
	}

	second := []testField{
		{":method", "GET"},
		{":scheme", "https"},
		{":path", "/two"},
		{":authority", "localhost"},
		{"accept", "*/*"},
		{"user-agent", "Mozilla/5.0"},
		{"sec-ch-ua", `"Chromium";v="152"`},
	}
	got = h2Request(t, conn, framer, encoder, &block, 3, second)
	want = "order=" + strings.Join(names(second), ",") + ";tls=tls1.3;proto=HTTP/2.0"
	if got != want {
		t.Fatalf("second request on the same connection\n got: %s\nwant: %s", got, want)
	}
}

func TestCaddyForwardsHTTP1HeaderOrder(t *testing.T) {
	addr := startCaddy(t, []map[string]any{echoRoute}, "")
	conn := dialTLS(t, addr, "http/1.1")
	requests := "POST /submit HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Connection: keep-alive\r\n" +
		"Content-Length: 2\r\n" +
		"sec-ch-ua: \"Chromium\"\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"X-Header-Order: spoofed\r\n" +
		"\r\n{}" +
		"GET /next HTTP/1.1\r\n" +
		"Accept: */*\r\n" +
		"Host: localhost\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, requests); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	wants := []string{
		"order=Host,Connection,Content-Length,sec-ch-ua,User-Agent,X-Header-Order;tls=tls1.3;proto=HTTP/1.1",
		"order=Accept,Host;tls=tls1.3;proto=HTTP/1.1",
	}
	for i, want := range wants {
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != want {
			t.Fatalf("request %d\n got: %s\nwant: %s", i, body, want)
		}
	}
}

func TestClientSuppliedHeaderOrderIsRemovedWithoutTheWrapper(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://localhost/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "192.0.2.1:1234"
	req.RequestURI = "/"
	req.Header.Set(HeaderOrderHeader, "spoofed")
	applyHeaderOrder(req)
	if _, present := req.Header[HeaderOrderHeader]; present {
		t.Fatal("a client-supplied X-Header-Order must not reach the upstream")
	}
}

type h2Client struct {
	t       *testing.T
	conn    *tls.Conn
	framer  *http2.Framer
	encoder *hpack.Encoder
	block   bytes.Buffer
}

func newH2Client(t *testing.T, addr string) *h2Client {
	t.Helper()
	c := &h2Client{t: t, conn: dialTLS(t, addr, "h2")}
	if _, err := io.WriteString(c.conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	c.framer = http2.NewFramer(c.conn, c.conn)
	c.framer.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	if err := c.framer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	c.encoder = hpack.NewEncoder(&c.block)
	return c
}

func (c *h2Client) do(streamID uint32, fields []testField) string {
	return h2Request(c.t, c.conn, c.framer, c.encoder, &c.block, streamID, fields)
}

func TestCaddyAttachesOrderToTheRightRequestOnASharedConnection(t *testing.T) {
	skipsHandler := map[string]any{
		"match":    []map[string]any{{"host": []string{"other.test"}}},
		"handle":   []map[string]any{{"handler": "static_response", "body": "no client_hello here"}},
		"terminal": true,
	}
	rewriteFirst := map[string]any{
		"match": []map[string]any{{"path": []string{"/old"}}},
		"handle": []map[string]any{
			{"handler": "rewrite", "uri": "/new?q=1"},
			{"handler": "client_hello"},
			{"handler": "static_response", "body": echoBody},
		},
		"terminal": true,
	}
	addr := startCaddy(t, []map[string]any{skipsHandler, rewriteFirst, echoRoute}, "")
	client := newH2Client(t, addr)

	skipped := []testField{{":method", "GET"}, {":authority", "other.test"}, {":scheme", "https"}, {":path", "/"}, {"a-first", "1"}}
	if got := client.do(1, skipped); got != "no client_hello here" {
		t.Fatalf("unexpected body %q", got)
	}
	served := []testField{{":method", "GET"}, {":authority", "localhost"}, {":scheme", "https"}, {":path", "/"}, {"b-second", "1"}}
	if got, want := client.do(3, served), "order="+strings.Join(names(served), ",")+";tls=tls1.3;proto=HTTP/2.0"; got != want {
		t.Fatalf("order from a request that skipped the handler leaked\n got: %s\nwant: %s", got, want)
	}
	rewritten := []testField{{":method", "GET"}, {":authority", "localhost"}, {":scheme", "https"}, {":path", "/old"}, {"c-third", "1"}}
	if got, want := client.do(5, rewritten), "order="+strings.Join(names(rewritten), ",")+";tls=tls1.3;proto=HTTP/2.0"; got != want {
		t.Fatalf("a rewrite before client_hello lost the order\n got: %s\nwant: %s", got, want)
	}
}

func closedWithin(conn net.Conn, limit time.Duration) bool {
	_ = conn.SetReadDeadline(time.Now().Add(limit))
	_, err := conn.Read(make([]byte, 1))
	var netErr net.Error
	return err != nil && !(errors.As(err, &netErr) && netErr.Timeout())
}

func TestCaddyClosesSilentConnections(t *testing.T) {
	addr := startCaddy(t, []map[string]any{echoRoute}, "300ms")

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if !closedWithin(raw, 3*time.Second) {
		t.Fatal("a connection that never starts TLS must be closed")
	}
	for _, alpn := range []string{"http/1.1", "h2"} {
		conn := dialTLS(t, addr, alpn)
		if !closedWithin(conn, 3*time.Second) {
			t.Fatalf("a %s connection that sends nothing after the handshake must be closed", alpn)
		}
	}
}

func TestCaddyKeepsActiveConnectionsPastTheTimeout(t *testing.T) {
	addr := startCaddy(t, []map[string]any{echoRoute}, "300ms")
	client := newH2Client(t, addr)
	request := []testField{{":method", "GET"}, {":authority", "localhost"}, {":scheme", "https"}, {":path", "/"}}
	want := "order=" + strings.Join(names(request), ",") + ";tls=tls1.3;proto=HTTP/2.0"
	if got := client.do(1, request); got != want {
		t.Fatalf("got %s", got)
	}
	time.Sleep(800 * time.Millisecond)
	if got := client.do(3, request); got != want {
		t.Fatalf("after the timeout got %s", got)
	}
}

func TestCaddyRemovesRecordersWhenConnectionsClose(t *testing.T) {
	addr := startCaddy(t, []map[string]any{echoRoute}, "")
	conn := dialTLS(t, addr, "http/1.1")
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	key := conn.LocalAddr().String()
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for headerOrders.get(key) != nil {
		if time.Now().After(deadline) {
			t.Fatal("the recorder for a closed connection is still registered")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
