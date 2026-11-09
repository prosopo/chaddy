package caddy_clienthello

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// distantClientConn answers the server's handshake flight only after an
// extra delay, as a client further away would.
type distantClientConn struct {
	net.Conn
	delay   time.Duration
	hasRead bool
}

func (c *distantClientConn) Read(b []byte) (int, error) {
	c.hasRead = true
	return c.Conn.Read(b)
}

func (c *distantClientConn) Write(b []byte) (int, error) {
	if c.hasRead {
		time.Sleep(c.delay)
		c.delay = 0
	}
	return c.Conn.Write(b)
}

func handshakeRttOver(t *testing.T, version uint16, clientDelay time.Duration) *time.Duration {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cache := &Cache{}
	cache.init(zap.NewNop())
	serverDone := make(chan string, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serverDone <- ""
			return
		}
		wrapped := NewClientHelloConnWrapper(raw, cache, zap.NewNop(), time.Now(), "")
		server := tls.Server(wrapped, &tls.Config{
			Certificates: []tls.Certificate{selfSignedCert(t)},
			MinVersion:   version,
			MaxVersion:   version,
		})
		if err := server.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
		}
		serverDone <- raw.RemoteAddr().String()
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	client := tls.Client(&distantClientConn{Conn: raw, delay: clientDelay}, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	return cache.GetHandshakeRtt(<-serverDone)
}

func TestTheHandshakeRoundTripIncludesTheTimeTheClientTakesToAnswer(t *testing.T) {
	for _, c := range []struct {
		name    string
		version uint16
	}{{"TLS 1.3", tls.VersionTLS13}, {"TLS 1.2", tls.VersionTLS12}} {
		t.Run(c.name, func(t *testing.T) {
			const delay = 80 * time.Millisecond
			rtt := handshakeRttOver(t, c.version, delay)
			if rtt == nil {
				t.Fatal("no round trip recorded")
			}
			if *rtt < delay || *rtt > delay+500*time.Millisecond {
				t.Fatalf("round trip %v does not reflect the client's %v delay", *rtt, delay)
			}
		})
	}
}

func TestANearbyClientHasASmallHandshakeRoundTrip(t *testing.T) {
	rtt := handshakeRttOver(t, tls.VersionTLS13, 0)
	if rtt == nil {
		t.Fatal("no round trip recorded")
	}
	if *rtt > 50*time.Millisecond {
		t.Fatalf("loopback round trip %v is implausibly large", *rtt)
	}
}

func TestAReplyAlreadyBufferedBeforeTheFlightIsNotTimed(t *testing.T) {
	cache := openConnectionCache(t)
	server, client := net.Pipe()
	defer client.Close()
	conn := remoteAddrConn{Conn: server, addr: &net.TCPAddr{IP: testIP, Port: 54321}}
	wrapper := NewClientHelloConnWrapper(conn, cache, zap.NewNop(), time.Now(), "")
	wrapper.done = true

	go func() { _, _ = client.Write([]byte("early")) }()
	if _, err := wrapper.bufferedReader.Peek(5); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = client.Read(make([]byte, 16)) }()
	if _, err := wrapper.Write([]byte("flight")); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapper.Read(make([]byte, 16)); err != nil {
		t.Fatal(err)
	}

	if rtt := cache.GetHandshakeRtt(testAddr); rtt != nil {
		t.Fatalf("timed a reply that was buffered before the flight: %v", *rtt)
	}
}

func TestClosingTheConnectionDropsItsHandshakeRoundTrip(t *testing.T) {
	cache := openConnectionCache(t)
	cache.SetHandshakeRttIfOpen(testAddr, 30*time.Millisecond)

	cache.ClearClientHello(testAddr)

	if rtt := cache.GetHandshakeRtt(testAddr); rtt != nil {
		t.Fatalf("round trip outlived its connection: %v", *rtt)
	}
}
