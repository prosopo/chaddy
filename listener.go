package caddy_clienthello

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	"net/http"
)

func init() {
	caddy.RegisterModule(ClientHelloListenerWrapper{})
}

type ClientHelloListenerWrapper struct {
	log *zap.Logger
}

type clientHelloListener struct {
	net.Listener
	log *zap.Logger
}

type clientHelloConnListener struct {
	net.Conn
	log         *zap.Logger
	clientHello string
}

// CaddyModule implements caddy.Module
func (ClientHelloListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.client_hello",
		New: func() caddy.Module { return new(ClientHelloListenerWrapper) },
	}
}

func (l *ClientHelloListenerWrapper) Provision(ctx caddy.Context) error {
	l.log = ctx.Logger(l)
	return nil
}

// WrapListener implements caddy.ListenerWrapper
func (l *ClientHelloListenerWrapper) WrapListener(ln net.Listener) net.Listener {
	return &clientHelloListener{
		ln,
		l.log,
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (l *ClientHelloListenerWrapper) UnmarshalCaddyfile(_ *caddyfile.Dispenser) error {
	return nil
}

// Accept implements net.Listener
func (l *clientHelloListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return conn, err
	}

	raw, err := ReadClientHello(conn)
	if err != nil && err.Error() != "ClientHello exceeds maximum size, treating as invalid" {
		l.log.Debug("Failed to read ClientHello", zap.String("addr", conn.RemoteAddr().String()), zap.Error(err))
		return RewindConn(conn, raw)
	}

	var encoded string
	if err != nil {
		encoded = "EXCEEDS_MAXIMUM_SIZE"
	} else {
		encoded = base64.StdEncoding.EncodeToString(raw)
	}

	l.log.Debug("Read ClientHello for connection", zap.String("addr", conn.RemoteAddr().String()))

	return RewindConn(&clientHelloConnListener{
		Conn:        conn,
		log:         l.log,
		clientHello: encoded,
	}, raw)
}

// ServeHTTP injects the ClientHello as a request header
func (l *clientHelloConnListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if l.clientHello != "" {
		r.Header.Set("X-ClientHello", l.clientHello)
	}
	http.DefaultServeMux.ServeHTTP(w, r)
}

// Close implements net.Conn
func (l *clientHelloConnListener) Close() error {
	return l.Conn.Close()
}

func ReadClientHello(r io.Reader) (raw []byte, err error) {
	raw = make([]byte, 5)
	if _, err = io.ReadFull(r, raw); err != nil {
		return
	}

	if raw[0] != 0x16 {
		err = errors.New("not a TLS handshake record")
		return
	}

	length := binary.BigEndian.Uint16(raw[3:5])
	if length > 16384 {
		err = errors.New("ClientHello exceeds maximum size, treating as invalid")
		return
	}

	raw = append(raw, make([]byte, length)...)
	_, err = io.ReadFull(r, raw[5:])
	return raw, err
}

// Interface guards
var (
	_ caddy.Provisioner     = (*ClientHelloListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ClientHelloListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*ClientHelloListenerWrapper)(nil)
)
