package caddy_clienthello

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ClientHelloListenerWrapper{})
}

type ClientHelloListenerWrapper struct {
	cache  *Cache
	config *Config
	log    *zap.Logger
}

type clientHelloListener struct {
	net.Listener
	cache  *Cache
	config *Config
	log    *zap.Logger
}

type clientHelloConnListener struct {
	net.Conn
	cache *Cache
	log   *zap.Logger
}

// CaddyModule implements caddy.Module
func (ClientHelloListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.client_hello",
		New: func() caddy.Module { return new(ClientHelloListenerWrapper) },
	}
}

func (l *ClientHelloListenerWrapper) Provision(ctx caddy.Context) error {
	app, err := ctx.App(CacheAppId)
	if err != nil {
		return err
	}
	l.cache = app.(*Cache)

	app, err = ctx.App(ConfigAppId)
	if err != nil {
		return err
	}
	l.config = app.(*Config)

	l.log = ctx.Logger(l)
	return nil
}

// WrapListener implements caddy.ListenerWrapper
func (l *ClientHelloListenerWrapper) WrapListener(ln net.Listener) net.Listener {
	return &clientHelloListener{
		ln,
		l.cache,
		l.config,
		l.log,
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (l *ClientHelloListenerWrapper) UnmarshalCaddyfile(_ *caddyfile.Dispenser) error {
	// no-op impl
	return nil
}

// Accept implements net.Listener
func (l *clientHelloListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return conn, err
	}

	// when a connection is first init'd, read the client hello
	raw, err := ReadClientHello(l.config, conn)

	if err != nil && err.Error() != "ClientHello exceeds maximum size, treating as invalid" {
		l.log.Error("Failed to read ClientHello", zap.String("addr", conn.RemoteAddr().String()), zap.Error(err))
		return RewindConn(conn, raw)
	}

	var encoded string
	if err != nil {
		encoded = "EXCEEDS_MAXIMUM_SIZE"
	} else {
		encoded = base64.StdEncoding.EncodeToString(raw)
	}
	// record the client hello against the remote addr
	// the remote addr is the clients IP + an ephemeral port
	// this is unique per connection, so we can cache client hello's keyed by this
	// note that even with NAT/CGNAT, the remote addr will be unique per connection
	if err := l.cache.SetClientHello(conn.RemoteAddr().String(), encoded); err != nil {
		l.log.Error("Failed to set record in ClientHello cache",
			zap.String("addr", conn.RemoteAddr().String()),
			zap.String("client_hello", encoded),
			zap.Error(err),
		)
	} else {
		l.log.Debug("Cached ClientHello for connection", zap.String("addr", conn.RemoteAddr().String()))
	}

	return RewindConn(&clientHelloConnListener{
		conn,
		l.cache,
		l.log,
	}, raw)
}

// Close implements net.Conn
func (l *clientHelloConnListener) Close() error {
	addr := l.Conn.RemoteAddr().String()

	// clear the client hello on connection closed
	// the connection is closed, so client hello will no longer be needed as connection cannot be used going forwards
	l.cache.ClearClientHello(addr)

	return l.Conn.Close()
}

// ReadClientHello reads as much of a ClientHello as possible and returns it.
// If any error was encountered, then an error is returned as well and the raw bytes are not a full ClientHello.
func ReadClientHello(config *Config, r io.Reader) (raw []byte, err error) {
	// Based on https://github.com/gaukas/clienthellod/blob/7cce34b88b314256c8759998f6192860f6f6ede5/clienthello.go#L68

	// Read a TLS record
	// Read exactly 5 bytes from the reader
	raw = make([]byte, 5)
	if _, err = io.ReadFull(r, raw); err != nil {
		return
	}

	// Check if the first byte is 0x16 (TLS Handshake)
	if raw[0] != 0x16 {
		err = errors.New("not a TLS handshake record")
		return
	}

	// Read ClientHello length
	length := binary.BigEndian.Uint16(raw[3:5])
	if length > config.MaxClientHelloSize {
		err = errors.New("ClientHello exceeds maximum size, treating as invalid; size=" + strconv.Itoa(int(length)))
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

