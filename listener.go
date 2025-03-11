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

	raw, err := ReadClientHello(l.config, conn)

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

	l.log.Debug("Cache Size", zap.Int("size", len(l.cache.clientHellos)))

	// Extract the SessionID from the ClientHello (this assumes `ReadClientHello` parses the ClientHello structure)
	sessionID := extractSessionIDFromClientHello(raw)
	if sessionID != nil {
		l.log.Debug("Extracted SessionID", zap.String("session_id", base64.StdEncoding.EncodeToString(sessionID)))
	}

	if err := l.cache.SetClientHello(sessionID, encoded); err != nil {
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

// Function to extract the SessionID from the ClientHello (assuming raw contains the ClientHello message)
func extractSessionIDFromClientHello(clientHello []byte) []byte {
	// This is where you would parse the ClientHello message and extract the SessionID
	// A typical ClientHello structure has a SessionID field at a specific offset in the raw bytes
	// Depending on how your ReadClientHello function works, you'd need to parse it accordingly.
	// Here's a placeholder implementation.

	// For example:
	// The SessionID typically follows the protocol version and random data in the ClientHello message.
	// You can decode it based on the standard TLS protocol message format.

	if len(clientHello) < 38 { // ClientHello has a minimum length
		return nil
	}

	// SessionID is generally located at the offset of 38 bytes in the ClientHello
	// (this might need adjustment depending on your exact `ReadClientHello` parsing implementation)
	sessionIDLen := int(clientHello[38]) // SessionID length is at byte 38
	if len(clientHello) < 39+sessionIDLen {
		return nil
	}
    // SessionID is located at byte 39
	return clientHello[39 : 39+sessionIDLen]

}

// Close implements net.Conn
func (l *clientHelloConnListener) Close() error {
	addr := l.Conn.RemoteAddr().String()

	l.cache.ClearClientHello(addr)
	l.log.Debug("Clearing ClientHello for connection", zap.String("addr", addr))

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
