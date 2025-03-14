package caddy_clienthello

import (
	"bufio"
	"encoding/base64"
	"net"

	"go.uber.org/zap"
)

// ClientHelloConnWrapper is a custom wrapper for net.Conn that intercepts the Read operation
// and allows us to collect the client hello bytes
type ClientHelloConnWrapper struct {
	net.Conn // embed the net.Conn interface (crucial for setReadTimeout to be applied by caddy to avoid blocking reads!)
	log    *zap.Logger
	bufferedReader *bufio.Reader
	done   bool
	cache *Cache
}

// NewClientHelloConnWrapper creates a new wrapper
func NewClientHelloConnWrapper(conn net.Conn, cache *Cache, log *zap.Logger) *ClientHelloConnWrapper {
	// create a buffered reader for the conn
	bufferedReader := bufio.NewReader(conn)
	return &ClientHelloConnWrapper{
		Conn:   conn,
		log:    log,
		bufferedReader: bufferedReader,
		done:   false, // we haven't read the client hello yet
		cache: cache,
	}
}

// Read intercepts the bytes being read from the connection.
// We can catch the client hello bytes here by peeking the client hello bytes from the connection.
func (r *ClientHelloConnWrapper) Read(b []byte) (n int, err error) {
	if r.done {
		// we've already read the client hello, just pass through to the buffered reader
		return r.bufferedReader.Read(b)
	}

	r.log.Debug("Reading client hello")

	r.done = true // we only want to read the client hello once
	
	// use the buffered reader to read the client hello
	// we peek here so we can read the client hello without consuming it

	// peek the first byte to check record type
	bytes, err := r.bufferedReader.Peek(1)
	if err != nil {
		r.log.Error("Error peeking record type", zap.Error(err))
		return r.bufferedReader.Read(b)
	}

	// byte 0: record type
	// check the record type is a handshake record (0x16)
	if bytes[0] != 0x16 {
		// not a handshake record, just pass through
		return r.bufferedReader.Read(b)
	}

	// peek the first 5 bytes of the client hello
	bytes, err = r.bufferedReader.Peek(5)
	if err != nil {
		r.log.Error("Error peeking record header", zap.Error(err))
		return r.bufferedReader.Read(b)
	}

	// byte 1-2: TLS version
	// byte 3-4: length of the handshake message (big endian)
	len := int(bytes[3])<<8 | int(bytes[4])

	// peek the full client hello
	bytes, err = r.bufferedReader.Peek(len + 5)
	if err != nil {
		r.log.Error("Error peeking client hello", zap.Error(err))
		return r.bufferedReader.Read(b)
	}

	// convert the client hello bytes to base64
	encoded := base64.StdEncoding.EncodeToString(bytes)
	
	// record client hello in cache
	r.cache.SetClientHello(r.Conn.RemoteAddr().String(), encoded)

	// delegate the original read call to the buffered reader
	return r.bufferedReader.Read(b)
}

// Close closes the connection
func (r *ClientHelloConnWrapper) Close() error {
	// connection is closing, remove the client hello from the cache
	r.cache.ClearClientHello(r.Conn.RemoteAddr().String())

	return r.Conn.Close()
}
