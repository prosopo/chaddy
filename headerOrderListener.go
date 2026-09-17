package caddy_clienthello

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// HeaderOrderHeader carries the request's header names in the order the
// client sent them, comma-joined. HTTP/2 names are lowercase and include
// the pseudo-headers; HTTP/1.x names keep the client's casing. Duplicates
// are kept.
const HeaderOrderHeader = "X-Header-Order"

func init() {
	caddy.RegisterModule(HeaderOrderListenerWrapper{})
}

// HeaderOrderListenerWrapper records the order of request header names as
// they arrive on the wire, before Go's HTTP server parses them into a map.
// It must be placed after the `tls` placeholder so it sees plaintext:
//
//	listener_wrappers {
//		tls
//		header_order
//	}
//
// The recorded order is attached to the request by the client_hello
// handler. Requires Caddy v2.11+, which serves both HTTP/1.x and HTTP/2 on
// wrapped TLS connections and restores Request.TLS from ConnectionState.
type HeaderOrderListenerWrapper struct{}

func (HeaderOrderListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.header_order",
		New: func() caddy.Module { return new(HeaderOrderListenerWrapper) },
	}
}

func (l *HeaderOrderListenerWrapper) WrapListener(ln net.Listener) net.Listener {
	return &headerOrderListener{Listener: ln}
}

func (l *HeaderOrderListenerWrapper) UnmarshalCaddyfile(_ *caddyfile.Dispenser) error {
	return nil
}

type connectionStater interface {
	ConnectionState() tls.ConnectionState
}

type headerOrderListener struct {
	net.Listener
}

func (l *headerOrderListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	stater, ok := conn.(connectionStater)
	if !ok {
		return conn, nil
	}
	key := conn.RemoteAddr().String()
	recorder := newHeaderOrderRecorder()
	headerOrders.put(key, recorder)
	return &headerOrderConn{Conn: conn, stater: stater, recorder: recorder, key: key}, nil
}

type headerOrderConn struct {
	net.Conn
	stater    connectionStater
	recorder  *headerOrderRecorder
	key       string
	closeOnce sync.Once
}

func (c *headerOrderConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.recorder.observe(b[:n])
	}
	return n, err
}

func (c *headerOrderConn) Close() error {
	c.closeOnce.Do(func() { headerOrders.remove(c.key, c.recorder) })
	return c.Conn.Close()
}

func (c *headerOrderConn) ConnectionState() tls.ConnectionState {
	return c.stater.ConnectionState()
}

// headerOrderRegistry maps a connection's remote address to its recorder,
// the same key the ClientHello cache uses. It is package-level so recorders
// survive config reloads that replace module instances.
type headerOrderRegistry struct {
	mu     sync.Mutex
	byAddr map[string]*headerOrderRecorder
}

var headerOrders = &headerOrderRegistry{byAddr: make(map[string]*headerOrderRecorder)}

func (r *headerOrderRegistry) put(key string, recorder *headerOrderRecorder) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byAddr[key] = recorder
}

func (r *headerOrderRegistry) get(key string) *headerOrderRecorder {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byAddr[key]
}

func (r *headerOrderRegistry) remove(key string, recorder *headerOrderRecorder) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byAddr[key] == recorder {
		delete(r.byAddr, key)
	}
}

// applyHeaderOrder replaces any client-supplied X-Header-Order with the
// order recorded for this request, or removes it when none was recorded.
func applyHeaderOrder(req *http.Request) {
	req.Header.Del(HeaderOrderHeader)
	recorder := headerOrders.get(req.RemoteAddr)
	if recorder == nil {
		return
	}
	names, ok := recorder.take(req.Method, req.RequestURI)
	if !ok {
		return
	}
	req.Header.Set(HeaderOrderHeader, strings.Join(names, ","))
}

var (
	_ caddy.ListenerWrapper = (*HeaderOrderListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*HeaderOrderListenerWrapper)(nil)
	_ connectionStater      = (*headerOrderConn)(nil)
)
