package caddy_clienthello

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// HeaderOrderHeader carries the request's header names in the order the
// client sent them, comma-joined. HTTP/2 names are lowercase and include
// the pseudo-headers; HTTP/1.x names keep the client's casing. Duplicates
// are kept.
const HeaderOrderHeader = "X-Header-Order"

const defaultFirstBytesTimeout = 10 * time.Second

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
type HeaderOrderListenerWrapper struct {
	// Timeout closes a connection that has not completed the TLS handshake
	// and sent its first request bytes in time. Go's HTTP server only
	// applies its handshake and HTTP/2 preface timeouts to an unwrapped
	// *tls.Conn, so without this a silent client would be held open
	// indefinitely. Defaults to 10s, Go's HTTP/2 preface timeout.
	Timeout caddy.Duration `json:"timeout,omitempty"`
}

func (HeaderOrderListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.header_order",
		New: func() caddy.Module { return new(HeaderOrderListenerWrapper) },
	}
}

func (l *HeaderOrderListenerWrapper) Provision(_ caddy.Context) error {
	if l.Timeout <= 0 {
		l.Timeout = caddy.Duration(defaultFirstBytesTimeout)
	}
	return nil
}

func (l *HeaderOrderListenerWrapper) WrapListener(ln net.Listener) net.Listener {
	return &headerOrderListener{Listener: ln, timeout: time.Duration(l.Timeout)}
}

// UnmarshalCaddyfile sets up the wrapper from Caddyfile tokens:
//
//	header_order {
//		timeout <duration>
//	}
func (l *HeaderOrderListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			timeout, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid timeout: %v", err)
			}
			l.Timeout = caddy.Duration(timeout)
		default:
			return d.Errf("unrecognized option: %s", d.Val())
		}
	}
	return nil
}

type connectionStater interface {
	ConnectionState() tls.ConnectionState
}

type headerOrderListener struct {
	net.Listener
	timeout time.Duration
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
	wrapped := &headerOrderConn{
		Conn:     conn,
		stater:   stater,
		recorder: &headerOrderRecorder{},
		key:      conn.RemoteAddr().String(),
	}
	headerOrders.put(wrapped.key, wrapped.recorder)
	wrapped.firstBytesTimer = time.AfterFunc(l.timeout, func() { _ = wrapped.closeConn() })
	return wrapped, nil
}

type headerOrderConn struct {
	net.Conn
	stater          connectionStater
	recorder        *headerOrderRecorder
	key             string
	firstBytesTimer *time.Timer
	firstBytesSeen  bool
	closeOnce       sync.Once
}

func (c *headerOrderConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		if !c.firstBytesSeen {
			c.firstBytesSeen = true
			c.firstBytesTimer.Stop()
		}
		c.recorder.observe(b[:n])
	}
	return n, err
}

func (c *headerOrderConn) Close() error {
	c.firstBytesTimer.Stop()
	return c.closeConn()
}

func (c *headerOrderConn) closeConn() error {
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
// Matching uses the request as it arrived, before any rewrite.
func applyHeaderOrder(req *http.Request) {
	recorder := headerOrders.get(req.RemoteAddr)
	var order string
	var recorded bool
	if recorder != nil {
		method, target := req.Method, req.RequestURI
		if original, ok := req.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request); ok {
			method, target = original.Method, original.RequestURI
		}
		order, recorded = recorder.take(method, target, req.Host, req.Header)
	}
	req.Header.Del(HeaderOrderHeader)
	if recorded {
		req.Header.Set(HeaderOrderHeader, order)
	}
}

var (
	_ caddy.Provisioner     = (*HeaderOrderListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*HeaderOrderListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*HeaderOrderListenerWrapper)(nil)
	_ connectionStater      = (*headerOrderConn)(nil)
)
