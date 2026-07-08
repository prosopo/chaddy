package caddy_clienthello

import (
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ClientHelloHandler{})
	httpcaddyfile.RegisterHandlerDirective("client_hello", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		handler := &ClientHelloHandler{}
		return handler, handler.UnmarshalCaddyfile(h.Dispenser)
	})
}

type ClientHelloHandler struct {
	cache *Cache
	log   *zap.Logger
}

// CaddyModule implements caddy.Module
func (ClientHelloHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.client_hello",
		New: func() caddy.Module { return new(ClientHelloHandler) },
	}
}

// Provision implements caddy.Provisioner
func (h *ClientHelloHandler) Provision(ctx caddy.Context) error {
	a, err := ctx.App(CacheAppId)
	if err != nil {
		return err
	}

	h.cache = a.(*Cache)
	h.log = ctx.Logger(h)

	h.log.Info(("chaddy handler provisioned"))

	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (h *ClientHelloHandler) UnmarshalCaddyfile(_ *caddyfile.Dispenser) error {
	// no-op impl
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler
func (h *ClientHelloHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error {
	h.log.Debug("ClientHelloHandler: ServeHTTP")

	if req.TLS.HandshakeComplete && req.ProtoMajor < 3 { // Check that this uses TLS and < HTTP/3
		// get the client hello for the connection (which is cached by the remote addr, which is unique per connection)
		clientHello := h.cache.GetClientHello(req.RemoteAddr)

		if clientHello == nil {
			h.log.Error("ClientHello missing from cache", zap.String("addr", req.RemoteAddr))
		} else {
			h.log.Debug("Adding encoded ClientHello to request", zap.String("addr", req.RemoteAddr), zap.String("client_hello", *clientHello))
			req.Header.Add("X-TLS-ClientHello", *clientHello)
		}

		// Per-connection TLS handshake timing, forwarded as headers so
		// the downstream service can log them for proxy-detection
		// distribution analysis. Constant across every request over
		// the same TCP connection; the downstream should dedupe by
		// (connection-id, values) if that matters.
		//
		// Microseconds, not milliseconds: ms buckets fast handshakes
		// (local proxies, same-DC clients) to 0/1 and destroys the
		// distribution shape needed for detection. Go's monotonic
		// clock via time.Now() is ~1μs precise on Linux vDSO — μs is
		// the honest resolution ceiling.
		//
		// chello_to_handshake_us is measured at ServeHTTP entry, which
		// is a few tens of μs to a few ms after the TLS handshake
		// actually completes (the std lib finishes the handshake
		// between the CH being peeked and Caddy invoking this
		// middleware). Small positive baseline offset — treat the
		// value as relative-within-a-fleet, not absolute.
		timing := h.cache.GetTiming(req.RemoteAddr)
		if timing != nil {
			serveEntry := time.Now()
			tcpToChelloUs := timing.ClientHelloReceived.Sub(timing.ConnectionStart).Microseconds()
			chelloToHandshakeUs := serveEntry.Sub(timing.ClientHelloReceived).Microseconds()
			req.Header.Add("X-TLS-TCP-To-Chello-Us", strconv.FormatInt(tcpToChelloUs, 10))
			req.Header.Add("X-TLS-Chello-To-Handshake-Us", strconv.FormatInt(chelloToHandshakeUs, 10))
			h.log.Debug(
				"Added handshake timing headers",
				zap.String("addr", req.RemoteAddr),
				zap.Int64("tcp_to_chello_us", tcpToChelloUs),
				zap.Int64("chello_to_handshake_us", chelloToHandshakeUs),
			)
		}
	}

	return next.ServeHTTP(rw, req)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*ClientHelloHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*ClientHelloHandler)(nil)
	_ caddyfile.Unmarshaler       = (*ClientHelloHandler)(nil)
)
