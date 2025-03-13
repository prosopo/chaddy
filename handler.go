package caddy_clienthello

import (
	"net/http"

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
	}

	return next.ServeHTTP(rw, req)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*ClientHelloHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*ClientHelloHandler)(nil)
	_ caddyfile.Unmarshaler       = (*ClientHelloHandler)(nil)
)
