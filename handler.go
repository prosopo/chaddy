package caddy_clienthello

import (
	"encoding/base64"
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
	if req.TLS.HandshakeComplete && req.ProtoMajor < 3 { // Ensure this uses TLS and < HTTP/3
		var cacheKey string
		if req.TLS != nil {
			// Extract the SessionID from the TLS connection state
			sessionID := req.TLS.TLSUnique

			if sessionID != nil && len(sessionID) > 0 {
				cacheKey = base64.StdEncoding.EncodeToString(sessionID)
				h.log.Debug("SessionID found", zap.String("addr", req.RemoteAddr), zap.String("session_id", cacheKey))

			} else {
				h.log.Debug("No SessionID found", zap.String("addr", req.RemoteAddr))
				cacheKey = req.RemoteAddr
			}

		} else {
			h.log.Debug("No SessionID found", zap.String("addr", req.RemoteAddr))
			cacheKey = req.RemoteAddr
		}

		clientHello := h.cache.GetClientHello(cacheKey) // Retrieve ClientHello from cache
		if clientHello == nil {
			h.log.Error("ClientHello missing from cache", zap.String("addr", req.RemoteAddr))
		} else {
			h.log.Debug("Adding encoded ClientHello to request", zap.String("addr", req.RemoteAddr))
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
