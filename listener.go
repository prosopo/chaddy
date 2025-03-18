package caddy_clienthello

import (
	"net"

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

	l.log.Info(("chaddy listener provisioned"))

	return nil
}

// WrapListener implements caddy.ListenerWrapper
func (l *ClientHelloListenerWrapper) WrapListener(ln net.Listener) net.Listener {
	// returns our custom listener which accepts new connections
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

// accept a connection
// this needs to resolve asap bc it's blocking!
func (l *clientHelloListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()

	if err != nil {
		return nil, err
	}

	// wrap the conn in a ClientHelloConnWrapper to intercept the client hello
	conn = NewClientHelloConnWrapper(conn, l.cache, l.log)

	return conn, nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*ClientHelloListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ClientHelloListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*ClientHelloListenerWrapper)(nil)
)

