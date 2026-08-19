package caddy_clienthello

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"strconv"
)

const (
	ConfigAppId = "client_hello.config"
)

type Config struct {
	MaxClientHelloSize uint16 `json:"max_client_hello_size"`
	// TcpProbeSocket is the filesystem path to a co-located eBPF TCP
	// handshake probe's Unix socket. When set, the ClientHelloHandler
	// enriches each request with X-TLS-* headers carrying the raw
	// wire signals the probe captured on the SYN (SYN/SYN-ACK/ACK ns
	// timestamps, observed TTL, TCP options / MSS / wscale / window).
	// When empty (the default), no lookup is attempted and no extra
	// headers are injected — chaddy still forwards X-TLS-ClientHello
	// exactly as before.
	//
	// Wire protocol expected on the socket: 12-byte big-endian request
	// (client_ip[4], client_port[2], server_ip[4], server_port[2]),
	// 80-byte fixed-size response (see tcpProbe.go for the layout).
	// prosopo's ja4l-probe binary is the reference implementation but
	// any probe that speaks the same protocol works.
	TcpProbeSocket string `json:"tcp_probe_socket,omitempty"`
}

func init() {
	caddy.RegisterModule(Config{})
	httpcaddyfile.RegisterGlobalOption("client_hello", parseCaddyfile)
}

func parseCaddyfile(d *caddyfile.Dispenser, _ any) (any, error) {
	var config Config

	for d.Next() {
		for d.NextBlock(0) {
			opt := d.Val()

			switch opt {
			case "max_client_hello_size":
				var tmp string
				if !d.AllArgs(&tmp) {
					return nil, d.Errf("invalid max_client_hello_size")
				}
				size, err := strconv.Atoi(tmp)
				if err != nil || size < 0 || size > 16384 {
					return nil, d.Errf("invalid max_client_hello_size, must be between [1, 16384]: %s", tmp)
				}
				config.MaxClientHelloSize = uint16(size)

			case "tcp_probe_socket":
				var tmp string
				if !d.AllArgs(&tmp) {
					return nil, d.Errf("invalid tcp_probe_socket")
				}
				config.TcpProbeSocket = tmp

			default:
				return nil, d.Errf("unrecognized option: %s", opt)
			}
		}
	}

	return httpcaddyfile.App{
		Name:  ConfigAppId,
		Value: caddyconfig.JSON(config, nil),
	}, nil
}

// CaddyModule implements caddy.Module
func (Config) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  ConfigAppId,
		New: func() caddy.Module { return new(Config) },
	}
}

// Provision implements caddy.Provisioner
func (c *Config) Provision(ctx caddy.Context) error {
	// Set defaults if global options were not present
	if c.MaxClientHelloSize == 0 {
		c.MaxClientHelloSize = 16384
	}

	// Disable TLS session resumption via session tickets
	app, err := ctx.App("tls")
	if err != nil {
		return err
	}
	tlsApp := app.(*caddytls.TLS)
	if tlsApp.SessionTickets == nil {
		tlsApp.SessionTickets = new(caddytls.SessionTicketService)
	}
	tlsApp.SessionTickets.Disabled = true
	ctx.Logger(c).Debug("adjusted config: disabled TLS session tickets")

	return nil
}

// Start implements caddy.App
func (c *Config) Start() error {
	return nil
}

// Stop implements caddy.App
func (c *Config) Stop() error {
	return nil
}

// Interface guards
var (
	_ caddy.App         = (*Config)(nil)
	_ caddy.Module      = (*Config)(nil)
	_ caddy.Provisioner = (*Config)(nil)
)
