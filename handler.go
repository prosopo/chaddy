package caddy_clienthello

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
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
	cache  *Cache
	config *Config
	log    *zap.Logger

	// lastSizeMismatchLog is the UnixNano of the last record-size mismatch
	// we logged, throttling a per-deployment fault that would otherwise
	// report once per request. See logRecordSizeMismatch. A pointer because
	// CaddyModule takes this struct by value, and an inline atomic makes
	// that a vet failure.
	lastSizeMismatchLog *atomic.Int64
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

	b, err := ctx.App(ConfigAppId)
	if err != nil {
		return err
	}
	h.config = b.(*Config)

	h.log = ctx.Logger(h)
	h.lastSizeMismatchLog = &atomic.Int64{}

	if h.config.TcpProbeSocket != "" {
		h.log.Info("chaddy handler provisioned",
			zap.String("tcp_probe_socket", h.config.TcpProbeSocket))
	} else {
		h.log.Info("chaddy handler provisioned")
	}

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

		// Optional: enrich with raw TCP handshake signals from a
		// co-located eBPF probe. Everything sent is a wire-observed
		// primitive (RFC 793 / RFC 9293) — no fingerprints or derived
		// metrics are computed here. The downstream service decides
		// what (if anything) to derive.
		if h.config.TcpProbeSocket != "" {
			h.injectTcpProbeHeaders(req)
		}
	}

	return next.ServeHTTP(rw, req)
}

// injectTcpProbeHeaders looks up the raw TCP handshake record for the
// current connection and forwards each field as its own X-TLS-* header.
// Any error (bad RemoteAddr, socket unreachable, timeout, miss) is
// logged at debug and dropped — the request continues without the
// extra headers.
func (h *ClientHelloHandler) injectTcpProbeHeaders(req *http.Request) {
	host, portStr, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		h.log.Debug("SplitHostPort failed on RemoteAddr",
			zap.String("addr", req.RemoteAddr), zap.Error(err))
		return
	}
	clientIP := net.ParseIP(host)
	if clientIP == nil {
		h.log.Debug("ParseIP failed on RemoteAddr host",
			zap.String("host", host))
		return
	}
	portInt, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		h.log.Debug("ParseUint failed on RemoteAddr port",
			zap.String("port", portStr), zap.Error(err))
		return
	}

	rec, err := LookupHandshake(h.config.TcpProbeSocket, clientIP, uint16(portInt))
	if err != nil {
		if errors.Is(err, ErrRecordSizeMismatch) {
			h.logRecordSizeMismatch(err)
			return
		}
		h.log.Debug("TCP probe lookup failed",
			zap.String("addr", req.RemoteAddr), zap.Error(err))
		return
	}
	if rec == nil {
		h.log.Debug("TCP probe cache miss",
			zap.String("addr", req.RemoteAddr))
		return
	}

	// Header names deliberately match what the downstream provider
	// middleware (rawTlsSignalsMiddleware in the closed-source Prosopo
	// captcha provider) already parses. Any external consumer of chaddy
	// can wire their own middleware against the same names.
	req.Header.Set("X-TLS-Syn-Ns", strconv.FormatUint(rec.SynNs, 10))
	req.Header.Set("X-TLS-Synack-Ns", strconv.FormatUint(rec.SynackNs, 10))
	req.Header.Set("X-TLS-Ack-Ns", strconv.FormatUint(rec.AckNs, 10))
	req.Header.Set("X-TLS-Observed-Ttl", strconv.FormatUint(uint64(rec.ObservedTtl), 10))
	req.Header.Set("X-TLS-Tcp-Mss", strconv.FormatUint(uint64(rec.TcpMss), 10))
	req.Header.Set("X-TLS-Tcp-Wscale", strconv.FormatUint(uint64(rec.TcpWscale), 10))
	req.Header.Set("X-TLS-Tcp-Window", strconv.FormatUint(uint64(rec.TcpWindow), 10))

	// Only the header set the record actually carries. An 80-byte sidecar
	// has no option kinds, no Timestamps values and no IPv4 header fields;
	// sending zeros for them would publish "not sent" as an observation of
	// zero, which is the class of bug this reader exists to avoid.
	if rec.Legacy {
		req.Header.Set("X-TLS-Tcp-Opts-Flags", strconv.FormatUint(uint64(rec.TcpOptsFlags), 10))
		req.Header.Set("X-TLS-Tcp-Opts-Order", strconv.FormatUint(uint64(rec.TcpOptsOrder), 10))
	} else {
		// New names rather than the old ones carrying new meanings:
		// reusing a name for a differently-encoded value is how a column
		// silently changes what it holds.
		req.Header.Set("X-TLS-Tcp-Opts-Kinds", strconv.FormatUint(rec.TcpOptsKinds, 10))
		req.Header.Set("X-TLS-Tcp-Opts-Present", strconv.FormatUint(uint64(rec.TcpOptsPresent), 10))
		req.Header.Set("X-TLS-Tcp-Opts-Count", strconv.FormatUint(uint64(rec.TcpOptsCount), 10))
		req.Header.Set("X-TLS-Tcp-Flags", strconv.FormatUint(uint64(rec.TcpFlags), 10))
		req.Header.Set("X-TLS-Tcp-Data-Offset-Resv", strconv.FormatUint(uint64(rec.TcpDataOffsetResv), 10))
		req.Header.Set("X-TLS-Tcp-Urg-Ptr", strconv.FormatUint(uint64(rec.TcpUrgPtr), 10))
		req.Header.Set("X-TLS-Ip-Ident", strconv.FormatUint(uint64(rec.IpIdent), 10))
		req.Header.Set("X-TLS-Ip-Total-Len", strconv.FormatUint(uint64(rec.IpTotalLen), 10))
		req.Header.Set("X-TLS-Ip-Frag-Flags", strconv.FormatUint(uint64(rec.IpFragFlags), 10))
		req.Header.Set("X-TLS-Ip-Tos", strconv.FormatUint(uint64(rec.IpTos), 10))

		// Gated on the presence bit rather than on the value. A TSval of
		// exactly 0 is legal — a machine in its first tick after boot —
		// and TSecr is *expected* to be 0 on a SYN, so zero cannot stand
		// for absent.
		if rec.HasOption(OptTimestamps) {
			req.Header.Set("X-TLS-Tcp-Tsval", strconv.FormatUint(uint64(rec.TcpTsval), 10))
			req.Header.Set("X-TLS-Tcp-Tsecr", strconv.FormatUint(uint64(rec.TcpTsecr), 10))
		}
	}

	h.log.Debug("Added TCP handshake headers",
		zap.String("addr", req.RemoteAddr),
		zap.Uint8("observed_ttl", rec.ObservedTtl),
		zap.Uint16("tcp_mss", rec.TcpMss),
		zap.Uint8("tcp_wscale", rec.TcpWscale),
		zap.Uint16("tcp_opts_present", rec.TcpOptsPresent),
		zap.Uint8("tcp_opts_count", rec.TcpOptsCount),
		zap.Bool("legacy_record", rec.Legacy),
	)
}

// recordSizeMismatchLogInterval throttles the mismatch error. The
// condition is per-deployment, not per-request, so without a throttle one
// skewed sidecar would emit a line on every request on the node and bury
// everything else in the log. One a minute keeps it continuously visible
// to whoever looks — including someone who looks an hour later — without
// that.
const recordSizeMismatchLogInterval = time.Minute

// logRecordSizeMismatch reports a sidecar whose record is not the size
// this build parses. At error, because it means the two are at different
// versions and nothing will fix itself: until they match, every lookup on
// this node is dropped and the TCP columns go empty. Empty is the
// intended outcome — the alternative, which this replaced, was parsing
// the old offsets out of the new layout and writing plausible-looking
// wrong integers.
func (h *ClientHelloHandler) logRecordSizeMismatch(err error) {
	now := time.Now().UnixNano()
	last := h.lastSizeMismatchLog.Load()
	if now-last < int64(recordSizeMismatchLogInterval) {
		return
	}
	if !h.lastSizeMismatchLog.CompareAndSwap(last, now) {
		return
	}
	h.log.Error("TCP probe record layout mismatch — dropping all handshake headers; "+
		"chaddy and the tcp-probe sidecar must be deployed as a pair",
		zap.Error(err))
}

// Interface guards
var (
	_ caddy.Provisioner           = (*ClientHelloHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*ClientHelloHandler)(nil)
	_ caddyfile.Unmarshaler       = (*ClientHelloHandler)(nil)
)
