package caddy_clienthello

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CrawlerList{})
}

// CrawlerList matches requests from crawlers named in a list file, so they can
// be turned away before they cost the upstream any work.
//
// One entry per line; `#` starts a comment. An entry is either a CIDR range
// matched against the client address, or a substring matched case-insensitively
// against the User-Agent. Entries starting with `!` are user-agent substrings
// that are never matched, for agents acting for a person whose UAs contain a
// listed word. A request carrying a Signature-Agent header (Web Bot Auth) is
// never matched, so the upstream can verify it.
//
// The file is read when the config loads, so `caddy reload` picks up edits. A
// missing file matches nothing rather than stopping Caddy from starting.
type CrawlerList struct {
	File string `json:"file,omitempty"`

	blocked []string
	allowed []string
	ranges  []netip.Prefix
}

var cidrShape = regexp.MustCompile(`^[0-9a-fA-F:.]+/[0-9]+$`)

func (CrawlerList) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.crawler_list",
		New: func() caddy.Module { return new(CrawlerList) },
	}
}

func (m *CrawlerList) Provision(ctx caddy.Context) error {
	return m.load(ctx.Logger(m))
}

func (m *CrawlerList) load(log *zap.Logger) error {
	f, err := os.Open(m.File)
	if errors.Is(err, fs.ErrNotExist) {
		log.Warn("crawler list file not found, matching nothing", zap.String("file", m.File))
		return nil
	}
	if err != nil {
		return fmt.Errorf("crawler_list: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for n := 1; scanner.Scan(); n++ {
		entry, _, _ := strings.Cut(scanner.Text(), "#")
		entry = strings.ToLower(strings.TrimSpace(entry))
		switch {
		case entry == "":
		case strings.HasPrefix(entry, "!"):
			if allowed := strings.TrimSpace(entry[1:]); allowed != "" {
				m.allowed = append(m.allowed, allowed)
			}
		case cidrShape.MatchString(entry):
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return fmt.Errorf("crawler_list: %s line %d: %w", m.File, n, err)
			}
			m.ranges = append(m.ranges, prefix.Masked())
		default:
			m.blocked = append(m.blocked, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("crawler_list: %w", err)
	}
	log.Info("crawler list loaded",
		zap.String("file", m.File),
		zap.Int("user_agents", len(m.blocked)),
		zap.Int("allowed_user_agents", len(m.allowed)),
		zap.Int("ranges", len(m.ranges)))
	return nil
}

func (m *CrawlerList) Match(r *http.Request) bool {
	if r.Header.Get("Signature-Agent") != "" {
		return false
	}
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	for _, allowed := range m.allowed {
		if strings.Contains(ua, allowed) {
			return false
		}
	}
	if m.fromListedRange(r) {
		return true
	}
	for _, blocked := range m.blocked {
		if strings.Contains(ua, blocked) {
			return true
		}
	}
	return false
}

// fromListedRange reads the peer address the same way Caddy's remote_ip
// matcher does; behind the layer4 router that is the PROXY-protocol client.
func (m *CrawlerList) fromListedRange(r *http.Request) bool {
	if len(m.ranges) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range m.ranges {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// UnmarshalCaddyfile parses `crawler_list <file>`.
func (m *CrawlerList) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if !d.NextArg() {
		return d.ArgErr()
	}
	m.File = d.Val()
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

var (
	_ caddy.Provisioner        = (*CrawlerList)(nil)
	_ caddyhttp.RequestMatcher = (*CrawlerList)(nil)
	_ caddyfile.Unmarshaler    = (*CrawlerList)(nil)
)
