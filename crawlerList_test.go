package caddy_clienthello

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

const testList = `# comment line
!claude-user          # 162
!google-agent         # 930

meta-externalagent    # 278,045
Baiduspider
hubspot crawler
dataprovider.com
claudebot
crawler
bot/

116.179.32.0/20       # Baidu crawling with a Chrome UA
2001:db8::/32
`

func loadTestList(t *testing.T, content string) *CrawlerList {
	t.Helper()
	path := filepath.Join(t.TempDir(), "crawlers.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &CrawlerList{File: path}
	if err := m.load(zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCrawlerListMatches(t *testing.T) {
	m := loadTestList(t, testList)
	cases := []struct {
		name      string
		ua        string
		remote    string
		signature string
		want      bool
	}{
		{"meta crawler", "Mozilla/5.0 (compatible; meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler))", "203.0.113.9:443", "", true},
		{"matching ignores case", "Mozilla/5.0 (compatible; Meta-ExternalAgent/1.1)", "203.0.113.9:443", "", true},
		{"pattern written in mixed case", "Mozilla/5.0 (compatible; baiduspider-render/2.0)", "203.0.113.9:443", "", true},
		{"pattern with a space", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; HubSpot Crawler; +https://www.hubspot.com)", "203.0.113.9:443", "", true},
		{"dot is literal", "Mozilla/5.0 (compatible; Dataprovider.com)", "203.0.113.9:443", "", true},
		{"dot is not a wildcard", "Mozilla/5.0 (compatible; dataproviderXcom)", "203.0.113.9:443", "", false},
		{"catch-all bot slash", "ArbeteoBot/0.2 (+https://arbeteo.com/bot)", "203.0.113.9:443", "", true},
		{"desktop chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36", "203.0.113.9:443", "", false},
		{"cubot phone is not a bot", "Mozilla/5.0 (Linux; Android 14; KINGKONG_AX; wv) Instagram 452.1.0.53.64 Android (34/14; CUBOT; KINGKONG_AX)", "203.0.113.9:443", "", false},
		{"no user agent", "", "203.0.113.9:443", "", false},
		{"allowed agent containing a blocked word", "Mozilla/5.0 (compatible; Claude-User/1.0; +claudebot@anthropic.com)", "203.0.113.9:443", "", false},
		{"allowed agent containing catch-all", "Mozilla/5.0 (compatible; Google-Agent; +https://developers.google.com/crawling/docs/crawlers-fetchers/google-agent)", "203.0.113.9:443", "", false},
		{"signed crawler goes to the provider", "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html) crawler", "203.0.113.9:443", `"https://bot.duckduckgo.com"`, false},
		{"browser UA from a listed range", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/99.0.4844.51 Safari/537.36", "116.179.37.2:51234", "", true},
		{"just outside the listed range", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/99.0.4844.51 Safari/537.36", "116.179.48.1:51234", "", false},
		{"ipv4-mapped address from a dual-stack listener", "Mozilla/5.0 Chrome/99.0.4844.51", "[::ffff:116.179.37.2]:51234", "", true},
		{"ipv6 range","Mozilla/5.0 Chrome/145.0.0.0", "[2001:db8::7]:443", "", true},
		{"signed request from a listed range", "Mozilla/5.0 Chrome/145.0.0.0", "116.179.37.2:51234", `"https://chatgpt.com"`, false},
		{"allowed agent from a listed range", "Mozilla/5.0 (compatible; Claude-User/1.0)", "116.179.37.2:51234", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/v1/prosopo/provider/client/captcha/frictionless", nil)
			r.RemoteAddr = c.remote
			if c.ua != "" {
				r.Header.Set("User-Agent", c.ua)
			}
			if c.signature != "" {
				r.Header.Set("Signature-Agent", c.signature)
			}
			if got := m.Match(r); got != c.want {
				t.Fatalf("Match = %v, want %v", got, c.want)
			}
		})
	}
}

func TestCrawlerListMissingFileMatchesNothing(t *testing.T) {
	m := &CrawlerList{File: filepath.Join(t.TempDir(), "absent.txt")}
	if err := m.load(zap.NewNop()); err != nil {
		t.Fatalf("a missing list must not stop Caddy starting: %v", err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "meta-externalagent/1.1")
	if m.Match(r) {
		t.Fatal("a missing list matched a request")
	}
}

func TestCrawlerListEmptyFileMatchesNothing(t *testing.T) {
	m := loadTestList(t, "# only comments\n\n")
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/145.0.0.0")
	if m.Match(r) {
		t.Fatal("an empty list matched a request")
	}
}

func TestCrawlerListRejectsAMalformedRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crawlers.txt")
	if err := os.WriteFile(path, []byte("116.179.32.0/40\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &CrawlerList{File: path}
	if err := m.load(zap.NewNop()); err == nil {
		t.Fatal("a /40 IPv4 range loaded without error")
	}
}

func BenchmarkCrawlerListBrowser(b *testing.B) {
	path := filepath.Join(b.TempDir(), "crawlers.txt")
	if err := os.WriteFile(path, []byte(testList), 0o600); err != nil {
		b.Fatal(err)
	}
	m := &CrawlerList{File: path}
	if err := m.load(zap.NewNop()); err != nil {
		b.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "203.0.113.9:443"
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36")
	for i := 0; i < b.N; i++ {
		m.Match(r)
	}
}
