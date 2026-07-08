package caddy_clienthello

import (
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

const (
	CacheAppId = "client_hello.cache"
)

func init() {
	caddy.RegisterModule(Cache{})
}

type CacheEntry struct {
	Value string
}

// TimingEntry records the two moments needed to compute the per-connection
// tcp_to_chello_us and chello_to_handshake_us deltas. Keyed by remote addr
// (unique per TCP connection) so ServeHTTP can look them up on the first
// request.
type TimingEntry struct {
	ConnectionStart     time.Time // when listener.Accept() returned
	ClientHelloReceived time.Time // when the CH bytes were fully peeked
}

type Cache struct {
	clientHellos map[string]CacheEntry
	timings      map[string]TimingEntry
	lock         sync.RWMutex
	logger *zap.Logger
}

func (c *Cache) Provision(ctx caddy.Context) error {
	c.clientHellos = make(map[string]CacheEntry)
	c.timings = make(map[string]TimingEntry)
	c.logger = ctx.Logger(c)
	return nil
}

func (c *Cache) SetClientHello(addr string, encoded string) {
	c.logger.Debug("SetClientHello", zap.String("addr", addr), zap.String("encoded", encoded))
	c.lock.Lock()
	defer c.lock.Unlock()

	c.clientHellos[addr] = CacheEntry{
        Value:      encoded,
    }

	c.logger.Info("cache size", zap.Int("size", len(c.clientHellos)))
}

func (c *Cache) ClearClientHello(addr string) {
	c.logger.Debug("ClearClientHello", zap.String("addr", addr))
	c.lock.Lock()
	defer c.lock.Unlock()
	delete(c.clientHellos, addr)
	delete(c.timings, addr)
	c.logger.Info("cache size", zap.Int("size", len(c.clientHellos)))
}

// SetTiming records the (connection_start, client_hello_received) pair
// for a connection, keyed by remote addr so ServeHTTP can look them up
// on the first request over that TCP connection.
func (c *Cache) SetTiming(addr string, start time.Time, chelloReceived time.Time) {
	c.logger.Debug("SetTiming", zap.String("addr", addr))
	c.lock.Lock()
	defer c.lock.Unlock()
	c.timings[addr] = TimingEntry{
		ConnectionStart:     start,
		ClientHelloReceived: chelloReceived,
	}
}

// GetTiming returns the timing entry for a connection, or nil if none
// is cached (e.g. connection wasn't a TLS handshake, or was already
// cleared on close).
func (c *Cache) GetTiming(addr string) *TimingEntry {
	c.logger.Debug("GetTiming", zap.String("addr", addr))
	c.lock.RLock()
	defer c.lock.RUnlock()
	entry, found := c.timings[addr]
	if !found {
		return nil
	}
	return &entry
}

func (c *Cache) GetClientHello(addr string) *string {
	c.logger.Debug("GetClientHello", zap.String("addr", addr))
	c.lock.RLock()
	defer c.lock.RUnlock()
    entry, found := c.clientHellos[addr]

    if !found {
        return nil // Entry doesn't exist
    }

	return &entry.Value
}

// CaddyModule implements caddy.Module
func (Cache) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  CacheAppId,
		New: func() caddy.Module { return new(Cache) },
	}
}

// Start implements caddy.App
func (c *Cache) Start() error {
	return nil
}

// Stop implements caddy.App
func (c *Cache) Stop() error {
	return nil
}

// Interface guards
var (
	_ caddy.App         = (*Cache)(nil)
	_ caddy.Provisioner = (*Cache)(nil)
)
