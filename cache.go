package caddy_clienthello

import (
	"sync"
	"github.com/caddyserver/caddy/v2"
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

const MaxCacheSize = 1000 // Maximum number of entries in the cache

type CacheEntry struct {
    Value      string
    Expiration int64
}

type Cache struct {
	clientHellos map[string]CacheEntry
	lock         sync.RWMutex
	logger *zap.Logger
}

func (c *Cache) Provision(ctx caddy.Context) error {
	c.clientHellos = make(map[string]CacheEntry)
	c.logger = ctx.Logger(c)
	return nil
}

func (c *Cache) SetClientHello(addr string, encoded string) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	// Set an expiration time for the cache (e.g., 1 hour)
    expiration := time.Now().Add(1 * time.Hour).Unix()

	// Check cache size and evict if needed
    if len(c.clientHellos) >= MaxCacheSize {
        // Eviction strategy (e.g., remove the first element or an LRU item)
        for key := range c.clientHellos {
            delete(c.clientHellos, key)
            break
        }
    }

	c.clientHellos[addr] = CacheEntry{
        Value:      encoded,
        Expiration: expiration,
    }

	return nil
}

func (c *Cache) ClearClientHello(addr string) {
	c.logger.Debug("ClearClientHello", zap.String("addr", addr))
	c.lock.Lock()
	defer c.lock.Unlock()
	delete(c.clientHellos, addr)
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
