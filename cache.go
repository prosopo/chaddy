package caddy_clienthello

import (
	"sync"

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
	c.logger.Debug("SetClientHello", zap.String("addr", addr), zap.String("encoded", encoded))
	c.lock.Lock()
	defer c.lock.Unlock()

	c.clientHellos[addr] = CacheEntry{
        Value:      encoded,
    }

	c.logger.Info("cache size", zap.Int("size", len(c.clientHellos)))
	
	return nil
}

func (c *Cache) ClearClientHello(addr string) {
	c.logger.Debug("ClearClientHello", zap.String("addr", addr))
	c.lock.Lock()
	defer c.lock.Unlock()
	delete(c.clientHellos, addr)
	c.logger.Info("cache size", zap.Int("size", len(c.clientHellos)))
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
