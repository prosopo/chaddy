package caddy_clienthello

import (
	"github.com/caddyserver/caddy/v2"
	"sync"
	"time"
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
}

func (c *Cache) Provision(_ caddy.Context) error {
	c.clientHellos = make(map[string]CacheEntry)
	return nil
}

func (c *Cache) SetClientHello(cacheKey string, encoded string) error {
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

	c.clientHellos[cacheKey] = CacheEntry{
		Value:      encoded,
		Expiration: expiration,
	}

	return nil
}

func (c *Cache) ClearClientHello(sessionID string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	delete(c.clientHellos, sessionID)
}

func (c *Cache) GetClientHello(cacheKey string) *string {
	c.lock.RLock()
	defer c.lock.RUnlock()

	entry, found := c.clientHellos[cacheKey]
	if !found {
		return nil // Entry doesn't exist
	}

	if entry.Expiration < time.Now().Unix() {
		c.ClearClientHello(cacheKey)
		return nil // Entry expired
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
