package caddy_clienthello

import (
	"sync"

	"github.com/caddyserver/caddy/v2"
)

const (
	CacheAppId = "client_hello.cache"
)

func init() {
	caddy.RegisterModule(Cache{})
}

type Cache struct {
	clientHellos map[string]string
	lock         sync.RWMutex
}

func (c *Cache) Provision(_ caddy.Context) error {
	c.clientHellos = make(map[string]string)
	return nil
}

func (c *Cache) SetClientHello(addr string, encoded string) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.clientHellos[addr] = encoded
	return nil
}

func (c *Cache) ClearClientHello(addr string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	delete(c.clientHellos, addr)
}

func (c *Cache) GetClientHello(addr string) *string {
	c.lock.RLock()
	defer c.lock.RUnlock()

	if data, found := c.clientHellos[addr]; found {
		return &data
	} else {
		return nil
	}
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
