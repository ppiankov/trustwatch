package revocation

import (
	"crypto/x509"
	"sync"
	"time"
)

// CRLCache is an in-memory cache for CRL data keyed by distribution point URL.
type CRLCache struct {
	entries map[string]crlEntry
	mu      sync.RWMutex
}

type crlEntry struct {
	crl       *x509.RevocationList
	expiresAt time.Time
}

// NewCRLCache creates an empty CRL cache.
func NewCRLCache() *CRLCache {
	return &CRLCache{entries: make(map[string]crlEntry)}
}

// Get returns a cached CRL for the URL, or nil if missing/expired.
func (c *CRLCache) Get(url string) *x509.RevocationList {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[url]
	if !ok || time.Now().After(e.expiresAt) {
		return nil
	}
	return e.crl
}

// Set stores a CRL in the cache, using its NextUpdate as expiry.
func (c *CRLCache) Set(url string, crl *x509.RevocationList) {
	expires := crl.NextUpdate
	if expires.IsZero() {
		expires = time.Now().Add(1 * time.Hour)
	}
	c.mu.Lock()
	c.entries[url] = crlEntry{crl: crl, expiresAt: expires}
	c.mu.Unlock()
}
