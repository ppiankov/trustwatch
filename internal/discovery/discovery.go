package discovery

import (
	"context"

	"github.com/ppiankov/trustwatch/internal/store"
)

// Discoverer finds TLS targets from a specific source.
type Discoverer interface {
	Name() string
	Discover(ctx context.Context) ([]store.CertFinding, error)
}
