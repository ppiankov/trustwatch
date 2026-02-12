package discovery

import "github.com/ppiankov/trustwatch/internal/store"

// Discoverer finds TLS targets from a specific source.
type Discoverer interface {
	// Name returns a human-readable label for this discoverer.
	Name() string

	// Discover returns findings from this source.
	// Errors are reported as findings with ProbeOK=false rather than
	// aborting the entire discovery run.
	Discover() ([]store.CertFinding, error)
}
