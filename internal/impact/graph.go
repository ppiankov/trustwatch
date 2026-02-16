// Package impact provides rotation impact analysis for certificate chains.
package impact

import (
	"strings"

	"github.com/ppiankov/trustwatch/internal/store"
)

// Graph indexes findings by issuer, subject, and serial for fast lookups.
type Graph struct {
	issuerIndex  map[string][]int
	subjectIndex map[string][]int
	serialIndex  map[string][]int
	findings     []store.CertFinding
}

// Build creates an impact graph from a set of findings.
func Build(findings []store.CertFinding) *Graph {
	g := &Graph{
		issuerIndex:  make(map[string][]int),
		subjectIndex: make(map[string][]int),
		serialIndex:  make(map[string][]int),
		findings:     findings,
	}

	for i := range findings {
		f := &findings[i]
		// Index by direct issuer
		if f.Issuer != "" {
			key := strings.ToLower(f.Issuer)
			g.issuerIndex[key] = append(g.issuerIndex[key], i)
		}
		// Index by each entry in the issuer chain (transitive issuers)
		for _, dn := range f.IssuerChain {
			key := strings.ToLower(dn)
			g.issuerIndex[key] = append(g.issuerIndex[key], i)
		}
		// Index by subject
		if f.Subject != "" {
			key := strings.ToLower(f.Subject)
			g.subjectIndex[key] = append(g.subjectIndex[key], i)
		}
		// Index by serial
		if f.Serial != "" {
			g.serialIndex[f.Serial] = append(g.serialIndex[f.Serial], i)
		}
	}

	return g
}
