package impact

import (
	"sort"
	"strings"

	"github.com/ppiankov/trustwatch/internal/store"
)

// QueryResult holds the blast radius of a rotation impact query.
type QueryResult struct {
	BySeverity     map[store.Severity]int   `json:"bySeverity"`
	BySource       map[store.SourceKind]int `json:"bySource"`
	MatchedPattern string                   `json:"matchedPattern"`
	Findings       []store.CertFinding      `json:"findings"`
	Namespaces     []string                 `json:"namespaces"`
	Clusters       []string                 `json:"clusters"`
}

// QueryIssuer finds all findings where Issuer or any IssuerChain entry
// contains the pattern (case-insensitive substring match).
func (g *Graph) QueryIssuer(pattern string) QueryResult {
	pat := strings.ToLower(pattern)
	seen := make(map[int]bool)

	for key, indices := range g.issuerIndex {
		if strings.Contains(key, pat) {
			for _, idx := range indices {
				seen[idx] = true
			}
		}
	}

	return g.buildResult(pattern, seen)
}

// QuerySerial finds findings with an exact serial number match.
func (g *Graph) QuerySerial(serial string) QueryResult {
	seen := make(map[int]bool)
	if indices, ok := g.serialIndex[serial]; ok {
		for _, idx := range indices {
			seen[idx] = true
		}
	}
	return g.buildResult(serial, seen)
}

// QuerySubject finds all findings where Subject contains the pattern
// (case-insensitive substring match).
func (g *Graph) QuerySubject(pattern string) QueryResult {
	pat := strings.ToLower(pattern)
	seen := make(map[int]bool)

	for key, indices := range g.subjectIndex {
		if strings.Contains(key, pat) {
			for _, idx := range indices {
				seen[idx] = true
			}
		}
	}

	return g.buildResult(pattern, seen)
}

func (g *Graph) buildResult(pattern string, indices map[int]bool) QueryResult {
	qr := QueryResult{
		MatchedPattern: pattern,
		BySeverity:     make(map[store.Severity]int),
		BySource:       make(map[store.SourceKind]int),
	}

	nsSet := make(map[string]bool)
	clusterSet := make(map[string]bool)

	for idx := range indices {
		f := g.findings[idx]
		qr.Findings = append(qr.Findings, f)
		if f.Severity != "" {
			qr.BySeverity[f.Severity]++
		}
		if f.Source != "" {
			qr.BySource[f.Source]++
		}
		if f.Namespace != "" {
			nsSet[f.Namespace] = true
		}
		if f.Cluster != "" {
			clusterSet[f.Cluster] = true
		}
	}

	for ns := range nsSet {
		qr.Namespaces = append(qr.Namespaces, ns)
	}
	sort.Strings(qr.Namespaces)

	for cl := range clusterSet {
		qr.Clusters = append(qr.Clusters, cl)
	}
	sort.Strings(qr.Clusters)

	return qr
}
