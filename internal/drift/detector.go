// Package drift detects unexpected certificate changes between consecutive snapshots.
package drift

import (
	"fmt"

	"github.com/ppiankov/trustwatch/internal/store"
)

// Drift finding types.
const (
	FindingCertNew       = "CERT_NEW"
	FindingCertGone      = "CERT_GONE"
	FindingSerialChanged = "SERIAL_CHANGED"
	FindingIssuerChanged = "ISSUER_CHANGED"
)

// certIdentity holds the fields compared for drift detection.
type certIdentity struct {
	Serial string
	Issuer string
}

// Detect compares previous and current findings and returns drift findings.
// Findings are matched by (source, namespace, name) composite key.
func Detect(prev, curr []store.CertFinding) []store.CertFinding {
	prevMap := indexFindings(prev)
	currMap := indexFindings(curr)

	var driftFindings []store.CertFinding

	// Check for new certs and changes
	for key, ci := range currMap {
		pi, existed := prevMap[key]
		if !existed {
			driftFindings = append(driftFindings, store.CertFinding{
				Source:      ci.source,
				Namespace:   ci.namespace,
				Name:        ci.name,
				Severity:    store.SeverityInfo,
				FindingType: FindingCertNew,
				Notes:       fmt.Sprintf("certificate appeared (serial=%s)", ci.id.Serial),
				ProbeOK:     true,
			})
			continue
		}

		// Check serial change
		if pi.id.Serial != "" && ci.id.Serial != "" && pi.id.Serial != ci.id.Serial {
			driftFindings = append(driftFindings, store.CertFinding{
				Source:      ci.source,
				Namespace:   ci.namespace,
				Name:        ci.name,
				Severity:    store.SeverityInfo,
				FindingType: FindingSerialChanged,
				Notes:       fmt.Sprintf("serial changed from %s to %s", pi.id.Serial, ci.id.Serial),
				ProbeOK:     true,
			})
		}

		// Check issuer change
		if pi.id.Issuer != "" && ci.id.Issuer != "" && pi.id.Issuer != ci.id.Issuer {
			driftFindings = append(driftFindings, store.CertFinding{
				Source:      ci.source,
				Namespace:   ci.namespace,
				Name:        ci.name,
				Severity:    store.SeverityWarn,
				FindingType: FindingIssuerChanged,
				Notes:       fmt.Sprintf("issuer changed from %s to %s", pi.id.Issuer, ci.id.Issuer),
				ProbeOK:     true,
			})
		}
	}

	// Check for disappeared certs
	for key, pi := range prevMap {
		if _, exists := currMap[key]; !exists {
			driftFindings = append(driftFindings, store.CertFinding{
				Source:      pi.source,
				Namespace:   pi.namespace,
				Name:        pi.name,
				Severity:    store.SeverityWarn,
				FindingType: FindingCertGone,
				Notes:       fmt.Sprintf("certificate disappeared (was serial=%s)", pi.id.Serial),
				ProbeOK:     true,
			})
		}
	}

	return driftFindings
}

type indexedFinding struct {
	id        certIdentity
	source    store.SourceKind
	namespace string
	name      string
}

func findingKey(f *store.CertFinding) string {
	return fmt.Sprintf("%s/%s/%s", f.Source, f.Namespace, f.Name)
}

func indexFindings(findings []store.CertFinding) map[string]indexedFinding {
	m := make(map[string]indexedFinding, len(findings))
	for i := range findings {
		f := &findings[i]
		// Skip probe failures — they don't represent meaningful certificate state
		if !f.ProbeOK {
			continue
		}
		key := findingKey(f)
		m[key] = indexedFinding{
			source:    f.Source,
			namespace: f.Namespace,
			name:      f.Name,
			id: certIdentity{
				Serial: f.Serial,
				Issuer: f.Issuer,
			},
		}
	}
	return m
}
