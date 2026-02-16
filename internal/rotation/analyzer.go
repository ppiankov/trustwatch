// Package rotation detects excessive certificate rotation frequencies.
package rotation

import (
	"fmt"
	"strings"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

// FindingExcessiveRotation indicates a certificate with a shorter lifetime than recommended for its role.
const FindingExcessiveRotation = "EXCESSIVE_ROTATION"

// CertRole classifies a certificate's role in a trust hierarchy.
type CertRole string

// Certificate roles in a trust hierarchy.
const (
	RoleTrustAnchor  CertRole = "trust_anchor"
	RoleIntermediate CertRole = "intermediate_ca"
	RoleLeaf         CertRole = "leaf"
)

// Minimum recommended durations per role.
const (
	MinTrustAnchorDuration  = 365 * 24 * time.Hour // 1 year
	MinIntermediateDuration = 30 * 24 * time.Hour  // 30 days
)

// DetectRole determines the certificate's role from finding metadata.
func DetectRole(f *store.CertFinding) CertRole {
	notes := strings.ToLower(f.Notes)
	if f.SelfSigned || strings.Contains(notes, "trust anchor") {
		return RoleTrustAnchor
	}
	if f.IsCA || strings.Contains(notes, "identity issuer") {
		return RoleIntermediate
	}
	return RoleLeaf
}

// Check analyzes findings for excessive rotation and returns new EXCESSIVE_ROTATION findings.
func Check(findings []store.CertFinding) []store.CertFinding {
	var results []store.CertFinding
	for i := range findings {
		f := &findings[i]
		if f.CertDuration <= 0 {
			continue
		}

		role := DetectRole(f)
		var minDur time.Duration
		switch role {
		case RoleTrustAnchor:
			minDur = MinTrustAnchorDuration
		case RoleIntermediate:
			minDur = MinIntermediateDuration
		case RoleLeaf:
			continue // no minimum for leaf certs
		}

		if f.CertDuration < minDur {
			results = append(results, store.CertFinding{
				Source:      f.Source,
				Severity:    store.SeverityWarn,
				FindingType: FindingExcessiveRotation,
				Name:        f.Name,
				Namespace:   f.Namespace,
				Notes:       fmt.Sprintf("duration %s below minimum %s for %s", f.CertDuration, minDur, role),
			})
		}
	}
	return results
}
