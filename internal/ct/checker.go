package ct

import (
	"strings"

	"github.com/ppiankov/trustwatch/internal/store"
)

const (
	// FindingCTUnknown indicates a certificate in CT logs not found in the cluster.
	FindingCTUnknown = "CT_UNKNOWN_CERT"
	// FindingCTRogue indicates a certificate issued by an unexpected CA.
	FindingCTRogue = "CT_ROGUE_ISSUER"
)

// Check compares CT log entries against known cluster serials and allowed issuers.
// Returns findings for unknown certs and rogue issuers.
func Check(entries []Entry, knownSerials map[string]bool, allowedIssuers []string) []store.CertFinding {
	var findings []store.CertFinding

	for i := range entries {
		e := &entries[i]

		unknown := !knownSerials[e.SerialNumber]
		rogue := len(allowedIssuers) > 0 && !matchesAnyIssuer(e.IssuerName, allowedIssuers)

		if unknown {
			findings = append(findings, entryToFinding(e, FindingCTUnknown, store.SeverityWarn,
				"certificate in CT log not found in cluster"))
		}
		if rogue {
			findings = append(findings, entryToFinding(e, FindingCTRogue, store.SeverityCritical,
				"certificate issued by unexpected CA: "+e.IssuerName))
		}
	}

	return findings
}

func entryToFinding(e *Entry, findingType string, sev store.Severity, notes string) store.CertFinding {
	f := store.CertFinding{
		Source:      store.SourceCT,
		FindingType: findingType,
		Severity:    sev,
		Subject:     e.CommonName,
		Issuer:      e.IssuerName,
		Serial:      e.SerialNumber,
		Notes:       notes,
		ProbeOK:     true,
	}
	if e.NameValue != "" {
		f.DNSNames = strings.Split(e.NameValue, "\n")
	}
	return f
}

func matchesAnyIssuer(issuer string, allowed []string) bool {
	lower := strings.ToLower(issuer)
	for _, a := range allowed {
		if strings.Contains(lower, strings.ToLower(a)) {
			return true
		}
	}
	return false
}
