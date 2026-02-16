package revocation

import (
	"crypto/x509"
	"fmt"
)

// Revocation status constants.
const (
	StatusRevoked       = "revoked"
	StatusUnreachable   = "unreachable"
	StatusStapleInvalid = "staple_invalid"
	StatusCRLStale      = "crl_stale"
)

// Result holds the outcome of a revocation check.
type Result struct {
	Status string
	Detail string
}

// Check runs OCSP and CRL checking on a certificate.
// Returns human-readable issue strings (parallel to PostureIssues/ChainErrors).
func Check(cert, issuer *x509.Certificate, ocspStaple []byte, cache *CRLCache) []string {
	if cert == nil {
		return nil
	}

	var issues []string

	// OCSP check (requires issuer)
	if issuer != nil {
		if r := CheckOCSP(cert, issuer, ocspStaple); r != nil {
			issues = append(issues, formatIssue(r))
		}
	}

	// CRL check
	if cache != nil {
		if r := CheckCRL(cert, cache); r != nil {
			issues = append(issues, formatIssue(r))
		}
	}

	return issues
}

func formatIssue(r *Result) string {
	tag := ""
	switch r.Status {
	case StatusRevoked:
		tag = "CERT_REVOKED"
	case StatusUnreachable:
		tag = "OCSP_UNREACHABLE"
	case StatusStapleInvalid:
		tag = "OCSP_STAPLE_INVALID"
	case StatusCRLStale:
		tag = "CRL_STALE"
	default:
		tag = "REVOCATION_UNKNOWN"
	}
	return fmt.Sprintf("%s: %s", tag, r.Detail)
}
