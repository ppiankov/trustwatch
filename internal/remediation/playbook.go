// Package remediation maps finding types to actionable fix suggestions.
package remediation

import (
	"github.com/ppiankov/trustwatch/internal/store"
)

// Lookup returns a remediation string for the given finding, or empty if none applies.
func Lookup(f *store.CertFinding) string {
	// FindingType-based lookups take priority
	if f.FindingType != "" {
		if r, ok := findingTypePlaybook[f.FindingType]; ok {
			return r
		}
	}

	// Revocation issues
	if len(f.RevocationIssues) > 0 {
		return "Check certificate revocation status. If revoked, reissue immediately and rotate all dependents."
	}

	// Chain errors
	if len(f.ChainErrors) > 0 {
		return "Fix the certificate chain: ensure intermediates are present and correctly ordered in the TLS secret or server config."
	}

	// Posture issues
	if len(f.PostureIssues) > 0 {
		return "Upgrade TLS configuration: disable TLS <1.2, remove weak ciphers (RC4, 3DES, NULL), and enable TLS 1.3 where possible."
	}

	// Probe failure
	if !f.ProbeOK && f.ProbeErr != "" {
		return "Investigate probe failure: check that the service is running, the port is correct, and TLS is configured."
	}

	// Severity-based expiry remediation
	switch f.Severity {
	case store.SeverityCritical:
		return "Certificate is expired or expiring imminently. Renew or rotate the certificate now."
	case store.SeverityWarn:
		return "Certificate is approaching expiry. Schedule renewal before the warning threshold."
	}

	return ""
}

// Apply populates the Remediation field on all findings in the slice.
func Apply(findings []store.CertFinding) {
	for i := range findings {
		if findings[i].Remediation == "" {
			findings[i].Remediation = Lookup(&findings[i])
		}
	}
}

var findingTypePlaybook = map[string]string{
	"MANAGED_EXPIRY": "Certificate is managed by cert-manager with healthy renewal. No action required.",

	"RENEWAL_STALLED": "cert-manager CertificateRequest is stuck. Check cert-manager logs, " +
		"issuer configuration, and RBAC. Run: kubectl describe certificaterequest -n <namespace>",

	"CHALLENGE_FAILED": "ACME challenge failed. Check DNS records, HTTP reachability, " +
		"and issuer account credentials. Run: kubectl describe challenge -n <namespace>",

	"REQUEST_PENDING": "cert-manager Certificate is not ready. Check the Certificate status " +
		"and issuer health. Run: kubectl describe certificate <name> -n <namespace>",

	"EXCESSIVE_ROTATION": "Certificate lifetime is shorter than recommended for its role. " +
		"Increase spec.duration in the cert-manager Certificate CR to reduce rotation frequency.",

	"CT_UNKNOWN_CERT": "Certificate found in CT logs but not in cluster inventory. " +
		"Investigate whether this is a legitimate cert issued outside the cluster or a potential compromise.",

	"CT_ROGUE_ISSUER": "Certificate in CT logs was issued by an unexpected CA. " +
		"Verify the issuing CA is authorized. If not, revoke the certificate and investigate the CA compromise.",

	"POLICY_VIOLATION": "Certificate violates a TrustPolicy rule. Review the policy " +
		"and update the certificate to comply (e.g., increase key size, switch issuer, remove self-signed).",
}
