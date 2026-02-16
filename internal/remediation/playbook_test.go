package remediation

import (
	"testing"

	"github.com/ppiankov/trustwatch/internal/store"
)

func TestLookup_FindingType(t *testing.T) {
	tests := []struct {
		name        string
		findingType string
		wantPrefix  string
	}{
		{"managed expiry", "MANAGED_EXPIRY", "Certificate is managed by cert-manager"},
		{"renewal stalled", "RENEWAL_STALLED", "cert-manager CertificateRequest is stuck"},
		{"challenge failed", "CHALLENGE_FAILED", "ACME challenge failed"},
		{"request pending", "REQUEST_PENDING", "cert-manager Certificate is not ready"},
		{"excessive rotation", "EXCESSIVE_ROTATION", "Certificate lifetime is shorter"},
		{"ct unknown", "CT_UNKNOWN_CERT", "Certificate found in CT logs"},
		{"ct rogue", "CT_ROGUE_ISSUER", "Certificate in CT logs was issued by an unexpected CA"},
		{"policy violation", "POLICY_VIOLATION", "Certificate violates a TrustPolicy rule"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &store.CertFinding{FindingType: tt.findingType}
			got := Lookup(f)
			if got == "" {
				t.Errorf("expected remediation for %s, got empty", tt.findingType)
			}
			if len(got) < len(tt.wantPrefix) || got[:len(tt.wantPrefix)] != tt.wantPrefix {
				t.Errorf("expected prefix %q, got %q", tt.wantPrefix, got)
			}
		})
	}
}

func TestLookup_RevocationIssues(t *testing.T) {
	f := &store.CertFinding{
		RevocationIssues: []string{"CERT_REVOKED via CRL"},
		ProbeOK:          true,
	}
	got := Lookup(f)
	if got == "" {
		t.Error("expected remediation for revocation issues")
	}
}

func TestLookup_ChainErrors(t *testing.T) {
	f := &store.CertFinding{
		ChainErrors: []string{"missing intermediate"},
		ProbeOK:     true,
	}
	got := Lookup(f)
	if got == "" {
		t.Error("expected remediation for chain errors")
	}
}

func TestLookup_PostureIssues(t *testing.T) {
	f := &store.CertFinding{
		PostureIssues: []string{"WEAK_TLS_VERSION: TLS 1.0"},
		ProbeOK:       true,
	}
	got := Lookup(f)
	if got == "" {
		t.Error("expected remediation for posture issues")
	}
}

func TestLookup_ProbeFailure(t *testing.T) {
	f := &store.CertFinding{
		ProbeOK:  false,
		ProbeErr: "connection refused",
	}
	got := Lookup(f)
	if got == "" {
		t.Error("expected remediation for probe failure")
	}
}

func TestLookup_CriticalExpiry(t *testing.T) {
	f := &store.CertFinding{
		Severity: store.SeverityCritical,
		ProbeOK:  true,
	}
	got := Lookup(f)
	if got == "" {
		t.Error("expected remediation for critical expiry")
	}
}

func TestLookup_WarnExpiry(t *testing.T) {
	f := &store.CertFinding{
		Severity: store.SeverityWarn,
		ProbeOK:  true,
	}
	got := Lookup(f)
	if got == "" {
		t.Error("expected remediation for warn expiry")
	}
}

func TestLookup_InfoSeverity(t *testing.T) {
	f := &store.CertFinding{
		Severity: store.SeverityInfo,
		ProbeOK:  true,
	}
	got := Lookup(f)
	if got != "" {
		t.Errorf("expected no remediation for info severity, got %q", got)
	}
}

func TestLookup_UnknownFindingType(t *testing.T) {
	f := &store.CertFinding{
		FindingType: "SOME_FUTURE_TYPE",
		Severity:    store.SeverityWarn,
		ProbeOK:     true,
	}
	// Falls through to severity-based remediation
	got := Lookup(f)
	if got == "" {
		t.Error("expected fallback remediation for unknown finding type")
	}
}

func TestApply(t *testing.T) {
	findings := []store.CertFinding{
		{FindingType: "RENEWAL_STALLED", Severity: store.SeverityWarn, ProbeOK: true},
		{Severity: store.SeverityCritical, ProbeOK: true},
		{Severity: store.SeverityInfo, ProbeOK: true},
		{Severity: store.SeverityWarn, ProbeOK: true, Remediation: "custom"},
	}
	Apply(findings)

	if findings[0].Remediation == "" {
		t.Error("expected remediation for RENEWAL_STALLED")
	}
	if findings[1].Remediation == "" {
		t.Error("expected remediation for critical")
	}
	if findings[2].Remediation != "" {
		t.Errorf("expected no remediation for info, got %q", findings[2].Remediation)
	}
	if findings[3].Remediation != "custom" {
		t.Errorf("expected custom remediation preserved, got %q", findings[3].Remediation)
	}
}

func TestLookup_FindingTypePriority(t *testing.T) {
	// FindingType should take priority over severity-based remediation
	f := &store.CertFinding{
		FindingType: "MANAGED_EXPIRY",
		Severity:    store.SeverityCritical,
		ProbeOK:     true,
	}
	got := Lookup(f)
	if got == "" || got[:len("Certificate is managed")] != "Certificate is managed" {
		t.Errorf("FindingType should override severity; got %q", got)
	}
}
