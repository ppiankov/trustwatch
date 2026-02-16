package rotation

import (
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

func TestDetectRole_SelfSigned(t *testing.T) {
	f := &store.CertFinding{SelfSigned: true}
	if got := DetectRole(f); got != RoleTrustAnchor {
		t.Errorf("expected trust_anchor, got %s", got)
	}
}

func TestDetectRole_TrustAnchorNotes(t *testing.T) {
	f := &store.CertFinding{Notes: "trust anchor"}
	if got := DetectRole(f); got != RoleTrustAnchor {
		t.Errorf("expected trust_anchor, got %s", got)
	}
}

func TestDetectRole_IsCA(t *testing.T) {
	f := &store.CertFinding{IsCA: true}
	if got := DetectRole(f); got != RoleIntermediate {
		t.Errorf("expected intermediate_ca, got %s", got)
	}
}

func TestDetectRole_IdentityIssuerNotes(t *testing.T) {
	f := &store.CertFinding{Notes: "identity issuer"}
	if got := DetectRole(f); got != RoleIntermediate {
		t.Errorf("expected intermediate_ca, got %s", got)
	}
}

func TestDetectRole_Leaf(t *testing.T) {
	f := &store.CertFinding{Name: "web-cert"}
	if got := DetectRole(f); got != RoleLeaf {
		t.Errorf("expected leaf, got %s", got)
	}
}

func TestCheck_IntermediateShortDuration(t *testing.T) {
	findings := []store.CertFinding{
		{
			Source:       store.SourceLinkerd,
			Name:         "linkerd-identity-issuer",
			Namespace:    "linkerd",
			Notes:        "identity issuer",
			CertDuration: 48 * time.Hour,
			ProbeOK:      true,
		},
	}
	results := Check(findings)
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}
	if results[0].FindingType != FindingExcessiveRotation {
		t.Errorf("expected EXCESSIVE_ROTATION, got %s", results[0].FindingType)
	}
	if results[0].Severity != store.SeverityWarn {
		t.Errorf("expected warn, got %s", results[0].Severity)
	}
}

func TestCheck_IntermediateAcceptableDuration(t *testing.T) {
	findings := []store.CertFinding{
		{
			Source:       store.SourceCertManager,
			Name:         "issuer-cert",
			Namespace:    "cert-manager",
			IsCA:         true,
			CertDuration: 8760 * time.Hour, // 1 year
			ProbeOK:      true,
		},
	}
	results := Check(findings)
	if len(results) != 0 {
		t.Errorf("expected no findings, got %d", len(results))
	}
}

func TestCheck_LeafShortDuration(t *testing.T) {
	findings := []store.CertFinding{
		{
			Source:       store.SourceCertManager,
			Name:         "web-cert",
			Namespace:    "default",
			CertDuration: 1 * time.Hour,
			ProbeOK:      true,
		},
	}
	results := Check(findings)
	if len(results) != 0 {
		t.Errorf("expected no findings for leaf cert, got %d", len(results))
	}
}

func TestCheck_TrustAnchorShortDuration(t *testing.T) {
	findings := []store.CertFinding{
		{
			Source:       store.SourceLinkerd,
			Name:         "linkerd-identity-trust-roots",
			Namespace:    "linkerd",
			Notes:        "trust anchor",
			SelfSigned:   true,
			CertDuration: 4380 * time.Hour, // 6 months
			ProbeOK:      true,
		},
	}
	results := Check(findings)
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}
	if results[0].FindingType != FindingExcessiveRotation {
		t.Errorf("expected EXCESSIVE_ROTATION, got %s", results[0].FindingType)
	}
}

func TestCheck_TrustAnchorAcceptableDuration(t *testing.T) {
	findings := []store.CertFinding{
		{
			Source:       store.SourceLinkerd,
			Name:         "linkerd-identity-trust-roots",
			Namespace:    "linkerd",
			Notes:        "trust anchor",
			SelfSigned:   true,
			CertDuration: 8760 * time.Hour, // 1 year
			ProbeOK:      true,
		},
	}
	results := Check(findings)
	if len(results) != 0 {
		t.Errorf("expected no findings, got %d", len(results))
	}
}

func TestCheck_CertManagerCA(t *testing.T) {
	findings := []store.CertFinding{
		{
			Source:       store.SourceCertManager,
			Name:         "ca-cert",
			Namespace:    "cert-manager",
			IsCA:         true,
			CertDuration: 48 * time.Hour,
			ProbeOK:      true,
		},
	}
	results := Check(findings)
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}
	if results[0].Severity != store.SeverityWarn {
		t.Errorf("expected warn, got %s", results[0].Severity)
	}
	if results[0].Name != "ca-cert" {
		t.Errorf("expected finding to reference original name, got %s", results[0].Name)
	}
}

func TestCheck_NoCertDuration(t *testing.T) {
	findings := []store.CertFinding{
		{
			Source:    store.SourceCertManager,
			Name:      "no-duration",
			Namespace: "default",
			IsCA:      true,
			ProbeOK:   true,
		},
	}
	results := Check(findings)
	if len(results) != 0 {
		t.Errorf("expected no findings (no duration), got %d", len(results))
	}
}

func TestCheck_BoundaryExact(t *testing.T) {
	// Exactly at the threshold → no finding
	findings := []store.CertFinding{
		{
			Source:       store.SourceCertManager,
			Name:         "exact-threshold",
			Namespace:    "default",
			IsCA:         true,
			CertDuration: MinIntermediateDuration,
			ProbeOK:      true,
		},
	}
	results := Check(findings)
	if len(results) != 0 {
		t.Errorf("expected no findings at exact threshold, got %d", len(results))
	}
}
