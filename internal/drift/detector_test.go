package drift

import (
	"testing"

	"github.com/ppiankov/trustwatch/internal/store"
)

func finding(name, ns, serial, issuer string) store.CertFinding {
	return store.CertFinding{
		Name:      name,
		Namespace: ns,
		Source:    store.SourceTLSSecret,
		Severity:  store.SeverityInfo,
		Serial:    serial,
		Issuer:    issuer,
		ProbeOK:   true,
	}
}

func TestDetect_NewCert(t *testing.T) {
	prev := []store.CertFinding{}
	curr := []store.CertFinding{finding("my-cert", "default", "ABC", "CN=CA")}

	results := Detect(prev, curr)

	if len(results) != 1 {
		t.Fatalf("expected 1 drift finding, got %d", len(results))
	}
	if results[0].FindingType != FindingCertNew {
		t.Errorf("expected CERT_NEW, got %q", results[0].FindingType)
	}
	if results[0].Severity != store.SeverityInfo {
		t.Errorf("expected info severity, got %q", results[0].Severity)
	}
}

func TestDetect_CertGone(t *testing.T) {
	prev := []store.CertFinding{finding("my-cert", "default", "ABC", "CN=CA")}
	curr := []store.CertFinding{}

	results := Detect(prev, curr)

	if len(results) != 1 {
		t.Fatalf("expected 1 drift finding, got %d", len(results))
	}
	if results[0].FindingType != FindingCertGone {
		t.Errorf("expected CERT_GONE, got %q", results[0].FindingType)
	}
	if results[0].Severity != store.SeverityWarn {
		t.Errorf("expected warn severity, got %q", results[0].Severity)
	}
}

func TestDetect_SerialChanged(t *testing.T) {
	prev := []store.CertFinding{finding("my-cert", "default", "ABC", "CN=CA")}
	curr := []store.CertFinding{finding("my-cert", "default", "DEF", "CN=CA")}

	results := Detect(prev, curr)

	if len(results) != 1 {
		t.Fatalf("expected 1 drift finding, got %d", len(results))
	}
	if results[0].FindingType != FindingSerialChanged {
		t.Errorf("expected SERIAL_CHANGED, got %q", results[0].FindingType)
	}
	if results[0].Severity != store.SeverityInfo {
		t.Errorf("expected info severity, got %q", results[0].Severity)
	}
}

func TestDetect_IssuerChanged(t *testing.T) {
	prev := []store.CertFinding{finding("my-cert", "default", "ABC", "CN=OldCA")}
	curr := []store.CertFinding{finding("my-cert", "default", "ABC", "CN=NewCA")}

	results := Detect(prev, curr)

	if len(results) != 1 {
		t.Fatalf("expected 1 drift finding, got %d", len(results))
	}
	if results[0].FindingType != FindingIssuerChanged {
		t.Errorf("expected ISSUER_CHANGED, got %q", results[0].FindingType)
	}
	if results[0].Severity != store.SeverityWarn {
		t.Errorf("expected warn severity, got %q", results[0].Severity)
	}
}

func TestDetect_NoChanges(t *testing.T) {
	cert := finding("my-cert", "default", "ABC", "CN=CA")
	prev := []store.CertFinding{cert}
	curr := []store.CertFinding{cert}

	results := Detect(prev, curr)

	if len(results) != 0 {
		t.Errorf("expected 0 drift findings, got %d", len(results))
	}
}

func TestDetect_BothSerialAndIssuerChanged(t *testing.T) {
	prev := []store.CertFinding{finding("my-cert", "default", "ABC", "CN=OldCA")}
	curr := []store.CertFinding{finding("my-cert", "default", "DEF", "CN=NewCA")}

	results := Detect(prev, curr)

	if len(results) != 2 {
		t.Fatalf("expected 2 drift findings, got %d", len(results))
	}

	var hasSerial, hasIssuer bool
	for _, r := range results {
		switch r.FindingType {
		case FindingSerialChanged:
			hasSerial = true
		case FindingIssuerChanged:
			hasIssuer = true
		}
	}
	if !hasSerial {
		t.Error("expected SERIAL_CHANGED finding")
	}
	if !hasIssuer {
		t.Error("expected ISSUER_CHANGED finding")
	}
}

func TestDetect_ProbeFailureExcluded(t *testing.T) {
	prev := []store.CertFinding{{
		Name:      "my-cert",
		Namespace: "default",
		Source:    store.SourceTLSSecret,
		ProbeOK:   false,
		ProbeErr:  "connection refused",
		Serial:    "ABC",
	}}
	curr := []store.CertFinding{finding("my-cert", "default", "DEF", "CN=CA")}

	results := Detect(prev, curr)

	// The probe failure in prev should be skipped, so the cert in curr looks new
	if len(results) != 1 {
		t.Fatalf("expected 1 drift finding, got %d", len(results))
	}
	if results[0].FindingType != FindingCertNew {
		t.Errorf("expected CERT_NEW (prev was probe failure), got %q", results[0].FindingType)
	}
}

func TestDetect_EmptySerialSkipsComparison(t *testing.T) {
	prev := []store.CertFinding{finding("my-cert", "default", "", "CN=CA")}
	curr := []store.CertFinding{finding("my-cert", "default", "ABC", "CN=CA")}

	results := Detect(prev, curr)

	// Empty serial in prev means we can't compare — should NOT flag as changed
	if len(results) != 0 {
		t.Errorf("expected 0 drift findings when prev serial is empty, got %d", len(results))
	}
}
