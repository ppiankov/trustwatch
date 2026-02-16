package report

import (
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

func TestGenerate_WithFindings(t *testing.T) {
	now := time.Now().UTC()
	snap := store.Snapshot{
		At: now,
		Findings: []store.CertFinding{
			{
				Name:      "expiring-cert",
				Namespace: "kube-system",
				Source:    store.SourceWebhook,
				Severity:  store.SeverityCritical,
				NotAfter:  now.Add(48 * time.Hour),
				ProbeOK:   true,
				Subject:   "CN=webhook.kube-system",
				Issuer:    "CN=cluster-ca",
				Serial:    "ABC123",
			},
			{
				Name:        "weak-tls",
				Namespace:   "default",
				Source:      store.SourceTLSSecret,
				Severity:    store.SeverityWarn,
				NotAfter:    now.Add(20 * 24 * time.Hour),
				ProbeOK:     true,
				Remediation: "Upgrade to TLS 1.2+",
			},
			{
				Name:      "healthy-cert",
				Namespace: "prod",
				Source:    store.SourceTLSSecret,
				Severity:  store.SeverityInfo,
				NotAfter:  now.Add(90 * 24 * time.Hour),
				ProbeOK:   true,
			},
		},
	}

	html, err := Generate(snap, "prod-cluster")
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	body := string(html)

	// Check HTML structure
	for _, want := range []string{
		"<!DOCTYPE html>",
		"TrustWatch Compliance Report",
		"prod-cluster",
		"Critical: 1",
		"Warn: 1",
		"Info: 1",
		"Total: 3",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected HTML to contain %q", want)
		}
	}

	// Check finding data appears
	for _, want := range []string{
		"expiring-cert",
		"kube-system",
		"weak-tls",
		"healthy-cert",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected HTML to contain finding %q", want)
		}
	}
}

func TestGenerate_EmptySnapshot(t *testing.T) {
	snap := store.Snapshot{At: time.Now().UTC()}

	html, err := Generate(snap, "")
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	body := string(html)
	if !strings.Contains(body, "No findings.") {
		t.Error("expected empty report to contain 'No findings.'")
	}
	if !strings.Contains(body, "Total: 0") {
		t.Error("expected total count of 0")
	}
}

func TestGenerate_RemediationShown(t *testing.T) {
	now := time.Now().UTC()
	snap := store.Snapshot{
		At: now,
		Findings: []store.CertFinding{
			{
				Name:        "my-cert",
				Namespace:   "default",
				Source:      store.SourceTLSSecret,
				Severity:    store.SeverityWarn,
				NotAfter:    now.Add(10 * 24 * time.Hour),
				ProbeOK:     true,
				Remediation: "Renew the certificate before expiry",
			},
		},
	}

	html, err := Generate(snap, "")
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	if !strings.Contains(string(html), "Renew the certificate before expiry") {
		t.Error("expected remediation text in report")
	}
}

func TestGenerate_CertificateDetails(t *testing.T) {
	now := time.Now().UTC()
	snap := store.Snapshot{
		At: now,
		Findings: []store.CertFinding{
			{
				Name:         "my-cert",
				Namespace:    "default",
				Source:       store.SourceTLSSecret,
				Severity:     store.SeverityCritical,
				NotAfter:     now.Add(24 * time.Hour),
				ProbeOK:      true,
				Subject:      "CN=example.com",
				Issuer:       "CN=My CA",
				Serial:       "DEADBEEF",
				DNSNames:     []string{"example.com", "*.example.com"},
				TLSVersion:   "TLS 1.3",
				CipherSuite:  "TLS_AES_256_GCM_SHA384",
				KeyAlgorithm: "ECDSA P-256",
			},
		},
	}

	html, err := Generate(snap, "test")
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	body := string(html)
	for _, want := range []string{
		"CN=example.com",
		"CN=My CA",
		"DEADBEEF",
		"example.com, *.example.com",
		"TLS 1.3",
		"TLS_AES_256_GCM_SHA384",
		"ECDSA P-256",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected HTML to contain %q", want)
		}
	}
}

func TestGenerate_SortOrder(t *testing.T) {
	now := time.Now().UTC()
	snap := store.Snapshot{
		At: now,
		Findings: []store.CertFinding{
			{Name: "info-cert", Severity: store.SeverityInfo, NotAfter: now.Add(90 * 24 * time.Hour), ProbeOK: true},
			{Name: "crit-cert", Severity: store.SeverityCritical, NotAfter: now.Add(24 * time.Hour), ProbeOK: true},
			{Name: "warn-cert", Severity: store.SeverityWarn, NotAfter: now.Add(10 * 24 * time.Hour), ProbeOK: true},
		},
	}

	html, err := Generate(snap, "")
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	body := string(html)
	critIdx := strings.Index(body, "crit-cert")
	warnIdx := strings.Index(body, "warn-cert")
	infoIdx := strings.Index(body, "info-cert")

	if critIdx > warnIdx || warnIdx > infoIdx {
		t.Error("expected findings sorted: critical, warn, info")
	}
}

func TestGenerate_ExpiredCert(t *testing.T) {
	now := time.Now().UTC()
	snap := store.Snapshot{
		At: now,
		Findings: []store.CertFinding{
			{
				Name:     "expired",
				Severity: store.SeverityCritical,
				NotAfter: now.Add(-24 * time.Hour),
				ProbeOK:  true,
			},
		},
	}

	html, err := Generate(snap, "")
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	if !strings.Contains(string(html), "EXPIRED") {
		t.Error("expected EXPIRED in report for expired cert")
	}
}
