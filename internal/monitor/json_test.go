package monitor

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

func TestWriteJSON_EmptySnapshot(t *testing.T) {
	snap := store.Snapshot{
		At:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Findings: []store.CertFinding{},
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, snap, 0); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var out NowOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.ExitCode != 0 {
		t.Errorf("exitCode = %d, want 0", out.ExitCode)
	}
	if len(out.Snapshot.Findings) != 0 {
		t.Errorf("findings = %d, want 0", len(out.Snapshot.Findings))
	}
}

func TestWriteJSON_WithFindings(t *testing.T) {
	snap := store.Snapshot{
		At: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Findings: []store.CertFinding{
			{
				Name:     "test-webhook",
				Source:   store.SourceWebhook,
				Severity: store.SeverityCritical,
				NotAfter: time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
				ProbeOK:  true,
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, snap, 2); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var out NowOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.ExitCode != 2 {
		t.Errorf("exitCode = %d, want 2", out.ExitCode)
	}
	if len(out.Snapshot.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(out.Snapshot.Findings))
	}
	if out.Snapshot.Findings[0].Name != "test-webhook" {
		t.Errorf("name = %q, want %q", out.Snapshot.Findings[0].Name, "test-webhook")
	}
	if out.Snapshot.Findings[0].Source != store.SourceWebhook {
		t.Errorf("source = %q, want %q", out.Snapshot.Findings[0].Source, store.SourceWebhook)
	}
}

func TestWriteJSON_RoundTrip(t *testing.T) {
	snap := store.Snapshot{
		At: time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC),
		Errors: map[string]string{
			"linkerd": "namespace not found",
		},
		Findings: []store.CertFinding{
			{
				Name:      "my-ingress/my-cert",
				Namespace: "default",
				Source:    store.SourceIngressTLS,
				Severity:  store.SeverityWarn,
				NotAfter:  time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
				Issuer:    "CN=Let's Encrypt",
				Subject:   "CN=example.com",
				Serial:    "123456",
				DNSNames:  []string{"example.com", "*.example.com"},
				ProbeOK:   true,
			},
			{
				Name:     "broken-svc",
				Source:   store.SourceAnnotation,
				Severity: store.SeverityInfo,
				ProbeOK:  false,
				ProbeErr: "connection refused",
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, snap, 1); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var out NowOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.ExitCode != 1 {
		t.Errorf("exitCode = %d, want 1", out.ExitCode)
	}
	if len(out.Snapshot.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(out.Snapshot.Findings))
	}
	if out.Snapshot.Errors["linkerd"] != "namespace not found" {
		t.Errorf("errors[linkerd] = %q, want %q", out.Snapshot.Errors["linkerd"], "namespace not found")
	}

	// Verify all fields survive round-trip
	f := out.Snapshot.Findings[0]
	if f.Issuer != "CN=Let's Encrypt" {
		t.Errorf("issuer = %q", f.Issuer)
	}
	if len(f.DNSNames) != 2 {
		t.Errorf("dnsNames = %d, want 2", len(f.DNSNames))
	}

	f2 := out.Snapshot.Findings[1]
	if f2.ProbeOK {
		t.Error("probeOK should be false")
	}
	if f2.ProbeErr != "connection refused" {
		t.Errorf("probeErr = %q", f2.ProbeErr)
	}
}

func TestWriteJSON_DiscoveryErrors(t *testing.T) {
	snap := store.Snapshot{
		At: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Errors: map[string]string{
			"webhooks":    "forbidden",
			"apiservices": "timeout",
		},
		Findings: []store.CertFinding{},
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, snap, 3); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var out NowOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.ExitCode != 3 {
		t.Errorf("exitCode = %d, want 3", out.ExitCode)
	}
	if len(out.Snapshot.Errors) != 2 {
		t.Errorf("errors = %d, want 2", len(out.Snapshot.Errors))
	}
}
