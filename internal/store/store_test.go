package store

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCertFindingJSON(t *testing.T) {
	f := CertFinding{
		Source:    SourceWebhook,
		Severity:  SeverityCritical,
		Namespace: "kube-system",
		Name:      "my-webhook",
		Target:    "tcp://my-webhook.kube-system.svc:443",
		NotAfter:  time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
		ProbeOK:   true,
		Notes:     "failurePolicy=Fail",
	}

	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}

	var decoded CertFinding
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Source != SourceWebhook {
		t.Errorf("expected source %s, got %s", SourceWebhook, decoded.Source)
	}
	if decoded.Severity != SeverityCritical {
		t.Errorf("expected severity %s, got %s", SeverityCritical, decoded.Severity)
	}
	if decoded.Namespace != "kube-system" {
		t.Errorf("expected namespace kube-system, got %s", decoded.Namespace)
	}
}

func TestSnapshotJSON(t *testing.T) {
	s := Snapshot{
		At: time.Now(),
		Findings: []CertFinding{
			{Source: SourceAPIServer, Severity: SeverityInfo, ProbeOK: true},
		},
	}

	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Snapshot
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}

	if len(decoded.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(decoded.Findings))
	}
}

func TestSeverityConstants(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityInfo, "info"},
		{SeverityWarn, "warn"},
		{SeverityCritical, "critical"},
	}
	for _, tt := range tests {
		if string(tt.sev) != tt.want {
			t.Errorf("expected %s, got %s", tt.want, tt.sev)
		}
	}
}
