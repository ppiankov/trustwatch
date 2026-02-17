package report

import (
	"bytes"
	"encoding/csv"
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

func TestWriteCSV_Header(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, nil); err != nil {
		t.Fatalf("WriteCSV error: %v", err)
	}

	r := csv.NewReader(&buf)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parsing CSV: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 row (header only), got %d", len(records))
	}

	want := []string{"name", "namespace", "source", "severity", "notAfter", "issuer", "serial", "findingType", "remediation", "probeOk"}
	for i, col := range want {
		if records[0][i] != col {
			t.Errorf("header[%d] = %q, want %q", i, records[0][i], col)
		}
	}
}

func TestWriteCSV_RowCount(t *testing.T) {
	findings := []store.CertFinding{
		{Name: "a", Source: store.SourceWebhook, Severity: store.SeverityCritical, ProbeOK: true},
		{Name: "b", Source: store.SourceExternal, Severity: store.SeverityInfo, ProbeOK: true},
		{Name: "c", Source: store.SourceAPIService, Severity: store.SeverityWarn, ProbeOK: false},
	}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, findings); err != nil {
		t.Fatalf("WriteCSV error: %v", err)
	}

	r := csv.NewReader(&buf)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parsing CSV: %v", err)
	}
	// 1 header + 3 data rows
	if len(records) != 4 {
		t.Errorf("expected 4 rows, got %d", len(records))
	}
}

func TestWriteCSV_RFC3339Timestamp(t *testing.T) {
	notAfter := time.Date(2025, 8, 15, 10, 30, 0, 0, time.UTC)
	findings := []store.CertFinding{
		{Name: "cert1", Source: store.SourceWebhook, Severity: store.SeverityWarn, NotAfter: notAfter, ProbeOK: true},
	}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, findings); err != nil {
		t.Fatalf("WriteCSV error: %v", err)
	}

	r := csv.NewReader(&buf)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parsing CSV: %v", err)
	}

	// notAfter is column index 4
	got := records[1][4]
	want := "2025-08-15T10:30:00Z"
	if got != want {
		t.Errorf("notAfter = %q, want %q", got, want)
	}
}

func TestWriteCSV_QuotingComma(t *testing.T) {
	findings := []store.CertFinding{
		{Name: "hook, with comma", Source: store.SourceWebhook, Severity: store.SeverityInfo, Issuer: "CN=My CA, O=Org", ProbeOK: true},
	}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, findings); err != nil {
		t.Fatalf("WriteCSV error: %v", err)
	}

	r := csv.NewReader(&buf)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parsing CSV: %v", err)
	}

	if records[1][0] != "hook, with comma" {
		t.Errorf("name = %q, want %q", records[1][0], "hook, with comma")
	}
	if records[1][5] != "CN=My CA, O=Org" {
		t.Errorf("issuer = %q, want %q", records[1][5], "CN=My CA, O=Org")
	}
}

func TestWriteCSV_ProbeOkValues(t *testing.T) {
	findings := []store.CertFinding{
		{Name: "ok", ProbeOK: true},
		{Name: "fail", ProbeOK: false},
	}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, findings); err != nil {
		t.Fatalf("WriteCSV error: %v", err)
	}

	r := csv.NewReader(&buf)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parsing CSV: %v", err)
	}

	// probeOk is column index 9
	if records[1][9] != "true" {
		t.Errorf("probeOk for ok = %q, want true", records[1][9])
	}
	if records[2][9] != "false" {
		t.Errorf("probeOk for fail = %q, want false", records[2][9])
	}
}
