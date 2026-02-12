package monitor

import (
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

func TestNewModel_EmptySnapshot(t *testing.T) {
	snap := store.Snapshot{At: time.Now()}
	m := NewModel(snap, "test-ctx")

	if len(m.findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(m.findings))
	}
	if m.context != "test-ctx" {
		t.Errorf("expected context 'test-ctx', got %q", m.context)
	}
}

func TestNewModel_SortsFindings(t *testing.T) {
	now := time.Now()
	snap := store.Snapshot{
		At: now,
		Findings: []store.CertFinding{
			{Severity: store.SeverityInfo, Name: "info", NotAfter: now.Add(90 * 24 * time.Hour), ProbeOK: true},
			{Severity: store.SeverityCritical, Name: "crit", NotAfter: now.Add(5 * 24 * time.Hour), ProbeOK: true},
			{Severity: store.SeverityWarn, Name: "warn", NotAfter: now.Add(20 * 24 * time.Hour), ProbeOK: true},
		},
	}
	m := NewModel(snap, "")

	if m.findings[0].Severity != store.SeverityCritical {
		t.Errorf("expected first finding to be critical, got %s", m.findings[0].Severity)
	}
	if m.findings[1].Severity != store.SeverityWarn {
		t.Errorf("expected second finding to be warn, got %s", m.findings[1].Severity)
	}
	if m.findings[2].Severity != store.SeverityInfo {
		t.Errorf("expected third finding to be info, got %s", m.findings[2].Severity)
	}
}

func TestFormatExpiresIn(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		notAfter time.Time
		want     string
	}{
		{"expired", now.Add(-1 * time.Hour), "EXPIRED"},
		{"days and hours", now.Add(3*24*time.Hour + 5*time.Hour), "3d 5h"},
		{"hours only", now.Add(5 * time.Hour), "5h"},
		{"minutes only", now.Add(45 * time.Minute), "45m"},
		{"just expired", now.Add(-1 * time.Minute), "EXPIRED"},
		{"large days", now.Add(365 * 24 * time.Hour), "365d 0h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatExpiresIn(tt.notAfter, now)
			// Strip ANSI escape sequences for comparison
			clean := stripANSI(got)
			if clean != tt.want {
				t.Errorf("FormatExpiresIn() = %q, want %q", clean, tt.want)
			}
		})
	}
}

func TestViewDoesNotPanic(t *testing.T) {
	now := time.Now()
	snap := store.Snapshot{
		At: now,
		Findings: []store.CertFinding{
			{
				Source:   store.SourceWebhook,
				Severity: store.SeverityCritical,
				Name:     "test-webhook",
				NotAfter: now.Add(3 * 24 * time.Hour),
				DNSNames: []string{"test.example.com"},
				Issuer:   "CN=Test CA",
				ProbeOK:  true,
			},
			{
				Source:   store.SourceExternal,
				Severity: store.SeverityInfo,
				Name:     "api.example.com",
				ProbeOK:  false,
				ProbeErr: "connection refused",
			},
		},
	}

	m := NewModel(snap, "test-ctx")
	// Should not panic
	output := m.View()
	if output == "" {
		t.Error("View() returned empty string")
	}
}

func TestPlainText(t *testing.T) {
	now := time.Now()
	snap := store.Snapshot{
		At: now,
		Findings: []store.CertFinding{
			{
				Source:    store.SourceWebhook,
				Severity:  store.SeverityCritical,
				Namespace: "kube-system",
				Name:      "my-webhook",
				NotAfter:  now.Add(3 * 24 * time.Hour),
				ProbeOK:   true,
			},
		},
	}

	out := PlainText(snap)
	if !strings.Contains(out, "SOURCE") {
		t.Error("PlainText should contain header row")
	}
	if !strings.Contains(out, "kube-system/my-webhook") {
		t.Errorf("PlainText should contain finding where, got:\n%s", out)
	}
}

func TestPlainText_Empty(t *testing.T) {
	snap := store.Snapshot{At: time.Now()}
	out := PlainText(snap)
	if out != "No findings." {
		t.Errorf("PlainText(empty) = %q, want %q", out, "No findings.")
	}
}

func TestSortFindings(t *testing.T) {
	now := time.Now()
	findings := []store.CertFinding{
		{Severity: store.SeverityWarn, NotAfter: now.Add(20 * 24 * time.Hour)},
		{Severity: store.SeverityCritical, NotAfter: now.Add(10 * 24 * time.Hour)},
		{Severity: store.SeverityCritical, NotAfter: now.Add(5 * 24 * time.Hour)},
		{Severity: store.SeverityInfo, NotAfter: now.Add(90 * 24 * time.Hour)},
	}

	sorted := sortFindings(findings)

	// Critical first, sorted by expiry ascending
	if sorted[0].Severity != store.SeverityCritical {
		t.Errorf("expected critical first")
	}
	if !sorted[0].NotAfter.Before(sorted[1].NotAfter) {
		t.Error("expected earlier expiry first within same severity")
	}
	// Then warn
	if sorted[2].Severity != store.SeverityWarn {
		t.Errorf("expected warn third, got %s", sorted[2].Severity)
	}
	// Then info
	if sorted[3].Severity != store.SeverityInfo {
		t.Errorf("expected info last, got %s", sorted[3].Severity)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		s    string
		want string
		max  int
	}{
		{"short", "short", 10},
		{"this is a long string", "this is...", 10},
		{"exact10chr", "exact10chr", 10},
	}
	for _, tt := range tests {
		got := truncate(tt.s, tt.max)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.s, tt.max, got, tt.want)
		}
	}
}

// stripANSI removes ANSI escape sequences for test comparison.
func stripANSI(s string) string {
	var result strings.Builder
	inEscape := false
	for _, r := range s {
		if r == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
			continue
		}
		result.WriteRune(r)
	}
	return result.String()
}
