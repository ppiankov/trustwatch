package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

func fixedSnapshot(findings []store.CertFinding) SnapshotFunc {
	snap := store.Snapshot{
		At:       time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC),
		Findings: findings,
	}
	return func() store.Snapshot { return snap }
}

func TestHealthzHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	w := httptest.NewRecorder()

	HealthzHandler()(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if got := w.Body.String(); got != "ok" {
		t.Errorf("body = %q, want %q", got, "ok")
	}
}

func TestSnapshotHandler(t *testing.T) {
	findings := []store.CertFinding{
		{Source: store.SourceWebhook, Severity: store.SeverityCritical, Namespace: "default", Name: "hook", ProbeOK: true},
		{Source: store.SourceExternal, Severity: store.SeverityInfo, Namespace: "", Name: "ext", ProbeOK: true},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/snapshot", http.NoBody)
	w := httptest.NewRecorder()

	SnapshotHandler(fixedSnapshot(findings))(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}

	var snap store.Snapshot
	if err := json.NewDecoder(w.Body).Decode(&snap); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if len(snap.Findings) != 2 {
		t.Errorf("findings count = %d, want 2", len(snap.Findings))
	}
}

func TestUIHandler_ShowsCriticalAndWarn(t *testing.T) {
	findings := []store.CertFinding{
		{
			Source:    store.SourceWebhook,
			Severity:  store.SeverityCritical,
			Namespace: "default",
			Name:      "critical-hook",
			NotAfter:  time.Date(2025, 6, 5, 0, 0, 0, 0, time.UTC),
			ProbeOK:   true,
		},
		{
			Source:    store.SourceAPIService,
			Severity:  store.SeverityWarn,
			Namespace: "kube-system",
			Name:      "warn-api",
			NotAfter:  time.Date(2025, 6, 20, 0, 0, 0, 0, time.UTC),
			ProbeOK:   true,
		},
		{
			Source:    store.SourceTLSSecret,
			Severity:  store.SeverityInfo,
			Namespace: "default",
			Name:      "info-only-secret",
			NotAfter:  time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			ProbeOK:   true,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	w := httptest.NewRecorder()

	UIHandler(fixedSnapshot(findings))(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()

	if !strings.Contains(body, "critical-hook") {
		t.Error("expected critical finding in HTML")
	}
	if !strings.Contains(body, "warn-api") {
		t.Error("expected warn finding in HTML")
	}
	if strings.Contains(body, "info-only-secret") {
		t.Error("info finding should not appear in UI")
	}
}

func TestUIHandler_NoProblems(t *testing.T) {
	findings := []store.CertFinding{
		{
			Source:    store.SourceTLSSecret,
			Severity:  store.SeverityInfo,
			Namespace: "default",
			Name:      "healthy-cert",
			NotAfter:  time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			ProbeOK:   true,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	w := httptest.NewRecorder()

	UIHandler(fixedSnapshot(findings))(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "No problems found") {
		t.Error("expected 'No problems found' when only info findings exist")
	}
}

func TestUIHandler_EmptySnapshot(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	w := httptest.NewRecorder()

	UIHandler(fixedSnapshot(nil))(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "No problems found") {
		t.Error("expected 'No problems found' for empty snapshot")
	}
}
