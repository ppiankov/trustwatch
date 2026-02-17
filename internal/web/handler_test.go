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

func TestHealthzHandler_Healthy(t *testing.T) {
	snap := store.Snapshot{At: time.Now()}
	getSnap := func() store.Snapshot { return snap }

	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	w := httptest.NewRecorder()

	HealthzHandler(getSnap, 5*time.Minute)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if got := w.Body.String(); got != "ok" {
		t.Errorf("body = %q, want %q", got, "ok")
	}
}

func TestHealthzHandler_NoScan(t *testing.T) {
	snap := store.Snapshot{} // zero At
	getSnap := func() store.Snapshot { return snap }

	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	w := httptest.NewRecorder()

	HealthzHandler(getSnap, 5*time.Minute)(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestHealthzHandler_Stale(t *testing.T) {
	snap := store.Snapshot{At: time.Now().Add(-10 * time.Minute)}
	getSnap := func() store.Snapshot { return snap }

	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	w := httptest.NewRecorder()

	HealthzHandler(getSnap, 5*time.Minute)(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestHealthzHandler_ZeroMaxAge(t *testing.T) {
	snap := store.Snapshot{At: time.Now().Add(-1 * time.Hour)}
	getSnap := func() store.Snapshot { return snap }

	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	w := httptest.NewRecorder()

	// Zero maxAge disables staleness check
	HealthzHandler(getSnap, 0)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
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

func TestSnapshotHandler_NoFilter(t *testing.T) {
	findings := []store.CertFinding{
		{Source: store.SourceWebhook, Severity: store.SeverityCritical, Namespace: "default", Name: "a", ProbeOK: true},
		{Source: store.SourceExternal, Severity: store.SeverityInfo, Namespace: "", Name: "b", ProbeOK: true},
		{Source: store.SourceAPIService, Severity: store.SeverityWarn, Namespace: "kube-system", Name: "c", ProbeOK: true},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/snapshot", http.NoBody)
	w := httptest.NewRecorder()
	SnapshotHandler(fixedSnapshot(findings))(w, req)

	var snap store.Snapshot
	if err := json.NewDecoder(w.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(snap.Findings) != 3 {
		t.Errorf("findings = %d, want 3", len(snap.Findings))
	}
}

func TestSnapshotHandler_FilterBySeverity(t *testing.T) {
	findings := []store.CertFinding{
		{Source: store.SourceWebhook, Severity: store.SeverityCritical, Name: "a", ProbeOK: true},
		{Source: store.SourceExternal, Severity: store.SeverityInfo, Name: "b", ProbeOK: true},
		{Source: store.SourceAPIService, Severity: store.SeverityWarn, Name: "c", ProbeOK: true},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/snapshot?severity=critical", http.NoBody)
	w := httptest.NewRecorder()
	SnapshotHandler(fixedSnapshot(findings))(w, req)

	var snap store.Snapshot
	if err := json.NewDecoder(w.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(snap.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(snap.Findings))
	}
	if snap.Findings[0].Name != "a" {
		t.Errorf("finding name = %q, want %q", snap.Findings[0].Name, "a")
	}
}

func TestSnapshotHandler_FilterMultipleSeverities(t *testing.T) {
	findings := []store.CertFinding{
		{Source: store.SourceWebhook, Severity: store.SeverityCritical, Name: "a", ProbeOK: true},
		{Source: store.SourceExternal, Severity: store.SeverityInfo, Name: "b", ProbeOK: true},
		{Source: store.SourceAPIService, Severity: store.SeverityWarn, Name: "c", ProbeOK: true},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/snapshot?severity=critical,warn", http.NoBody)
	w := httptest.NewRecorder()
	SnapshotHandler(fixedSnapshot(findings))(w, req)

	var snap store.Snapshot
	if err := json.NewDecoder(w.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(snap.Findings) != 2 {
		t.Errorf("findings = %d, want 2", len(snap.Findings))
	}
}

func TestSnapshotHandler_FilterBySource(t *testing.T) {
	findings := []store.CertFinding{
		{Source: store.SourceWebhook, Severity: store.SeverityCritical, Name: "a", ProbeOK: true},
		{Source: store.SourceExternal, Severity: store.SeverityInfo, Name: "b", ProbeOK: true},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/snapshot?source=external", http.NoBody)
	w := httptest.NewRecorder()
	SnapshotHandler(fixedSnapshot(findings))(w, req)

	var snap store.Snapshot
	if err := json.NewDecoder(w.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(snap.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(snap.Findings))
	}
	if snap.Findings[0].Name != "b" {
		t.Errorf("finding name = %q, want %q", snap.Findings[0].Name, "b")
	}
}

func TestSnapshotHandler_FilterByNamespace(t *testing.T) {
	findings := []store.CertFinding{
		{Source: store.SourceWebhook, Severity: store.SeverityCritical, Namespace: "default", Name: "a", ProbeOK: true},
		{Source: store.SourceWebhook, Severity: store.SeverityWarn, Namespace: "kube-system", Name: "b", ProbeOK: true},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/snapshot?namespace=kube-system", http.NoBody)
	w := httptest.NewRecorder()
	SnapshotHandler(fixedSnapshot(findings))(w, req)

	var snap store.Snapshot
	if err := json.NewDecoder(w.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(snap.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(snap.Findings))
	}
	if snap.Findings[0].Namespace != "kube-system" {
		t.Errorf("namespace = %q, want kube-system", snap.Findings[0].Namespace)
	}
}

func TestSnapshotHandler_MultipleFiltersAND(t *testing.T) {
	findings := []store.CertFinding{
		{Source: store.SourceWebhook, Severity: store.SeverityCritical, Namespace: "default", Name: "a", ProbeOK: true},
		{Source: store.SourceWebhook, Severity: store.SeverityWarn, Namespace: "default", Name: "b", ProbeOK: true},
		{Source: store.SourceExternal, Severity: store.SeverityCritical, Namespace: "", Name: "c", ProbeOK: true},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/snapshot?source=k8s.webhook&severity=critical", http.NoBody)
	w := httptest.NewRecorder()
	SnapshotHandler(fixedSnapshot(findings))(w, req)

	var snap store.Snapshot
	if err := json.NewDecoder(w.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(snap.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(snap.Findings))
	}
	if snap.Findings[0].Name != "a" {
		t.Errorf("finding name = %q, want %q", snap.Findings[0].Name, "a")
	}
}

func TestSnapshotHandler_UnknownValueReturnsEmpty(t *testing.T) {
	findings := []store.CertFinding{
		{Source: store.SourceWebhook, Severity: store.SeverityCritical, Name: "a", ProbeOK: true},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/snapshot?severity=nonexistent", http.NoBody)
	w := httptest.NewRecorder()
	SnapshotHandler(fixedSnapshot(findings))(w, req)

	var snap store.Snapshot
	if err := json.NewDecoder(w.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(snap.Findings) != 0 {
		t.Errorf("findings = %d, want 0", len(snap.Findings))
	}
}
