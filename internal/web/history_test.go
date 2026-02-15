package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/history"
	"github.com/ppiankov/trustwatch/internal/store"
)

func openTestHistory(t *testing.T) *history.Store {
	t.Helper()
	s, err := history.Open(":memory:")
	if err != nil {
		t.Fatalf("opening in-memory history: %v", err)
	}
	t.Cleanup(func() { s.Close() }) //nolint:errcheck // test cleanup
	return s
}

func TestHistoryHandler_Empty(t *testing.T) {
	hs := openTestHistory(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/history", http.NoBody)
	w := httptest.NewRecorder()

	HistoryHandler(hs)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}

	var summaries []history.SnapshotSummary
	if err := json.NewDecoder(w.Body).Decode(&summaries); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected 0 summaries, got %d", len(summaries))
	}
}

func TestHistoryHandler_WithData(t *testing.T) {
	hs := openTestHistory(t)

	snap := store.Snapshot{
		At: time.Now().UTC().Truncate(time.Second),
		Findings: []store.CertFinding{
			{Name: "cert-a", Severity: store.SeverityCritical, ProbeOK: true},
			{Name: "cert-b", Severity: store.SeverityWarn, ProbeOK: false},
		},
	}
	if err := hs.Save(snap); err != nil {
		t.Fatalf("save: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/history?limit=10", http.NoBody)
	w := httptest.NewRecorder()

	HistoryHandler(hs)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var summaries []history.SnapshotSummary
	if err := json.NewDecoder(w.Body).Decode(&summaries); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	if summaries[0].FindingsCount != 2 {
		t.Errorf("findingsCount = %d, want 2", summaries[0].FindingsCount)
	}
}

func TestTrendHandler_MissingParams(t *testing.T) {
	hs := openTestHistory(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/trend", http.NoBody)
	w := httptest.NewRecorder()

	TrendHandler(hs)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestTrendHandler_WithData(t *testing.T) {
	hs := openTestHistory(t)

	now := time.Now().UTC().Truncate(time.Second)
	for i := range 3 {
		snap := store.Snapshot{
			At: now.Add(time.Duration(i) * time.Minute),
			Findings: []store.CertFinding{
				{Name: "web-cert", Namespace: "prod", Source: store.SourceWebhook, Severity: store.SeverityWarn, ProbeOK: true},
			},
		}
		if err := hs.Save(snap); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/trend?name=web-cert&namespace=prod&source=k8s.webhook", http.NoBody)
	w := httptest.NewRecorder()

	TrendHandler(hs)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var points []history.TrendPoint
	if err := json.NewDecoder(w.Body).Decode(&points); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if len(points) != 3 {
		t.Errorf("expected 3 trend points, got %d", len(points))
	}
}

func TestTrendHandler_NoData(t *testing.T) {
	hs := openTestHistory(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/trend?name=nonexistent&namespace=ns&source=src", http.NoBody)
	w := httptest.NewRecorder()

	TrendHandler(hs)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var points []history.TrendPoint
	if err := json.NewDecoder(w.Body).Decode(&points); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if len(points) != 0 {
		t.Errorf("expected 0 points, got %d", len(points))
	}
}
