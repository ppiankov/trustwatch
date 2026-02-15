package history

import (
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

func openMemory(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("opening in-memory db: %v", err)
	}
	t.Cleanup(func() { s.Close() }) //nolint:errcheck // test cleanup
	return s
}

func TestOpen_InMemory(t *testing.T) {
	s := openMemory(t)
	if s.db == nil {
		t.Fatal("expected non-nil db")
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	s := openMemory(t)
	// Running migrate again should not error
	if err := migrate(s.db); err != nil {
		t.Fatalf("second migrate failed: %v", err)
	}
}

func TestSaveAndList(t *testing.T) {
	s := openMemory(t)
	now := time.Now().UTC().Truncate(time.Second)

	snap := store.Snapshot{
		At: now,
		Findings: []store.CertFinding{
			{Name: "cert-a", Namespace: "ns1", Source: store.SourceWebhook, Severity: store.SeverityCritical, ProbeOK: true},
			{Name: "cert-b", Namespace: "ns2", Source: store.SourceExternal, Severity: store.SeverityWarn, ProbeOK: true},
			{Name: "cert-c", Namespace: "ns1", Source: store.SourceTLSSecret, Severity: store.SeverityInfo, ProbeOK: false},
		},
	}

	if err := s.Save(snap); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	summaries, err := s.List(10)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(summaries))
	}

	sm := summaries[0]
	if sm.FindingsCount != 3 {
		t.Errorf("findingsCount = %d, want 3", sm.FindingsCount)
	}
	if sm.CritCount != 1 {
		t.Errorf("critCount = %d, want 1", sm.CritCount)
	}
	if sm.WarnCount != 1 {
		t.Errorf("warnCount = %d, want 1", sm.WarnCount)
	}
	if sm.ErrorCount != 1 {
		t.Errorf("errorCount = %d, want 1", sm.ErrorCount)
	}
}

func TestList_Ordering(t *testing.T) {
	s := openMemory(t)
	now := time.Now().UTC().Truncate(time.Second)

	for i := range 3 {
		snap := store.Snapshot{
			At:       now.Add(time.Duration(i) * time.Minute),
			Findings: []store.CertFinding{{Name: "cert", Severity: store.SeverityInfo, ProbeOK: true}},
		}
		if err := s.Save(snap); err != nil {
			t.Fatalf("save %d failed: %v", i, err)
		}
	}

	summaries, err := s.List(10)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(summaries) != 3 {
		t.Fatalf("expected 3 snapshots, got %d", len(summaries))
	}
	// Should be newest first
	if !summaries[0].At.After(summaries[1].At) {
		t.Error("expected newest first ordering")
	}
}

func TestList_Limit(t *testing.T) {
	s := openMemory(t)
	now := time.Now().UTC().Truncate(time.Second)

	for i := range 5 {
		snap := store.Snapshot{
			At:       now.Add(time.Duration(i) * time.Minute),
			Findings: []store.CertFinding{{Name: "cert", Severity: store.SeverityInfo, ProbeOK: true}},
		}
		if err := s.Save(snap); err != nil {
			t.Fatalf("save %d failed: %v", i, err)
		}
	}

	summaries, err := s.List(2)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(summaries) != 2 {
		t.Fatalf("expected 2 snapshots (limited), got %d", len(summaries))
	}
}

func TestTrend(t *testing.T) {
	s := openMemory(t)
	now := time.Now().UTC().Truncate(time.Second)

	for i := range 3 {
		sev := store.SeverityInfo
		if i == 2 {
			sev = store.SeverityWarn
		}
		snap := store.Snapshot{
			At: now.Add(time.Duration(i) * time.Minute),
			Findings: []store.CertFinding{
				{Name: "web-cert", Namespace: "prod", Source: store.SourceWebhook, Severity: sev, ProbeOK: true},
				{Name: "other-cert", Namespace: "staging", Source: store.SourceExternal, Severity: store.SeverityInfo, ProbeOK: true},
			},
		}
		if err := s.Save(snap); err != nil {
			t.Fatalf("save %d failed: %v", i, err)
		}
	}

	points, err := s.Trend("web-cert", "prod", string(store.SourceWebhook), 10)
	if err != nil {
		t.Fatalf("trend failed: %v", err)
	}
	if len(points) != 3 {
		t.Fatalf("expected 3 trend points, got %d", len(points))
	}
	// Newest first
	if points[0].Severity != string(store.SeverityWarn) {
		t.Errorf("newest point severity = %q, want %q", points[0].Severity, store.SeverityWarn)
	}
}

func TestTrend_NoData(t *testing.T) {
	s := openMemory(t)
	points, err := s.Trend("nonexistent", "ns", "src", 10)
	if err != nil {
		t.Fatalf("trend failed: %v", err)
	}
	if len(points) != 0 {
		t.Errorf("expected 0 points, got %d", len(points))
	}
}

func TestList_EmptyDB(t *testing.T) {
	s := openMemory(t)
	summaries, err := s.List(10)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected 0 snapshots, got %d", len(summaries))
	}
}
