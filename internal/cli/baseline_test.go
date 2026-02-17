package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

func testSnapshot() store.Snapshot {
	return store.Snapshot{
		At: time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC),
		Findings: []store.CertFinding{
			{Source: store.SourceWebhook, Severity: store.SeverityCritical, Namespace: "default", Name: "hook1", Serial: "AA:BB", Issuer: "CN=CA1", ProbeOK: true},
			{Source: store.SourceAPIService, Severity: store.SeverityWarn, Namespace: "kube-system", Name: "v1.metrics", Serial: "CC:DD", Issuer: "CN=CA2", ProbeOK: true},
		},
	}
}

func TestBaselineSave_RoundTrip(t *testing.T) {
	snap := testSnapshot()
	snapJSON, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(t.TempDir(), "baseline.json")

	stdin := bytes.NewReader(snapJSON)
	stdout := new(bytes.Buffer)
	cmd := rootCmd
	cmd.SetIn(stdin)
	cmd.SetOut(stdout)
	cmd.SetErr(stdout)
	cmd.SetArgs([]string{"baseline", "save", "-o", outPath})
	if execErr := cmd.Execute(); execErr != nil {
		t.Fatalf("baseline save: %v", execErr)
	}

	if !strings.Contains(stdout.String(), "2 findings") {
		t.Errorf("expected '2 findings' in output, got: %q", stdout.String())
	}

	// Read back and verify
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var loaded store.Snapshot
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("parsing saved baseline: %v", err)
	}
	if len(loaded.Findings) != 2 {
		t.Errorf("loaded findings = %d, want 2", len(loaded.Findings))
	}
	if loaded.Findings[0].Serial != "AA:BB" {
		t.Errorf("serial = %q, want AA:BB", loaded.Findings[0].Serial)
	}
}

func TestBaselineCheck_NoDrift(t *testing.T) {
	snap := testSnapshot()
	snapJSON, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}

	// Save baseline
	baselinePath := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(baselinePath, snapJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	// Check with identical snapshot
	stdin := bytes.NewReader(snapJSON)
	stdout := new(bytes.Buffer)
	cmd := rootCmd
	cmd.SetIn(stdin)
	cmd.SetOut(stdout)
	cmd.SetErr(stdout)
	cmd.SetArgs([]string{"baseline", "check", baselinePath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("baseline check: %v", err)
	}

	if !strings.Contains(stdout.String(), "no drift") {
		t.Errorf("expected 'no drift' in output, got: %q", stdout.String())
	}
}

func TestBaselineSave_AcceptsNowOutputEnvelope(t *testing.T) {
	snap := testSnapshot()
	envelope := struct {
		Snapshot store.Snapshot `json:"snapshot"`
		ExitCode int            `json:"exitCode"`
	}{Snapshot: snap, ExitCode: 0}

	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(t.TempDir(), "baseline.json")

	stdin := bytes.NewReader(envelopeJSON)
	stdout := new(bytes.Buffer)
	cmd := rootCmd
	cmd.SetIn(stdin)
	cmd.SetOut(stdout)
	cmd.SetErr(stdout)
	cmd.SetArgs([]string{"baseline", "save", "-o", outPath})
	if execErr := cmd.Execute(); execErr != nil {
		t.Fatalf("baseline save with envelope: %v", execErr)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var loaded store.Snapshot
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("parsing saved baseline: %v", err)
	}
	if len(loaded.Findings) != 2 {
		t.Errorf("loaded findings = %d, want 2", len(loaded.Findings))
	}
}
