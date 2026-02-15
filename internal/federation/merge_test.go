package federation

import (
	"testing"

	"github.com/ppiankov/trustwatch/internal/store"
)

func TestMerge_LabelsApplied(t *testing.T) {
	local := store.Snapshot{
		Findings: []store.CertFinding{
			{Name: "local-cert", ProbeOK: true},
		},
	}

	remotes := map[string]store.Snapshot{
		"staging": {
			Findings: []store.CertFinding{
				{Name: "staging-cert", ProbeOK: true},
			},
		},
	}

	merged := Merge("prod", local, remotes)

	if len(merged.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(merged.Findings))
	}

	for _, f := range merged.Findings {
		if f.Cluster == "" {
			t.Errorf("finding %q has empty cluster label", f.Name)
		}
	}

	// Check specific labels
	var foundProd, foundStaging bool
	for _, f := range merged.Findings {
		switch f.Name {
		case "local-cert":
			if f.Cluster != "prod" {
				t.Errorf("local cert cluster = %q, want %q", f.Cluster, "prod")
			}
			foundProd = true
		case "staging-cert":
			if f.Cluster != "staging" {
				t.Errorf("staging cert cluster = %q, want %q", f.Cluster, "staging")
			}
			foundStaging = true
		}
	}
	if !foundProd || !foundStaging {
		t.Error("expected both prod and staging findings")
	}
}

func TestMerge_NoRemotes(t *testing.T) {
	local := store.Snapshot{
		Findings: []store.CertFinding{
			{Name: "cert", ProbeOK: true},
		},
	}

	merged := Merge("local", local, nil)
	if len(merged.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(merged.Findings))
	}
	if merged.Findings[0].Cluster != "local" {
		t.Errorf("cluster = %q, want %q", merged.Findings[0].Cluster, "local")
	}
}
