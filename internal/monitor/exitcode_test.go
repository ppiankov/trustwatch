package monitor

import (
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

func TestExitCode_NoFindings(t *testing.T) {
	snap := store.Snapshot{At: time.Now()}
	if got := ExitCode(snap); got != 0 {
		t.Errorf("ExitCode(empty) = %d, want 0", got)
	}
}

func TestExitCode_InfoOnly(t *testing.T) {
	snap := store.Snapshot{
		Findings: []store.CertFinding{
			{Severity: store.SeverityInfo, ProbeOK: true},
			{Severity: store.SeverityInfo, ProbeOK: true},
		},
	}
	if got := ExitCode(snap); got != 0 {
		t.Errorf("ExitCode(info) = %d, want 0", got)
	}
}

func TestExitCode_WarnPresent(t *testing.T) {
	snap := store.Snapshot{
		Findings: []store.CertFinding{
			{Severity: store.SeverityInfo, ProbeOK: true},
			{Severity: store.SeverityWarn, ProbeOK: true},
		},
	}
	if got := ExitCode(snap); got != 1 {
		t.Errorf("ExitCode(warn) = %d, want 1", got)
	}
}

func TestExitCode_CriticalPresent(t *testing.T) {
	snap := store.Snapshot{
		Findings: []store.CertFinding{
			{Severity: store.SeverityWarn, ProbeOK: true},
			{Severity: store.SeverityCritical, ProbeOK: true},
		},
	}
	if got := ExitCode(snap); got != 2 {
		t.Errorf("ExitCode(critical) = %d, want 2", got)
	}
}

func TestExitCode_ProbeError(t *testing.T) {
	snap := store.Snapshot{
		Findings: []store.CertFinding{
			{Severity: store.SeverityInfo, ProbeOK: true},
			{Severity: store.SeverityInfo, ProbeOK: false, ProbeErr: "connection refused"},
		},
	}
	if got := ExitCode(snap); got != 3 {
		t.Errorf("ExitCode(probe error) = %d, want 3", got)
	}
}

func TestExitCode_ProbeErrorTakesPrecedence(t *testing.T) {
	snap := store.Snapshot{
		Findings: []store.CertFinding{
			{Severity: store.SeverityCritical, ProbeOK: true},
			{Severity: store.SeverityInfo, ProbeOK: false, ProbeErr: "timeout"},
		},
	}
	if got := ExitCode(snap); got != 3 {
		t.Errorf("ExitCode(probe error + critical) = %d, want 3", got)
	}
}

func TestExitCode_DiscoveryErrors(t *testing.T) {
	snap := store.Snapshot{
		Findings: []store.CertFinding{
			{Severity: store.SeverityInfo, ProbeOK: true},
		},
		Errors: map[string]string{"webhooks": "forbidden"},
	}
	if got := ExitCode(snap); got != 3 {
		t.Errorf("ExitCode(discovery error) = %d, want 3", got)
	}
}
