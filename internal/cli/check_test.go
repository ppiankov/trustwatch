package cli

import (
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

func TestCheckExitCode_NoFindings(t *testing.T) {
	snap := store.Snapshot{}
	if got := checkExitCode(snap, store.SeverityCritical); got != 0 {
		t.Errorf("expected exit code 0, got %d", got)
	}
}

func TestCheckExitCode_DiscoveryErrors(t *testing.T) {
	snap := store.Snapshot{
		Errors: map[string]string{"webhooks": "connection refused"},
	}
	if got := checkExitCode(snap, store.SeverityCritical); got != 3 {
		t.Errorf("expected exit code 3, got %d", got)
	}
}

func TestCheckExitCode_ProbeFailure(t *testing.T) {
	snap := store.Snapshot{
		Findings: []store.CertFinding{
			{ProbeOK: false, ProbeErr: "connection refused"},
		},
	}
	if got := checkExitCode(snap, store.SeverityCritical); got != 3 {
		t.Errorf("expected exit code 3, got %d", got)
	}
}

func TestCheckExitCode_CriticalFindings(t *testing.T) {
	snap := store.Snapshot{
		Findings: []store.CertFinding{
			{ProbeOK: true, Severity: store.SeverityCritical},
		},
	}
	if got := checkExitCode(snap, store.SeverityCritical); got != 2 {
		t.Errorf("expected exit code 2, got %d", got)
	}
}

func TestCheckExitCode_WarnFindings_ThresholdCritical(t *testing.T) {
	snap := store.Snapshot{
		Findings: []store.CertFinding{
			{ProbeOK: true, Severity: store.SeverityWarn},
		},
	}
	// With threshold=critical, warn findings should not trigger failure
	if got := checkExitCode(snap, store.SeverityCritical); got != 0 {
		t.Errorf("expected exit code 0, got %d", got)
	}
}

func TestCheckExitCode_WarnFindings_ThresholdWarn(t *testing.T) {
	snap := store.Snapshot{
		Findings: []store.CertFinding{
			{ProbeOK: true, Severity: store.SeverityWarn},
		},
	}
	if got := checkExitCode(snap, store.SeverityWarn); got != 1 {
		t.Errorf("expected exit code 1, got %d", got)
	}
}

func TestCheckExitCode_InfoFindings_ThresholdInfo(t *testing.T) {
	snap := store.Snapshot{
		Findings: []store.CertFinding{
			{ProbeOK: true, Severity: store.SeverityInfo},
		},
	}
	if got := checkExitCode(snap, store.SeverityInfo); got != 1 {
		t.Errorf("expected exit code 1, got %d", got)
	}
}

func TestCheckExitCode_InfoFindings_ThresholdWarn(t *testing.T) {
	snap := store.Snapshot{
		Findings: []store.CertFinding{
			{ProbeOK: true, Severity: store.SeverityInfo},
		},
	}
	// Info finding below warn threshold — should pass
	if got := checkExitCode(snap, store.SeverityWarn); got != 0 {
		t.Errorf("expected exit code 0, got %d", got)
	}
}

func TestApplyDeployWindow_Escalation(t *testing.T) {
	now := time.Now()
	findings := []store.CertFinding{
		{ProbeOK: true, Severity: store.SeverityInfo, NotAfter: now.Add(12 * time.Hour)}, // within 24h window
		{ProbeOK: true, Severity: store.SeverityInfo, NotAfter: now.Add(48 * time.Hour)}, // outside window
		{ProbeOK: true, Severity: store.SeverityWarn, NotAfter: now.Add(6 * time.Hour)},  // within window
		{ProbeOK: false, ProbeErr: "failed", NotAfter: now.Add(1 * time.Hour)},           // probe failed, skip
		{ProbeOK: true, Severity: store.SeverityInfo},                                    // no NotAfter, skip
	}

	applyDeployWindow(findings, 24*time.Hour, now)

	if findings[0].Severity != store.SeverityCritical {
		t.Errorf("findings[0]: expected critical, got %s", findings[0].Severity)
	}
	if findings[1].Severity != store.SeverityInfo {
		t.Errorf("findings[1]: expected info (outside window), got %s", findings[1].Severity)
	}
	if findings[2].Severity != store.SeverityCritical {
		t.Errorf("findings[2]: expected critical, got %s", findings[2].Severity)
	}
	if findings[3].Severity != "" {
		t.Errorf("findings[3]: expected unchanged (probe failed), got %s", findings[3].Severity)
	}
	if findings[4].Severity != store.SeverityInfo {
		t.Errorf("findings[4]: expected info (no NotAfter), got %s", findings[4].Severity)
	}
}

func TestMeetsThreshold(t *testing.T) {
	tests := []struct {
		name      string
		sev       store.Severity
		threshold store.Severity
		want      bool
	}{
		{"critical >= critical", store.SeverityCritical, store.SeverityCritical, true},
		{"warn >= warn", store.SeverityWarn, store.SeverityWarn, true},
		{"critical >= warn", store.SeverityCritical, store.SeverityWarn, true},
		{"warn >= critical", store.SeverityWarn, store.SeverityCritical, false},
		{"info >= info", store.SeverityInfo, store.SeverityInfo, true},
		{"info >= warn", store.SeverityInfo, store.SeverityWarn, false},
		{"warn >= info", store.SeverityWarn, store.SeverityInfo, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := meetsThreshold(tt.sev, tt.threshold); got != tt.want {
				t.Errorf("meetsThreshold(%s, %s) = %v, want %v", tt.sev, tt.threshold, got, tt.want)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input   string
		want    store.Severity
		wantErr bool
	}{
		{"info", store.SeverityInfo, false},
		{"warn", store.SeverityWarn, false},
		{"critical", store.SeverityCritical, false},
		{"invalid", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseSeverity(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSeverity(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("parseSeverity(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFilterManagedExpiry(t *testing.T) {
	findings := []store.CertFinding{
		{Name: "managed", FindingType: "MANAGED_EXPIRY", Severity: store.SeverityInfo},
		{Name: "normal", Severity: store.SeverityWarn},
		{Name: "critical", Severity: store.SeverityCritical},
	}
	filtered := filterManagedExpiry(findings)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(filtered))
	}
	if filtered[0].Name != "normal" {
		t.Errorf("expected first finding to be 'normal', got %q", filtered[0].Name)
	}
	if filtered[1].Name != "critical" {
		t.Errorf("expected second finding to be 'critical', got %q", filtered[1].Name)
	}
}

func TestCheckCommand_Registered(t *testing.T) {
	found := false
	for _, c := range rootCmd.Commands() {
		if c.Use == "check" {
			found = true
			break
		}
	}
	if !found {
		t.Error("check command not registered on root")
	}
}

func TestCheckCommand_Flags(t *testing.T) {
	flags := []string{
		"policy", "max-severity", "deploy-window",
		"config", "kubeconfig", "context", "namespace",
		"warn-before", "crit-before",
		"tunnel", "tunnel-ns", "tunnel-image",
		"check-revocation", "ct-domains", "ct-allowed-issuers",
		"ignore-managed",
		"spiffe-socket", "output", "quiet",
	}
	for _, name := range flags {
		if checkCmd.Flags().Lookup(name) == nil {
			t.Errorf("expected flag --%s on check command", name)
		}
	}
}
