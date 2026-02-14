package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/ppiankov/trustwatch/internal/store"
)

func TestUpdate_EmptySnapshot(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewCollector(reg)

	snap := store.Snapshot{At: time.Now()}
	c.Update(snap, 500*time.Millisecond)

	if got := testutil.ToFloat64(c.scanDuration); got != 0.5 {
		t.Errorf("scanDuration = %v, want 0.5", got)
	}
	if got := testutil.ToFloat64(c.findingsTotal.With(prometheus.Labels{"severity": "info"})); got != 0 {
		t.Errorf("findings_total{info} = %v, want 0", got)
	}
	if got := testutil.ToFloat64(c.findingsTotal.With(prometheus.Labels{"severity": "warn"})); got != 0 {
		t.Errorf("findings_total{warn} = %v, want 0", got)
	}
	if got := testutil.ToFloat64(c.findingsTotal.With(prometheus.Labels{"severity": "critical"})); got != 0 {
		t.Errorf("findings_total{critical} = %v, want 0", got)
	}
}

func TestUpdate_MixedFindings(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewCollector(reg)

	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	snap := store.Snapshot{
		At: now,
		Findings: []store.CertFinding{
			{
				Source:    store.SourceWebhook,
				Severity:  store.SeverityCritical,
				Namespace: "default",
				Name:      "validator",
				NotAfter:  now.Add(48 * time.Hour),
				ProbeOK:   true,
			},
			{
				Source:    store.SourceAPIService,
				Severity:  store.SeverityWarn,
				Namespace: "kube-system",
				Name:      "v1.metrics",
				NotAfter:  now.Add(720 * time.Hour),
				ProbeOK:   true,
			},
			{
				Source:    store.SourceExternal,
				Severity:  store.SeverityInfo,
				Namespace: "",
				Name:      "api.example.com",
				NotAfter:  now.Add(8760 * time.Hour),
				ProbeOK:   true,
			},
		},
	}

	c.Update(snap, 2*time.Second)

	if got := testutil.ToFloat64(c.findingsTotal.With(prometheus.Labels{"severity": "critical"})); got != 1 {
		t.Errorf("findings_total{critical} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(c.findingsTotal.With(prometheus.Labels{"severity": "warn"})); got != 1 {
		t.Errorf("findings_total{warn} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(c.findingsTotal.With(prometheus.Labels{"severity": "info"})); got != 1 {
		t.Errorf("findings_total{info} = %v, want 1", got)
	}

	// Check cert_expires_in_seconds for the critical finding
	expiresIn := testutil.ToFloat64(c.certExpiresIn.With(prometheus.Labels{
		"source": "k8s.webhook", "namespace": "default", "name": "validator", "severity": "critical",
	}))
	wantExpiry := 48 * 3600.0
	if expiresIn != wantExpiry {
		t.Errorf("cert_expires_in_seconds = %v, want %v", expiresIn, wantExpiry)
	}

	// Check not_after timestamp
	notAfter := testutil.ToFloat64(c.certNotAfter.With(prometheus.Labels{
		"source": "k8s.webhook", "namespace": "default", "name": "validator", "severity": "critical",
	}))
	wantTS := float64(now.Add(48 * time.Hour).Unix())
	if notAfter != wantTS {
		t.Errorf("cert_not_after_timestamp = %v, want %v", notAfter, wantTS)
	}

	// Check probe_success
	probeOK := testutil.ToFloat64(c.probeSuccess.With(prometheus.Labels{
		"source": "k8s.webhook", "namespace": "default", "name": "validator",
	}))
	if probeOK != 1 {
		t.Errorf("probe_success = %v, want 1", probeOK)
	}

	if got := testutil.ToFloat64(c.scanDuration); got != 2 {
		t.Errorf("scanDuration = %v, want 2", got)
	}
}

func TestUpdate_ResetsStaleMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewCollector(reg)

	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	// First update with two findings
	snap1 := store.Snapshot{
		At: now,
		Findings: []store.CertFinding{
			{Source: store.SourceWebhook, Severity: store.SeverityCritical, Namespace: "a", Name: "one", NotAfter: now.Add(time.Hour), ProbeOK: true},
			{Source: store.SourceWebhook, Severity: store.SeverityWarn, Namespace: "a", Name: "two", NotAfter: now.Add(time.Hour), ProbeOK: true},
		},
	}
	c.Update(snap1, time.Second)

	if got := testutil.ToFloat64(c.findingsTotal.With(prometheus.Labels{"severity": "critical"})); got != 1 {
		t.Fatalf("after first update: critical = %v, want 1", got)
	}

	// Second update with only one finding — stale metric should be gone
	snap2 := store.Snapshot{
		At: now,
		Findings: []store.CertFinding{
			{Source: store.SourceWebhook, Severity: store.SeverityWarn, Namespace: "a", Name: "two", NotAfter: now.Add(time.Hour), ProbeOK: true},
		},
	}
	c.Update(snap2, time.Second)

	if got := testutil.ToFloat64(c.findingsTotal.With(prometheus.Labels{"severity": "critical"})); got != 0 {
		t.Errorf("after second update: critical = %v, want 0", got)
	}
	if got := testutil.ToFloat64(c.findingsTotal.With(prometheus.Labels{"severity": "warn"})); got != 1 {
		t.Errorf("after second update: warn = %v, want 1", got)
	}
}

func TestUpdate_ExpiredCert(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewCollector(reg)

	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	snap := store.Snapshot{
		At: now,
		Findings: []store.CertFinding{
			{
				Source:    store.SourceWebhook,
				Severity:  store.SeverityCritical,
				Namespace: "default",
				Name:      "expired-hook",
				NotAfter:  now.Add(-24 * time.Hour), // expired yesterday
				ProbeOK:   true,
			},
		},
	}

	c.Update(snap, time.Second)

	expiresIn := testutil.ToFloat64(c.certExpiresIn.With(prometheus.Labels{
		"source": "k8s.webhook", "namespace": "default", "name": "expired-hook", "severity": "critical",
	}))
	if expiresIn >= 0 {
		t.Errorf("cert_expires_in_seconds = %v, want negative", expiresIn)
	}
}

func TestUpdate_ProbeFailed(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewCollector(reg)

	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	snap := store.Snapshot{
		At: now,
		Findings: []store.CertFinding{
			{
				Source:    store.SourceExternal,
				Severity:  store.SeverityCritical,
				Namespace: "",
				Name:      "down.example.com",
				ProbeOK:   false,
				ProbeErr:  "connection refused",
			},
		},
	}

	c.Update(snap, time.Second)

	probeOK := testutil.ToFloat64(c.probeSuccess.With(prometheus.Labels{
		"source": "external", "namespace": "", "name": "down.example.com",
	}))
	if probeOK != 0 {
		t.Errorf("probe_success = %v, want 0", probeOK)
	}
}

func TestUpdate_DiscoveryErrors(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewCollector(reg)

	snap := store.Snapshot{
		At:     time.Now(),
		Errors: map[string]string{"webhooks": "forbidden", "apiservices": "timeout"},
	}
	c.Update(snap, time.Second)

	webhookErr := testutil.ToFloat64(c.discoveryErrors.With(prometheus.Labels{"source": "webhooks"}))
	if webhookErr != 1 {
		t.Errorf("discovery_errors_total{source=webhooks} = %v, want 1", webhookErr)
	}

	apiSvcErr := testutil.ToFloat64(c.discoveryErrors.With(prometheus.Labels{"source": "apiservices"}))
	if apiSvcErr != 1 {
		t.Errorf("discovery_errors_total{source=apiservices} = %v, want 1", apiSvcErr)
	}

	// Update without errors — should reset
	snap2 := store.Snapshot{At: time.Now()}
	c.Update(snap2, time.Second)

	// After reset, the metric should have no series for webhooks
	count := testutil.CollectAndCount(c.discoveryErrors)
	if count != 0 {
		t.Errorf("discovery_errors_total should have 0 series after reset, got %d", count)
	}
}
