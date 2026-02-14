package discovery

import (
	"fmt"
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

// stubDiscoverer returns fixed findings or an error.
type stubDiscoverer struct {
	err      error
	name     string
	findings []store.CertFinding
}

func (s *stubDiscoverer) Name() string                           { return s.name }
func (s *stubDiscoverer) Discover() ([]store.CertFinding, error) { return s.findings, s.err }

func fixedNow() time.Time {
	return time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
}

const (
	testWarnBefore = 720 * time.Hour // 30 days
	testCritBefore = 336 * time.Hour // 14 days
)

func TestOrchestrator_NoDiscoverers(t *testing.T) {
	o := NewOrchestrator(nil, testWarnBefore, testCritBefore)
	o.nowFn = fixedNow
	snap := o.Run()

	if snap.At != fixedNow() {
		t.Errorf("expected At %v, got %v", fixedNow(), snap.At)
	}
	if len(snap.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(snap.Findings))
	}
}

func TestOrchestrator_SingleDiscoverer(t *testing.T) {
	now := fixedNow()
	findings := []store.CertFinding{
		{
			Source:   store.SourceTLSSecret,
			Severity: store.SeverityInfo,
			Name:     "healthy-cert",
			NotAfter: now.Add(365 * 24 * time.Hour),
			ProbeOK:  true,
		},
	}

	o := NewOrchestrator(
		[]Discoverer{&stubDiscoverer{name: "test", findings: findings}},
		testWarnBefore, testCritBefore,
	)
	o.nowFn = fixedNow
	snap := o.Run()

	if len(snap.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(snap.Findings))
	}
	// Healthy cert should stay info
	if snap.Findings[0].Severity != store.SeverityInfo {
		t.Errorf("expected severity %q, got %q", store.SeverityInfo, snap.Findings[0].Severity)
	}
}

func TestOrchestrator_MultipleDiscoverers(t *testing.T) {
	now := fixedNow()
	d1 := &stubDiscoverer{
		name:     "d1",
		findings: []store.CertFinding{{Source: store.SourceTLSSecret, Name: "a", NotAfter: now.Add(365 * 24 * time.Hour), ProbeOK: true}},
	}
	d2 := &stubDiscoverer{
		name:     "d2",
		findings: []store.CertFinding{{Source: store.SourceExternal, Name: "b", NotAfter: now.Add(365 * 24 * time.Hour), ProbeOK: true}},
	}

	o := NewOrchestrator([]Discoverer{d1, d2}, testWarnBefore, testCritBefore)
	o.nowFn = fixedNow
	snap := o.Run()

	if len(snap.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(snap.Findings))
	}
}

func TestOrchestrator_PartialFailure(t *testing.T) {
	now := fixedNow()
	good := &stubDiscoverer{
		name:     "good",
		findings: []store.CertFinding{{Source: store.SourceTLSSecret, Name: "cert", NotAfter: now.Add(365 * 24 * time.Hour), ProbeOK: true}},
	}
	bad := &stubDiscoverer{
		name: "bad",
		err:  fmt.Errorf("API server unreachable"),
	}

	o := NewOrchestrator([]Discoverer{good, bad}, testWarnBefore, testCritBefore)
	o.nowFn = fixedNow
	snap := o.Run()

	// Should still get the good discoverer's findings
	if len(snap.Findings) != 1 {
		t.Fatalf("expected 1 finding (partial failure), got %d", len(snap.Findings))
	}
	if snap.Findings[0].Name != "cert" {
		t.Errorf("expected finding from good discoverer, got %q", snap.Findings[0].Name)
	}
}

func TestOrchestrator_AllFailed(t *testing.T) {
	bad1 := &stubDiscoverer{name: "bad1", err: fmt.Errorf("fail1")}
	bad2 := &stubDiscoverer{name: "bad2", err: fmt.Errorf("fail2")}

	o := NewOrchestrator([]Discoverer{bad1, bad2}, testWarnBefore, testCritBefore)
	o.nowFn = fixedNow
	snap := o.Run()

	if len(snap.Findings) != 0 {
		t.Errorf("expected 0 findings when all fail, got %d", len(snap.Findings))
	}
}

func TestOrchestrator_ClassifyExpired(t *testing.T) {
	now := fixedNow()
	findings := []store.CertFinding{
		{
			Source:   store.SourceTLSSecret,
			Severity: store.SeverityInfo,
			Name:     "expired-cert",
			NotAfter: now.Add(-24 * time.Hour), // expired yesterday
			ProbeOK:  true,
		},
	}

	o := NewOrchestrator(
		[]Discoverer{&stubDiscoverer{name: "test", findings: findings}},
		testWarnBefore, testCritBefore,
	)
	o.nowFn = fixedNow
	snap := o.Run()

	if snap.Findings[0].Severity != store.SeverityCritical {
		t.Errorf("expired cert: expected severity %q, got %q", store.SeverityCritical, snap.Findings[0].Severity)
	}
}

func TestOrchestrator_ClassifyCritical(t *testing.T) {
	now := fixedNow()
	findings := []store.CertFinding{
		{
			Source:   store.SourceTLSSecret,
			Severity: store.SeverityInfo,
			Name:     "soon-cert",
			NotAfter: now.Add(7 * 24 * time.Hour), // 7 days out (within 14d critBefore)
			ProbeOK:  true,
		},
	}

	o := NewOrchestrator(
		[]Discoverer{&stubDiscoverer{name: "test", findings: findings}},
		testWarnBefore, testCritBefore,
	)
	o.nowFn = fixedNow
	snap := o.Run()

	if snap.Findings[0].Severity != store.SeverityCritical {
		t.Errorf("crit-threshold cert: expected severity %q, got %q", store.SeverityCritical, snap.Findings[0].Severity)
	}
}

func TestOrchestrator_ClassifyWarn(t *testing.T) {
	now := fixedNow()
	findings := []store.CertFinding{
		{
			Source:   store.SourceTLSSecret,
			Severity: store.SeverityInfo,
			Name:     "warning-cert",
			NotAfter: now.Add(20 * 24 * time.Hour), // 20 days out (within 30d warnBefore, outside 14d critBefore)
			ProbeOK:  true,
		},
	}

	o := NewOrchestrator(
		[]Discoverer{&stubDiscoverer{name: "test", findings: findings}},
		testWarnBefore, testCritBefore,
	)
	o.nowFn = fixedNow
	snap := o.Run()

	if snap.Findings[0].Severity != store.SeverityWarn {
		t.Errorf("warn-threshold cert: expected severity %q, got %q", store.SeverityWarn, snap.Findings[0].Severity)
	}
}

func TestOrchestrator_ClassifyHealthy(t *testing.T) {
	now := fixedNow()
	findings := []store.CertFinding{
		{
			Source:   store.SourceTLSSecret,
			Severity: store.SeverityInfo,
			Name:     "healthy-cert",
			NotAfter: now.Add(365 * 24 * time.Hour), // 1 year out
			ProbeOK:  true,
		},
	}

	o := NewOrchestrator(
		[]Discoverer{&stubDiscoverer{name: "test", findings: findings}},
		testWarnBefore, testCritBefore,
	)
	o.nowFn = fixedNow
	snap := o.Run()

	if snap.Findings[0].Severity != store.SeverityInfo {
		t.Errorf("healthy cert: expected severity %q, got %q", store.SeverityInfo, snap.Findings[0].Severity)
	}
}

func TestOrchestrator_WebhookEscalation(t *testing.T) {
	now := fixedNow()
	findings := []store.CertFinding{
		{
			Source:   store.SourceWebhook,
			Severity: store.SeverityInfo,
			Name:     "fail-webhook",
			NotAfter: now.Add(20 * 24 * time.Hour), // 20 days (in warn zone)
			ProbeOK:  true,
			Notes:    "failurePolicy=Fail",
		},
		{
			Source:   store.SourceWebhook,
			Severity: store.SeverityInfo,
			Name:     "ignore-webhook",
			NotAfter: now.Add(20 * 24 * time.Hour), // 20 days (in warn zone)
			ProbeOK:  true,
			Notes:    "failurePolicy=Ignore",
		},
	}

	o := NewOrchestrator(
		[]Discoverer{&stubDiscoverer{name: "test", findings: findings}},
		testWarnBefore, testCritBefore,
	)
	o.nowFn = fixedNow
	snap := o.Run()

	if len(snap.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(snap.Findings))
	}

	// failurePolicy=Fail should escalate from warn to critical
	if snap.Findings[0].Severity != store.SeverityCritical {
		t.Errorf("Fail webhook in warn zone: expected severity %q, got %q", store.SeverityCritical, snap.Findings[0].Severity)
	}

	// failurePolicy=Ignore stays at warn
	if snap.Findings[1].Severity != store.SeverityWarn {
		t.Errorf("Ignore webhook in warn zone: expected severity %q, got %q", store.SeverityWarn, snap.Findings[1].Severity)
	}
}

func TestOrchestrator_IgnoreWebhookSeverityCap(t *testing.T) {
	now := fixedNow()
	findings := []store.CertFinding{
		{
			Source:   store.SourceWebhook,
			Severity: store.SeverityInfo,
			Name:     "expired-ignore-webhook",
			NotAfter: now.Add(-24 * time.Hour), // expired
			ProbeOK:  true,
			Notes:    "failurePolicy=Ignore",
		},
		{
			Source:   store.SourceWebhook,
			Severity: store.SeverityInfo,
			Name:     "crit-zone-ignore-webhook",
			NotAfter: now.Add(7 * 24 * time.Hour), // within crit threshold
			ProbeOK:  true,
			Notes:    "failurePolicy=Ignore",
		},
		{
			Source:   store.SourceWebhook,
			Severity: store.SeverityCritical,
			Name:     "expired-fail-webhook",
			NotAfter: now.Add(-24 * time.Hour), // expired
			ProbeOK:  true,
			Notes:    "failurePolicy=Fail",
		},
	}

	o := NewOrchestrator(
		[]Discoverer{&stubDiscoverer{name: "test", findings: findings}},
		testWarnBefore, testCritBefore,
	)
	o.nowFn = fixedNow
	snap := o.Run()

	if len(snap.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(snap.Findings))
	}

	// Expired Ignore webhook should be capped at warn, not critical
	if snap.Findings[0].Severity != store.SeverityWarn {
		t.Errorf("expired Ignore webhook: expected %q, got %q", store.SeverityWarn, snap.Findings[0].Severity)
	}

	// Crit-zone Ignore webhook should be capped at warn
	if snap.Findings[1].Severity != store.SeverityWarn {
		t.Errorf("crit-zone Ignore webhook: expected %q, got %q", store.SeverityWarn, snap.Findings[1].Severity)
	}

	// Expired Fail webhook should stay critical
	if snap.Findings[2].Severity != store.SeverityCritical {
		t.Errorf("expired Fail webhook: expected %q, got %q", store.SeverityCritical, snap.Findings[2].Severity)
	}
}

func TestOrchestrator_SkipsProbeFailedFindings(t *testing.T) {
	findings := []store.CertFinding{
		{
			Source:   store.SourceTLSSecret,
			Severity: store.SeverityInfo,
			Name:     "failed-probe",
			ProbeOK:  false,
			ProbeErr: "connection refused",
		},
	}

	o := NewOrchestrator(
		[]Discoverer{&stubDiscoverer{name: "test", findings: findings}},
		testWarnBefore, testCritBefore,
	)
	o.nowFn = fixedNow
	snap := o.Run()

	// Severity should remain unchanged (classification skipped)
	if snap.Findings[0].Severity != store.SeverityInfo {
		t.Errorf("probe-failed finding: expected severity unchanged at %q, got %q", store.SeverityInfo, snap.Findings[0].Severity)
	}
}

func TestOrchestrator_SnapshotTimestamp(t *testing.T) {
	o := NewOrchestrator(nil, testWarnBefore, testCritBefore)
	o.nowFn = fixedNow
	snap := o.Run()

	if !snap.At.Equal(fixedNow()) {
		t.Errorf("expected snapshot At %v, got %v", fixedNow(), snap.At)
	}
}

func TestOrchestrator_ConcurrentExecution(t *testing.T) {
	// Verify all discoverers run (order doesn't matter)
	var discoverers []Discoverer
	for i := 0; i < 10; i++ {
		discoverers = append(discoverers, &stubDiscoverer{
			name: fmt.Sprintf("d%d", i),
			findings: []store.CertFinding{
				{Source: store.SourceTLSSecret, Name: fmt.Sprintf("cert-%d", i), NotAfter: fixedNow().Add(365 * 24 * time.Hour), ProbeOK: true},
			},
		})
	}

	o := NewOrchestrator(discoverers, testWarnBefore, testCritBefore)
	o.nowFn = fixedNow
	snap := o.Run()

	if len(snap.Findings) != 10 {
		t.Errorf("expected 10 findings from 10 concurrent discoverers, got %d", len(snap.Findings))
	}
}

func TestOrchestrator_PreservesOriginalSeverityWhenHealthy(t *testing.T) {
	now := fixedNow()
	// Some discoverers set critical severity structurally (e.g. apiservice, issuer certs)
	findings := []store.CertFinding{
		{
			Source:   store.SourceAPIService,
			Severity: store.SeverityCritical,
			Name:     "metrics-server",
			NotAfter: now.Add(365 * 24 * time.Hour), // healthy
			ProbeOK:  true,
		},
	}

	o := NewOrchestrator(
		[]Discoverer{&stubDiscoverer{name: "test", findings: findings}},
		testWarnBefore, testCritBefore,
	)
	o.nowFn = fixedNow
	snap := o.Run()

	// Should preserve the structural critical severity
	if snap.Findings[0].Severity != store.SeverityCritical {
		t.Errorf("expected structural severity preserved as %q, got %q", store.SeverityCritical, snap.Findings[0].Severity)
	}
}
