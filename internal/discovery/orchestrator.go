package discovery

import (
	"log"
	"sync"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

// Orchestrator runs all discoverers concurrently and classifies findings.
type Orchestrator struct {
	nowFn       func() time.Time
	discoverers []Discoverer
	warnBefore  time.Duration
	critBefore  time.Duration
}

// NewOrchestrator creates an orchestrator with the given thresholds.
func NewOrchestrator(discoverers []Discoverer, warnBefore, critBefore time.Duration) *Orchestrator {
	return &Orchestrator{
		discoverers: discoverers,
		warnBefore:  warnBefore,
		critBefore:  critBefore,
		nowFn:       time.Now,
	}
}

// Run executes all discoverers concurrently and returns a classified snapshot.
// Individual discoverer failures are logged but do not abort the run.
func (o *Orchestrator) Run() store.Snapshot {
	type result struct {
		err      error
		name     string
		findings []store.CertFinding
	}

	ch := make(chan result, len(o.discoverers))
	var wg sync.WaitGroup

	for _, d := range o.discoverers {
		wg.Add(1)
		go func(d Discoverer) {
			defer wg.Done()
			findings, err := d.Discover()
			ch <- result{name: d.Name(), findings: findings, err: err}
		}(d)
	}

	wg.Wait()
	close(ch)

	now := o.nowFn()
	var allFindings []store.CertFinding

	for r := range ch {
		if r.err != nil {
			log.Printf("discoverer %s failed: %v", r.name, r.err)
			continue
		}
		log.Printf("discoverer %s: %d findings", r.name, len(r.findings))
		allFindings = append(allFindings, r.findings...)
	}

	o.classifyFindings(allFindings, now)

	return store.Snapshot{
		At:       now,
		Findings: allFindings,
	}
}

// classifyFindings applies severity based on time thresholds.
func (o *Orchestrator) classifyFindings(findings []store.CertFinding, now time.Time) {
	warnCutoff := now.Add(o.warnBefore)
	critCutoff := now.Add(o.critBefore)

	for i := range findings {
		f := &findings[i]

		// Skip findings without a valid cert (probe failed or no NotAfter)
		if !f.ProbeOK || f.NotAfter.IsZero() {
			continue
		}

		switch {
		case f.NotAfter.Before(now):
			// Already expired
			f.Severity = store.SeverityCritical
		case f.NotAfter.Before(critCutoff):
			// Within critical threshold
			f.Severity = store.SeverityCritical
		case f.NotAfter.Before(warnCutoff):
			// Within warning threshold — but escalate webhooks with failurePolicy=Fail
			if f.Source == store.SourceWebhook && f.Notes == "failurePolicy=Fail" {
				f.Severity = store.SeverityCritical
			} else {
				f.Severity = store.SeverityWarn
			}
		default:
			// Healthy — keep original severity (discoverers may set info or critical for structural reasons)
		}

		// Cap failurePolicy=Ignore webhooks at warn — cert expiry on these
		// won't break deployments since the API server skips the webhook on failure.
		if f.Source == store.SourceWebhook && f.Notes == "failurePolicy=Ignore" && f.Severity == store.SeverityCritical {
			f.Severity = store.SeverityWarn
		}
	}
}
