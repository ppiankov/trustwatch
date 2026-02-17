package discovery

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"

	"fmt"

	"github.com/ppiankov/trustwatch/internal/ct"
	"github.com/ppiankov/trustwatch/internal/drift"
	"github.com/ppiankov/trustwatch/internal/policy"
	"github.com/ppiankov/trustwatch/internal/remediation"
	"github.com/ppiankov/trustwatch/internal/revocation"
	"github.com/ppiankov/trustwatch/internal/rotation"
	"github.com/ppiankov/trustwatch/internal/store"
)

// FindingManagedExpiry indicates a cert expiring but managed by cert-manager with healthy renewal.
const FindingManagedExpiry = "MANAGED_EXPIRY"

// Orchestrator runs all discoverers concurrently and classifies findings.
type Orchestrator struct {
	tracer           trace.Tracer
	nowFn            func() time.Time
	discoverTimer    func(string, time.Duration)
	crlCache         *revocation.CRLCache
	ctClient         *ct.Client
	prevSnap         *store.Snapshot
	policies         []policy.TrustPolicy
	discoverers      []Discoverer
	ctDomains        []string
	ctAllowedIssuers []string
	warnBefore       time.Duration
	critBefore       time.Duration
}

// OrchestratorOption configures an Orchestrator.
type OrchestratorOption func(*Orchestrator)

// WithTracer sets the OpenTelemetry tracer for discovery spans.
func WithTracer(t trace.Tracer) OrchestratorOption {
	return func(o *Orchestrator) {
		o.tracer = t
	}
}

// WithCheckRevocation enables OCSP/CRL revocation checking using the given cache.
func WithCheckRevocation(cache *revocation.CRLCache) OrchestratorOption {
	return func(o *Orchestrator) {
		o.crlCache = cache
	}
}

// WithCTCheck enables Certificate Transparency log monitoring for the given domains.
func WithCTCheck(domains, allowedIssuers []string, client *ct.Client) OrchestratorOption {
	return func(o *Orchestrator) {
		o.ctDomains = domains
		o.ctAllowedIssuers = allowedIssuers
		o.ctClient = client
	}
}

// WithDriftDetection enables certificate drift detection by comparing against a previous snapshot.
func WithDriftDetection(prev *store.Snapshot) OrchestratorOption {
	return func(o *Orchestrator) {
		o.prevSnap = prev
	}
}

// WithDiscoverTimer sets a callback invoked after each discoverer completes with its name and duration.
func WithDiscoverTimer(fn func(string, time.Duration)) OrchestratorOption {
	return func(o *Orchestrator) {
		o.discoverTimer = fn
	}
}

// WithPolicies adds TrustPolicy CRs for policy engine evaluation.
func WithPolicies(policies []policy.TrustPolicy) OrchestratorOption {
	return func(o *Orchestrator) {
		o.policies = policies
	}
}

// NewOrchestrator creates an orchestrator with the given thresholds.
func NewOrchestrator(discoverers []Discoverer, warnBefore, critBefore time.Duration, opts ...OrchestratorOption) *Orchestrator {
	o := &Orchestrator{
		discoverers: discoverers,
		warnBefore:  warnBefore,
		critBefore:  critBefore,
		nowFn:       time.Now,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// Run executes all discoverers concurrently and returns a classified snapshot.
// Individual discoverer failures are logged but do not abort the run.
func (o *Orchestrator) Run() store.Snapshot {
	ctx := context.Background()
	if o.tracer != nil {
		var span trace.Span
		ctx, span = o.tracer.Start(ctx, "discovery.run")
		defer span.End()
	}

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
			if o.tracer != nil {
				_, span := o.tracer.Start(ctx, "discover."+d.Name())
				defer span.End()
			}
			start := time.Now()
			findings, err := d.Discover()
			if o.discoverTimer != nil {
				o.discoverTimer(d.Name(), time.Since(start))
			}
			ch <- result{name: d.Name(), findings: findings, err: err}
		}(d)
	}

	wg.Wait()
	close(ch)

	now := o.nowFn()
	var allFindings []store.CertFinding
	discoveryErrors := make(map[string]string)

	for r := range ch {
		if r.err != nil {
			slog.Warn("discoverer failed", "source", r.name, "err", r.err)
			discoveryErrors[r.name] = r.err.Error()
			continue
		}
		slog.Debug("discoverer complete", "source", r.name, "findings", len(r.findings))
		allFindings = append(allFindings, r.findings...)
	}

	o.classifyFindings(allFindings, now)
	applyManagedExpiry(allFindings)

	// Check for excessive rotation frequency
	rotationFindings := rotation.Check(allFindings)
	allFindings = append(allFindings, rotationFindings...)

	// Run revocation checks if enabled
	if o.crlCache != nil {
		for i := range allFindings {
			f := &allFindings[i]
			if !f.ProbeOK || f.RawCert == nil {
				continue
			}
			if issues := revocation.Check(f.RawCert, f.RawIssuer, f.OCSPStaple, o.crlCache); len(issues) > 0 {
				f.RevocationIssues = issues
				for _, issue := range issues {
					if strings.Contains(issue, "CERT_REVOKED") {
						f.Severity = store.SeverityCritical
						break
					}
				}
			}
		}
	}

	// Clear transient fields before returning
	for i := range allFindings {
		allFindings[i].RawCert = nil
		allFindings[i].RawIssuer = nil
		allFindings[i].OCSPStaple = nil
	}

	// Run CT log comparison if enabled
	if len(o.ctDomains) > 0 && o.ctClient != nil {
		knownSerials := make(map[string]bool, len(allFindings))
		for i := range allFindings {
			if s := allFindings[i].Serial; s != "" {
				knownSerials[s] = true
			}
		}
		for _, domain := range o.ctDomains {
			entries, fetchErr := o.ctClient.FetchCerts(ctx, domain)
			if fetchErr != nil {
				slog.Warn("CT log query failed", "domain", domain, "err", fetchErr)
				discoveryErrors["ct:"+domain] = fetchErr.Error()
				continue
			}
			slog.Debug("CT log entries", "domain", domain, "count", len(entries))
			ctFindings := ct.Check(entries, knownSerials, o.ctAllowedIssuers)
			for i := range ctFindings {
				ctFindings[i].Target = domain
			}
			allFindings = append(allFindings, ctFindings...)
		}
	}

	// Evaluate policy rules
	if len(o.policies) > 0 {
		engine := policy.NewEngine(o.policies)
		violations := engine.Evaluate(allFindings)
		allFindings = append(allFindings, violations...)
	}

	// Populate remediation suggestions
	remediation.Apply(allFindings)

	// Detect certificate drift if previous snapshot is available
	if o.prevSnap != nil {
		driftFindings := drift.Detect(o.prevSnap.Findings, allFindings)
		allFindings = append(allFindings, driftFindings...)
	}

	snap := store.Snapshot{
		At:       now,
		Findings: allFindings,
	}
	if len(discoveryErrors) > 0 {
		snap.Errors = discoveryErrors
	}
	return snap
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
		if f.Source == store.SourceWebhook && f.Notes == notesFailPolicyIgnore && f.Severity == store.SeverityCritical {
			f.Severity = store.SeverityWarn
		}

		// Chain errors escalate info to warn (structural trust issue)
		if len(f.ChainErrors) > 0 && f.Severity == store.SeverityInfo {
			f.Severity = store.SeverityWarn
		}

		// Posture issues escalate info to warn (weak TLS config)
		if len(f.PostureIssues) > 0 && f.Severity == store.SeverityInfo {
			f.Severity = store.SeverityWarn
		}
	}
}

// applyManagedExpiry downgrades expiry findings for certs managed by healthy cert-manager renewals.
func applyManagedExpiry(findings []store.CertFinding) {
	// Index cert-manager managed certs by namespace/name and serial
	managedByName := make(map[string]bool)
	managedBySerial := make(map[string]string) // serial → namespace/name
	for i := range findings {
		f := &findings[i]
		if f.Source != store.SourceCertManager || !f.ProbeOK {
			continue
		}
		key := f.Namespace + "/" + f.Name
		managedByName[key] = true
		if f.Serial != "" {
			managedBySerial[f.Serial] = key
		}
	}

	if len(managedByName) == 0 {
		return
	}

	// Index unhealthy certs from renewal findings (REQUEST_PENDING = Certificate Ready=False)
	unhealthy := make(map[string]bool)
	for i := range findings {
		f := &findings[i]
		if f.Source == store.SourceCertManagerRenewal && f.FindingType == FindingRequestPending {
			unhealthy[f.Namespace+"/"+f.Name] = true
		}
	}

	// Apply suppression
	for i := range findings {
		f := &findings[i]
		if f.Severity != store.SeverityWarn && f.Severity != store.SeverityCritical {
			continue
		}

		var managedKey string
		if f.Source == store.SourceCertManager {
			key := f.Namespace + "/" + f.Name
			if managedByName[key] {
				managedKey = key
			}
		} else if f.Serial != "" {
			if key, ok := managedBySerial[f.Serial]; ok {
				managedKey = key
			}
		}

		if managedKey == "" {
			continue
		}

		if unhealthy[managedKey] {
			if f.Notes != "" {
				f.Notes += "; "
			}
			f.Notes += fmt.Sprintf("managed by cert-manager Certificate %s, renewal UNHEALTHY", managedKey)
		} else {
			f.FindingType = FindingManagedExpiry
			f.Severity = store.SeverityInfo
			f.Notes = fmt.Sprintf("managed by cert-manager Certificate %s, renewal healthy", managedKey)
		}
	}
}
