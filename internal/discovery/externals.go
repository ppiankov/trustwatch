package discovery

import (
	"github.com/ppiankov/trustwatch/internal/config"
	"github.com/ppiankov/trustwatch/internal/probe"
	"github.com/ppiankov/trustwatch/internal/store"
)

// ExternalDiscoverer probes explicit external TLS endpoints from config.
type ExternalDiscoverer struct {
	probeFn func(string) probe.Result
	targets []config.ExternalTarget
}

// NewExternalDiscoverer creates a discoverer for external TLS targets.
func NewExternalDiscoverer(targets []config.ExternalTarget, opts ...func(*ExternalDiscoverer)) *ExternalDiscoverer {
	d := &ExternalDiscoverer{
		targets: targets,
		probeFn: probe.Probe,
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// WithExternalProbeFn sets a custom probe function for external target discovery.
func WithExternalProbeFn(fn func(string) probe.Result) func(*ExternalDiscoverer) {
	return func(d *ExternalDiscoverer) {
		d.probeFn = fn
	}
}

// Name returns the discoverer label.
func (d *ExternalDiscoverer) Name() string {
	return "externals"
}

// Discover probes each configured external target.
func (d *ExternalDiscoverer) Discover() ([]store.CertFinding, error) {
	if len(d.targets) == 0 {
		return nil, nil
	}

	var findings []store.CertFinding

	for _, t := range d.targets {
		finding := store.CertFinding{
			Source:   store.SourceExternal,
			Severity: store.SeverityInfo,
			Target:   t.URL,
		}

		result := d.probeFn(t.URL)
		finding.ProbeOK = result.ProbeOK
		finding.ProbeErr = result.ProbeErr

		if result.ProbeOK && result.Cert != nil {
			finding.NotAfter = result.Cert.NotAfter
			finding.DNSNames = result.Cert.DNSNames
			finding.Issuer = result.Cert.Issuer.String()
			finding.Subject = result.Cert.Subject.String()
			finding.Serial = result.Cert.SerialNumber.String()
			applyProbeChainValidation(&finding, result, extractHostFromTarget(t.URL))
		}

		findings = append(findings, finding)
	}

	return findings, nil
}
