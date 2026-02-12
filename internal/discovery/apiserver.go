package discovery

import (
	"github.com/ppiankov/trustwatch/internal/probe"
	"github.com/ppiankov/trustwatch/internal/store"
)

const defaultAPIServerTarget = "kubernetes.default.svc:443"

// APIServerDiscoverer probes the Kubernetes API server TLS endpoint.
type APIServerDiscoverer struct {
	probeFn func(string) probe.Result
	target  string
}

// NewAPIServerDiscoverer creates a discoverer for the Kubernetes API server.
// If target is empty, defaults to kubernetes.default.svc:443.
func NewAPIServerDiscoverer(target string, opts ...func(*APIServerDiscoverer)) *APIServerDiscoverer {
	if target == "" {
		target = defaultAPIServerTarget
	}
	d := &APIServerDiscoverer{target: target, probeFn: probe.Probe}
	for _, o := range opts {
		o(d)
	}
	return d
}

// WithProbeFn sets a custom probe function (e.g. REST-transport-aware).
func WithProbeFn(fn func(string) probe.Result) func(*APIServerDiscoverer) {
	return func(d *APIServerDiscoverer) {
		d.probeFn = fn
	}
}

// Name returns the discoverer label.
func (d *APIServerDiscoverer) Name() string {
	return "apiserver"
}

// Discover probes the API server and returns a single finding.
func (d *APIServerDiscoverer) Discover() ([]store.CertFinding, error) {
	result := d.probeFn(probe.FormatTarget(d.target, ""))

	finding := store.CertFinding{
		Source:   store.SourceAPIServer,
		Severity: store.SeverityInfo,
		Name:     "kubernetes-apiserver",
		Target:   d.target,
		ProbeOK:  result.ProbeOK,
		ProbeErr: result.ProbeErr,
	}

	if result.ProbeOK && result.Cert != nil {
		finding.NotAfter = result.Cert.NotAfter
		finding.DNSNames = result.Cert.DNSNames
		finding.Issuer = result.Cert.Issuer.String()
		finding.Subject = result.Cert.Subject.String()
		finding.Serial = result.Cert.SerialNumber.String()
	}

	return []store.CertFinding{finding}, nil
}
