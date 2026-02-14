// Package store defines the data model for trustwatch findings and snapshots.
package store

import "time"

// Severity classifies how urgent a finding is.
type Severity string

// Severity levels for findings.
const (
	SeverityInfo     Severity = "info"
	SeverityWarn     Severity = "warn"
	SeverityCritical Severity = "critical"
)

// SourceKind identifies where a finding was discovered.
type SourceKind string

// Source kinds for findings.
const (
	SourceTLSSecret   SourceKind = "k8s.tlsSecret"
	SourceIngressTLS  SourceKind = "k8s.ingressTLS"
	SourceWebhook     SourceKind = "k8s.webhook"
	SourceAPIService  SourceKind = "k8s.apiservice"
	SourceLinkerd     SourceKind = "mesh.linkerd"
	SourceIstio       SourceKind = "mesh.istio"
	SourceExternal    SourceKind = "external"
	SourceAPIServer   SourceKind = "k8s.apiserver"
	SourceAnnotation  SourceKind = "annotation"
	SourceGateway     SourceKind = "k8s.gateway"
	SourceCertManager SourceKind = "certmanager"
)

// CertFinding represents a single trust surface observation.
type CertFinding struct {
	NotAfter    time.Time  `json:"notAfter"`
	Name        string     `json:"name,omitempty"`
	Namespace   string     `json:"namespace,omitempty"`
	Source      SourceKind `json:"source"`
	Target      string     `json:"target,omitempty"`
	SNI         string     `json:"sni,omitempty"`
	Severity    Severity   `json:"severity"`
	Issuer      string     `json:"issuer,omitempty"`
	Subject     string     `json:"subject,omitempty"`
	Serial      string     `json:"serial,omitempty"`
	ProbeErr    string     `json:"probeError,omitempty"`
	Notes       string     `json:"notes,omitempty"`
	ChainErrors []string   `json:"chainErrors,omitempty"`
	DNSNames    []string   `json:"dnsNames,omitempty"`
	ProbeOK     bool       `json:"probeOk"`
	ChainLen    int        `json:"chainLen,omitempty"`
}

// Snapshot is a point-in-time collection of findings.
type Snapshot struct {
	At       time.Time         `json:"at"`
	Errors   map[string]string `json:"errors,omitempty"`
	Findings []CertFinding     `json:"findings"`
}
