package store

import "time"

// Severity classifies how urgent a finding is.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarn     Severity = "warn"
	SeverityCritical Severity = "critical"
)

// SourceKind identifies where a finding was discovered.
type SourceKind string

const (
	SourceTLSSecret  SourceKind = "k8s.tlsSecret"
	SourceIngressTLS SourceKind = "k8s.ingressTLS"
	SourceWebhook    SourceKind = "k8s.webhook"
	SourceAPIService SourceKind = "k8s.apiservice"
	SourceLinkerd    SourceKind = "mesh.linkerd"
	SourceIstio      SourceKind = "mesh.istio"
	SourceExternal   SourceKind = "external"
	SourceAPIServer  SourceKind = "k8s.apiserver"
	SourceAnnotation SourceKind = "annotation"
)

// CertFinding represents a single trust surface observation.
type CertFinding struct {
	Source    SourceKind `json:"source"`
	Severity  Severity   `json:"severity"`
	Namespace string     `json:"namespace,omitempty"`
	Name      string     `json:"name,omitempty"`
	Target    string     `json:"target,omitempty"`
	SNI       string     `json:"sni,omitempty"`
	NotAfter  time.Time  `json:"notAfter"`
	DNSNames  []string   `json:"dnsNames,omitempty"`
	Issuer    string     `json:"issuer,omitempty"`
	Subject   string     `json:"subject,omitempty"`
	Serial    string     `json:"serial,omitempty"`
	ProbeOK   bool       `json:"probeOk"`
	ProbeErr  string     `json:"probeError,omitempty"`
	Notes     string     `json:"notes,omitempty"`
}

// Snapshot is a point-in-time collection of findings.
type Snapshot struct {
	At       time.Time         `json:"at"`
	Findings []CertFinding     `json:"findings"`
	Errors   map[string]string `json:"errors,omitempty"` // discoverer name → error message
}
