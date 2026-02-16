// Package store defines the data model for trustwatch findings and snapshots.
package store

import (
	"crypto/x509"
	"time"
)

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
	SourceTLSSecret          SourceKind = "k8s.tlsSecret"
	SourceIngressTLS         SourceKind = "k8s.ingressTLS"
	SourceWebhook            SourceKind = "k8s.webhook"
	SourceAPIService         SourceKind = "k8s.apiservice"
	SourceLinkerd            SourceKind = "mesh.linkerd"
	SourceIstio              SourceKind = "mesh.istio"
	SourceExternal           SourceKind = "external"
	SourceAPIServer          SourceKind = "k8s.apiserver"
	SourceAnnotation         SourceKind = "annotation"
	SourceGateway            SourceKind = "k8s.gateway"
	SourceCertManager        SourceKind = "certmanager"
	SourceCertManagerRenewal SourceKind = "certmanager.renewal"
	SourcePolicy             SourceKind = "policy"
	SourceSPIFFE             SourceKind = "spiffe"
	SourceAWSACM             SourceKind = "cloud.aws.acm"
	SourceGCPManagedCert     SourceKind = "cloud.gcp.cert"
	SourceAzureKeyVault      SourceKind = "cloud.azure.keyvault"
	SourceCT                 SourceKind = "ct"
)

// CertFinding represents a single trust surface observation.
type CertFinding struct {
	NotAfter           time.Time         `json:"notAfter"`
	RawIssuer          *x509.Certificate `json:"-"`
	RawCert            *x509.Certificate `json:"-"`
	SignatureAlgorithm string            `json:"signatureAlgorithm,omitempty"`
	FindingType        string            `json:"findingType,omitempty"`
	Namespace          string            `json:"namespace,omitempty"`
	Cluster            string            `json:"cluster,omitempty"`
	Source             SourceKind        `json:"source"`
	Target             string            `json:"target,omitempty"`
	SNI                string            `json:"sni,omitempty"`
	Severity           Severity          `json:"severity"`
	Issuer             string            `json:"issuer,omitempty"`
	CipherSuite        string            `json:"cipherSuite,omitempty"`
	Notes              string            `json:"notes,omitempty"`
	ProbeErr           string            `json:"probeError,omitempty"`
	Serial             string            `json:"serial,omitempty"`
	Name               string            `json:"name,omitempty"`
	PolicyName         string            `json:"policyName,omitempty"`
	KeyAlgorithm       string            `json:"keyAlgorithm,omitempty"`
	Subject            string            `json:"subject,omitempty"`
	TLSVersion         string            `json:"tlsVersion,omitempty"`
	ChainErrors        []string          `json:"chainErrors,omitempty"`
	DNSNames           []string          `json:"dnsNames,omitempty"`
	IssuerChain        []string          `json:"issuerChain,omitempty"`
	RevocationIssues   []string          `json:"revocationIssues,omitempty"`
	PostureIssues      []string          `json:"postureIssues,omitempty"`
	OCSPStaple         []byte            `json:"-"`
	ChainLen           int               `json:"chainLen,omitempty"`
	KeySize            int               `json:"keySize,omitempty"`
	ProbeOK            bool              `json:"probeOk"`
	SelfSigned         bool              `json:"selfSigned,omitempty"`
}

// Snapshot is a point-in-time collection of findings.
type Snapshot struct {
	At       time.Time         `json:"at"`
	Errors   map[string]string `json:"errors,omitempty"`
	Findings []CertFinding     `json:"findings"`
}
