package discovery

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ppiankov/trustwatch/internal/store"
)

// SecretDiscoverer inventories TLS certificates stored in kubernetes.io/tls Secrets.
type SecretDiscoverer struct {
	client kubernetes.Interface
}

// NewSecretDiscoverer creates a discoverer that parses TLS Secrets for certificate metadata.
func NewSecretDiscoverer(client kubernetes.Interface) *SecretDiscoverer {
	return &SecretDiscoverer{client: client}
}

// Name returns the discoverer label.
func (d *SecretDiscoverer) Name() string {
	return "secrets"
}

// Discover lists all TLS Secrets and parses their leaf certificates.
func (d *SecretDiscoverer) Discover() ([]store.CertFinding, error) {
	ctx := context.Background()

	secrets, err := d.client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing secrets: %w", err)
	}

	var findings []store.CertFinding

	for i := range secrets.Items {
		s := &secrets.Items[i]
		if s.Type != corev1.SecretTypeTLS {
			continue
		}

		finding := store.CertFinding{
			Source:    store.SourceTLSSecret,
			Severity:  store.SeverityInfo,
			Namespace: s.Namespace,
			Name:      s.Name,
		}

		pemData, ok := s.Data["tls.crt"]
		if !ok {
			finding.ProbeOK = false
			finding.ProbeErr = "missing tls.crt key"
			findings = append(findings, finding)
			continue
		}

		cert, err := parsePEMCert(pemData)
		if err != nil {
			finding.ProbeOK = false
			finding.ProbeErr = err.Error()
			findings = append(findings, finding)
			continue
		}

		finding.ProbeOK = true
		finding.NotAfter = cert.NotAfter
		finding.DNSNames = cert.DNSNames
		finding.Issuer = cert.Issuer.String()
		finding.Subject = cert.Subject.String()
		finding.Serial = cert.SerialNumber.String()
		findings = append(findings, finding)
	}

	return findings, nil
}

// parsePEMCert decodes the first PEM block and parses it as an X.509 certificate.
func parsePEMCert(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}
