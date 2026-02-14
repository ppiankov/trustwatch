package discovery

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ppiankov/trustwatch/internal/store"
)

const (
	istioNamespace      = "istio-system"
	istioCASecretName   = "istio-ca-secret"
	istioCACertsName    = "cacerts"
	istioRootCertCMName = "istio-ca-root-cert"
	istioCACertKey      = "ca-cert.pem"
	istioRootCertKey    = "root-cert.pem"
)

// IstioDiscoverer finds Istio CA and root certificates.
type IstioDiscoverer struct {
	client kubernetes.Interface
}

// NewIstioDiscoverer creates a discoverer for Istio mesh CA material.
func NewIstioDiscoverer(client kubernetes.Interface) *IstioDiscoverer {
	return &IstioDiscoverer{client: client}
}

// Name returns the discoverer label.
func (d *IstioDiscoverer) Name() string {
	return "istio"
}

// Discover checks for Istio presence and reads CA material from known locations.
// Returns nil findings (not an error) if Istio is not installed.
func (d *IstioDiscoverer) Discover() ([]store.CertFinding, error) {
	ctx := context.Background()

	_, err := d.client.CoreV1().Namespaces().Get(ctx, istioNamespace, metav1.GetOptions{})
	if err != nil {
		return nil, nil
	}

	var findings []store.CertFinding

	// Plug-in CA secret (takes precedence when present)
	pluginFindings, err := d.discoverPluginCA(ctx)
	if err != nil {
		return nil, err
	}
	findings = append(findings, pluginFindings...)

	// Self-signed CA secret (only if plug-in CA not found)
	if len(pluginFindings) == 0 {
		selfSignedFindings, err := d.discoverSelfSignedCA(ctx)
		if err != nil {
			return nil, err
		}
		findings = append(findings, selfSignedFindings...)
	}

	// Root cert ConfigMap (distributed to all namespaces by istiod)
	if f, err := d.discoverRootCertCM(ctx); err != nil {
		return nil, err
	} else if f != nil {
		findings = append(findings, *f)
	}

	return findings, nil
}

// discoverPluginCA reads the plug-in CA secret (cacerts).
func (d *IstioDiscoverer) discoverPluginCA(ctx context.Context) ([]store.CertFinding, error) {
	secret, err := d.client.CoreV1().Secrets(istioNamespace).Get(ctx, istioCACertsName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting secret %s/%s: %w", istioNamespace, istioCACertsName, err)
	}

	var findings []store.CertFinding

	// Intermediate/issuer cert
	if f := d.parseCertFromSecret(secret.Data, istioCACertKey, istioCACertsName, store.SeverityCritical, "CA issuer"); f != nil {
		findings = append(findings, *f)
	}

	// Root cert
	if f := d.parseCertFromSecret(secret.Data, istioRootCertKey, istioCACertsName, store.SeverityInfo, "root cert"); f != nil {
		findings = append(findings, *f)
	}

	return findings, nil
}

// discoverSelfSignedCA reads the self-signed CA secret (istio-ca-secret).
func (d *IstioDiscoverer) discoverSelfSignedCA(ctx context.Context) ([]store.CertFinding, error) {
	secret, err := d.client.CoreV1().Secrets(istioNamespace).Get(ctx, istioCASecretName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting secret %s/%s: %w", istioNamespace, istioCASecretName, err)
	}

	var findings []store.CertFinding

	if f := d.parseCertFromSecret(secret.Data, istioCACertKey, istioCASecretName, store.SeverityCritical, "self-signed CA"); f != nil {
		findings = append(findings, *f)
	}

	return findings, nil
}

// discoverRootCertCM reads the root cert ConfigMap distributed by istiod.
func (d *IstioDiscoverer) discoverRootCertCM(ctx context.Context) (*store.CertFinding, error) {
	cm, err := d.client.CoreV1().ConfigMaps(istioNamespace).Get(ctx, istioRootCertCMName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting configmap %s/%s: %w", istioNamespace, istioRootCertCMName, err)
	}

	finding := store.CertFinding{
		Source:    store.SourceIstio,
		Severity:  store.SeverityInfo,
		Namespace: istioNamespace,
		Name:      istioRootCertCMName,
		Notes:     "distributed root cert",
	}

	pemData, ok := cm.Data[istioRootCertKey]
	if !ok {
		finding.ProbeOK = false
		finding.ProbeErr = fmt.Sprintf("missing key %s", istioRootCertKey)
		return &finding, nil
	}

	cert := applyPEMChainValidation(&finding, []byte(pemData), "")
	if cert == nil {
		return &finding, nil
	}

	finding.ProbeOK = true
	finding.NotAfter = cert.NotAfter
	finding.DNSNames = cert.DNSNames
	finding.Issuer = cert.Issuer.String()
	finding.Subject = cert.Subject.String()
	finding.Serial = cert.SerialNumber.String()

	return &finding, nil
}

// parseCertFromSecret extracts and parses a PEM cert from secret data.
func (d *IstioDiscoverer) parseCertFromSecret(data map[string][]byte, key, secretName string, severity store.Severity, notes string) *store.CertFinding {
	finding := store.CertFinding{
		Source:    store.SourceIstio,
		Severity:  severity,
		Namespace: istioNamespace,
		Name:      fmt.Sprintf("%s/%s", secretName, key),
		Notes:     notes,
	}

	pemData, ok := data[key]
	if !ok {
		return nil
	}

	cert := applyPEMChainValidation(&finding, pemData, "")
	if cert == nil {
		return &finding
	}

	finding.ProbeOK = true
	finding.NotAfter = cert.NotAfter
	finding.DNSNames = cert.DNSNames
	finding.Issuer = cert.Issuer.String()
	finding.Subject = cert.Subject.String()
	finding.Serial = cert.SerialNumber.String()

	return &finding
}
