package discovery

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ppiankov/trustwatch/internal/store"
)

const (
	linkerdNamespace           = "linkerd"
	linkerdTrustRootsConfigMap = "linkerd-identity-trust-roots"
	linkerdTrustRootsKey       = "ca-bundle.crt"
	linkerdIssuerSecret        = "linkerd-identity-issuer"
	linkerdIssuerKeyDefault    = "crt.pem"
	linkerdIssuerKeyFallback   = "tls.crt"
)

// LinkerdDiscoverer finds Linkerd identity trust anchors and issuer certificates.
type LinkerdDiscoverer struct {
	client kubernetes.Interface
}

// NewLinkerdDiscoverer creates a discoverer for Linkerd mesh identity material.
func NewLinkerdDiscoverer(client kubernetes.Interface) *LinkerdDiscoverer {
	return &LinkerdDiscoverer{client: client}
}

// Name returns the discoverer label.
func (d *LinkerdDiscoverer) Name() string {
	return "linkerd"
}

// Discover checks for Linkerd presence and reads trust anchors and issuer cert.
// Returns nil findings (not an error) if Linkerd is not installed.
func (d *LinkerdDiscoverer) Discover() ([]store.CertFinding, error) {
	ctx := context.Background()

	// Check if the linkerd namespace exists
	_, err := d.client.CoreV1().Namespaces().Get(ctx, linkerdNamespace, metav1.GetOptions{})
	if err != nil {
		// Linkerd not installed — not an error, just nothing to report
		return nil, nil
	}

	var findings []store.CertFinding

	if f, err := d.discoverTrustRoots(ctx); err != nil {
		return nil, err
	} else if f != nil {
		findings = append(findings, *f)
	}

	if f, err := d.discoverIssuer(ctx); err != nil {
		return nil, err
	} else if f != nil {
		findings = append(findings, *f)
	}

	return findings, nil
}

// discoverTrustRoots reads the trust anchor CA bundle from the ConfigMap.
func (d *LinkerdDiscoverer) discoverTrustRoots(ctx context.Context) (*store.CertFinding, error) {
	cm, err := d.client.CoreV1().ConfigMaps(linkerdNamespace).Get(ctx, linkerdTrustRootsConfigMap, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting configmap %s/%s: %w", linkerdNamespace, linkerdTrustRootsConfigMap, err)
	}

	finding := store.CertFinding{
		Source:    store.SourceLinkerd,
		Severity:  store.SeverityInfo,
		Namespace: linkerdNamespace,
		Name:      linkerdTrustRootsConfigMap,
		Notes:     "trust anchor",
	}

	pemData, ok := cm.Data[linkerdTrustRootsKey]
	if !ok {
		finding.ProbeOK = false
		finding.ProbeErr = fmt.Sprintf("missing key %s", linkerdTrustRootsKey)
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

// discoverIssuer reads the identity issuer cert from the Secret.
func (d *LinkerdDiscoverer) discoverIssuer(ctx context.Context) (*store.CertFinding, error) {
	secret, err := d.client.CoreV1().Secrets(linkerdNamespace).Get(ctx, linkerdIssuerSecret, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting secret %s/%s: %w", linkerdNamespace, linkerdIssuerSecret, err)
	}

	finding := store.CertFinding{
		Source:    store.SourceLinkerd,
		Severity:  store.SeverityCritical,
		Namespace: linkerdNamespace,
		Name:      linkerdIssuerSecret,
		Notes:     "identity issuer",
	}

	pemData, ok := secret.Data[linkerdIssuerKeyDefault]
	if !ok {
		// Fall back to tls.crt for kubernetes.io/tls type secrets
		pemData, ok = secret.Data[linkerdIssuerKeyFallback]
	}
	if !ok {
		finding.ProbeOK = false
		finding.ProbeErr = fmt.Sprintf("missing key %s or %s", linkerdIssuerKeyDefault, linkerdIssuerKeyFallback)
		return &finding, nil
	}

	cert := applyPEMChainValidation(&finding, pemData, "")
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
