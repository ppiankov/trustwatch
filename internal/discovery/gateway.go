package discovery

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"github.com/ppiankov/trustwatch/internal/store"
)

// GatewayDiscoverer finds TLS certificates referenced by Gateway API Gateway objects.
type GatewayDiscoverer struct {
	gwClient   gatewayclient.Interface
	coreClient kubernetes.Interface
	namespaces []string
}

// NewGatewayDiscoverer creates a discoverer that extracts TLS secrets from Gateway listener specs.
func NewGatewayDiscoverer(gwClient gatewayclient.Interface, coreClient kubernetes.Interface, opts ...func(*GatewayDiscoverer)) *GatewayDiscoverer {
	d := &GatewayDiscoverer{
		gwClient:   gwClient,
		coreClient: coreClient,
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// WithGatewayNamespaces restricts discovery to the given namespaces.
func WithGatewayNamespaces(ns []string) func(*GatewayDiscoverer) {
	return func(d *GatewayDiscoverer) {
		d.namespaces = ns
	}
}

// Name returns the discoverer label.
func (d *GatewayDiscoverer) Name() string {
	return "gateway"
}

// Discover lists all Gateways, extracts TLS certificate references from listeners,
// and parses the certificates found in the referenced Secrets.
// Returns nil, nil if the Gateway API CRDs are not installed.
func (d *GatewayDiscoverer) Discover() ([]store.CertFinding, error) {
	ctx := context.Background()

	// Check if Gateway API CRDs are installed
	if !d.gatewayAPIInstalled() {
		slog.Debug("gateway API not installed, skipping")
		return nil, nil
	}

	var findings []store.CertFinding
	for _, ns := range namespacesOrAll(d.namespaces) {
		gateways, err := d.gwClient.GatewayV1().Gateways(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("listing gateways: %w", err)
		}

		for i := range gateways.Items {
			gw := &gateways.Items[i]
			for j := range gw.Spec.Listeners {
				listener := &gw.Spec.Listeners[j]
				if listener.TLS == nil {
					continue
				}
				for _, ref := range listener.TLS.CertificateRefs {
					f := d.findingFromCertRef(ctx, gw, listener, ref)
					findings = append(findings, f)
				}
			}
		}
	}

	return findings, nil
}

// gatewayAPIInstalled checks if the Gateway API resource group is registered.
func (d *GatewayDiscoverer) gatewayAPIInstalled() bool {
	_, err := d.coreClient.Discovery().ServerResourcesForGroupVersion("gateway.networking.k8s.io/v1")
	return err == nil
}

// findingFromCertRef builds a CertFinding by dereferencing a Gateway TLS certificate reference.
func (d *GatewayDiscoverer) findingFromCertRef(
	ctx context.Context,
	gw *gatewayv1.Gateway,
	listener *gatewayv1.Listener,
	ref gatewayv1.SecretObjectReference,
) store.CertFinding {
	secretName := string(ref.Name)
	secretNS := gw.Namespace
	if ref.Namespace != nil {
		secretNS = string(*ref.Namespace)
	}

	finding := store.CertFinding{
		Source:   store.SourceGateway,
		Severity: store.SeverityInfo,
		Name:     fmt.Sprintf("%s/%s/%s", gw.Name, listener.Name, secretName),
	}
	if gw.Namespace != "" {
		finding.Namespace = gw.Namespace
	}

	// Only handle core group Secret references
	if ref.Group != nil && string(*ref.Group) != "" {
		finding.ProbeOK = false
		finding.ProbeErr = fmt.Sprintf("unsupported certificateRef group %q", string(*ref.Group))
		return finding
	}
	if ref.Kind != nil && string(*ref.Kind) != "Secret" {
		finding.ProbeOK = false
		finding.ProbeErr = fmt.Sprintf("unsupported certificateRef kind %q", string(*ref.Kind))
		return finding
	}

	secret, err := d.coreClient.CoreV1().Secrets(secretNS).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		finding.ProbeOK = false
		finding.ProbeErr = fmt.Sprintf("getting secret %s/%s: %s", secretNS, secretName, err)
		return finding
	}

	if secret.Type != corev1.SecretTypeTLS {
		finding.ProbeOK = false
		finding.ProbeErr = fmt.Sprintf("secret %s/%s has type %s, expected %s",
			secretNS, secretName, secret.Type, corev1.SecretTypeTLS)
		return finding
	}

	pemData, ok := secret.Data["tls.crt"]
	if !ok {
		finding.ProbeOK = false
		finding.ProbeErr = errMissingTLSCrt
		return finding
	}

	cert := applyPEMChainValidation(&finding, pemData, "")
	if cert == nil {
		return finding
	}

	finding.ProbeOK = true
	finding.NotAfter = cert.NotAfter
	finding.DNSNames = cert.DNSNames
	finding.Issuer = cert.Issuer.String()
	finding.Subject = cert.Subject.String()
	finding.Serial = cert.SerialNumber.String()

	return finding
}
