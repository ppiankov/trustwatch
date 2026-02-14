package discovery

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ppiankov/trustwatch/internal/store"
)

// IngressDiscoverer finds TLS certificates referenced by Ingress objects.
type IngressDiscoverer struct {
	client     kubernetes.Interface
	namespaces []string
}

// NewIngressDiscoverer creates a discoverer that extracts TLS secrets from Ingress specs.
func NewIngressDiscoverer(client kubernetes.Interface, opts ...func(*IngressDiscoverer)) *IngressDiscoverer {
	d := &IngressDiscoverer{client: client}
	for _, o := range opts {
		o(d)
	}
	return d
}

// WithIngressNamespaces restricts discovery to the given namespaces.
func WithIngressNamespaces(ns []string) func(*IngressDiscoverer) {
	return func(d *IngressDiscoverer) {
		d.namespaces = ns
	}
}

// Name returns the discoverer label.
func (d *IngressDiscoverer) Name() string {
	return "ingress"
}

// Discover lists Ingresses, dereferences their TLS secret references,
// and parses the certificates found in those secrets.
func (d *IngressDiscoverer) Discover() ([]store.CertFinding, error) {
	ctx := context.Background()
	var findings []store.CertFinding

	for _, ns := range namespacesOrAll(d.namespaces) {
		ingresses, err := d.client.NetworkingV1().Ingresses(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("listing ingresses: %w", err)
		}

		for i := range ingresses.Items {
			ing := &ingresses.Items[i]
			for _, tls := range ing.Spec.TLS {
				if tls.SecretName == "" {
					continue
				}

				finding := d.findingFromIngressTLS(ctx, ing, tls)
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// findingFromIngressTLS builds a CertFinding by dereferencing the TLS secret.
func (d *IngressDiscoverer) findingFromIngressTLS(ctx context.Context, ing *networkingv1.Ingress, tls networkingv1.IngressTLS) store.CertFinding {
	finding := store.CertFinding{
		Source:    store.SourceIngressTLS,
		Severity:  store.SeverityInfo,
		Namespace: ing.Namespace,
		Name:      fmt.Sprintf("%s/%s", ing.Name, tls.SecretName),
	}

	secret, err := d.client.CoreV1().Secrets(ing.Namespace).Get(ctx, tls.SecretName, metav1.GetOptions{})
	if err != nil {
		finding.ProbeOK = false
		finding.ProbeErr = fmt.Sprintf("getting secret %s/%s: %s", ing.Namespace, tls.SecretName, err)
		return finding
	}

	if secret.Type != corev1.SecretTypeTLS {
		finding.ProbeOK = false
		finding.ProbeErr = fmt.Sprintf("secret %s/%s has type %s, expected %s", ing.Namespace, tls.SecretName, secret.Type, corev1.SecretTypeTLS)
		return finding
	}

	pemData, ok := secret.Data["tls.crt"]
	if !ok {
		finding.ProbeOK = false
		finding.ProbeErr = errMissingTLSCrt
		return finding
	}

	cert, err := parsePEMCert(pemData)
	if err != nil {
		finding.ProbeOK = false
		finding.ProbeErr = err.Error()
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
