package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/ppiankov/trustwatch/internal/store"
)

var certGVR = schema.GroupVersionResource{
	Group:    "cert-manager.io",
	Version:  "v1",
	Resource: "certificates",
}

// CertManagerDiscoverer finds certificate expiry from cert-manager Certificate CRs.
// Uses the dynamic client to avoid importing the cert-manager module.
type CertManagerDiscoverer struct {
	dynamicClient dynamic.Interface
	coreClient    kubernetes.Interface
	namespaces    []string
}

// NewCertManagerDiscoverer creates a discoverer for cert-manager Certificate resources.
func NewCertManagerDiscoverer(dynClient dynamic.Interface, coreClient kubernetes.Interface, opts ...func(*CertManagerDiscoverer)) *CertManagerDiscoverer {
	d := &CertManagerDiscoverer{
		dynamicClient: dynClient,
		coreClient:    coreClient,
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// WithCertManagerNamespaces restricts discovery to the given namespaces.
func WithCertManagerNamespaces(ns []string) func(*CertManagerDiscoverer) {
	return func(d *CertManagerDiscoverer) {
		d.namespaces = ns
	}
}

// Name returns the discoverer label.
func (d *CertManagerDiscoverer) Name() string {
	return "certmanager"
}

// Discover lists cert-manager Certificate CRs and extracts expiry information.
// Returns nil, nil if cert-manager CRDs are not installed.
func (d *CertManagerDiscoverer) Discover() ([]store.CertFinding, error) {
	ctx := context.Background()

	if !d.certManagerInstalled() {
		slog.Debug("cert-manager CRDs not installed, skipping")
		return nil, nil
	}

	var findings []store.CertFinding
	for _, ns := range namespacesOrAll(d.namespaces) {
		certs, err := d.dynamicClient.Resource(certGVR).Namespace(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("listing cert-manager certificates: %w", err)
		}

		for i := range certs.Items {
			findings = append(findings, d.findingFromCert(ctx, &certs.Items[i]))
		}
	}

	return findings, nil
}

// findingFromCert builds a CertFinding from a single cert-manager Certificate CR.
func (d *CertManagerDiscoverer) findingFromCert(ctx context.Context, obj *unstructured.Unstructured) store.CertFinding {
	finding := store.CertFinding{
		Source:    store.SourceCertManager,
		Severity:  store.SeverityInfo,
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
	}

	spec := extractMap(obj.Object, "spec")
	d.populateSpecFields(&finding, spec)

	// Try status.notAfter first
	if notAfter := d.extractNotAfter(obj.Object); !notAfter.IsZero() {
		finding.NotAfter = notAfter
		finding.ProbeOK = true
		return finding
	}

	// Fall back to reading the Secret
	return d.populateFromSecret(ctx, &finding, spec)
}

// populateSpecFields extracts commonName, dnsNames, and issuerRef from the spec.
func (d *CertManagerDiscoverer) populateSpecFields(f *store.CertFinding, spec map[string]interface{}) {
	if spec == nil {
		return
	}
	if cn, ok := spec["commonName"].(string); ok {
		f.Subject = cn
	}
	if dnsNames, ok := spec["dnsNames"].([]interface{}); ok {
		for _, dn := range dnsNames {
			if s, ok := dn.(string); ok {
				f.DNSNames = append(f.DNSNames, s)
			}
		}
	}
	if issuerRef, ok := spec["issuerRef"].(map[string]interface{}); ok {
		issuerName, _ := issuerRef["name"].(string) //nolint:errcheck // type assertion to zero value
		issuerKind, _ := issuerRef["kind"].(string) //nolint:errcheck // type assertion to zero value
		if issuerKind == "" {
			issuerKind = "Issuer"
		}
		f.Issuer = fmt.Sprintf("%s/%s", issuerKind, issuerName)
	}
}

// populateFromSecret reads the TLS Secret referenced by spec.secretName and fills the finding.
func (d *CertManagerDiscoverer) populateFromSecret(ctx context.Context, f *store.CertFinding, spec map[string]interface{}) store.CertFinding {
	secretName := extractString(spec, "secretName")
	if secretName == "" {
		f.ProbeOK = false
		f.ProbeErr = "no status.notAfter and no spec.secretName"
		return *f
	}

	secret, err := d.coreClient.CoreV1().Secrets(f.Namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		f.ProbeOK = false
		f.ProbeErr = fmt.Sprintf("getting secret %s/%s: %s", f.Namespace, secretName, err)
		return *f
	}

	pemData, ok := secret.Data["tls.crt"]
	if !ok {
		f.ProbeOK = false
		f.ProbeErr = errMissingTLSCrt
		return *f
	}

	cert := applyPEMChainValidation(f, pemData, "")
	if cert == nil {
		return *f
	}

	f.ProbeOK = true
	f.NotAfter = cert.NotAfter
	if f.Subject == "" {
		f.Subject = cert.Subject.String()
	}
	if len(f.DNSNames) == 0 {
		f.DNSNames = cert.DNSNames
	}
	f.Serial = cert.SerialNumber.String()
	return *f
}

// certManagerInstalled checks if the cert-manager CRDs are registered.
func (d *CertManagerDiscoverer) certManagerInstalled() bool {
	_, err := d.coreClient.Discovery().ServerResourcesForGroupVersion("cert-manager.io/v1")
	return err == nil
}

// extractNotAfter reads status.notAfter from the unstructured object.
func (d *CertManagerDiscoverer) extractNotAfter(obj map[string]interface{}) time.Time {
	status, ok := obj["status"].(map[string]interface{})
	if !ok {
		return time.Time{}
	}
	notAfterStr, ok := status["notAfter"].(string)
	if !ok || notAfterStr == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, notAfterStr)
	if err != nil {
		return time.Time{}
	}
	return t
}

// extractMap safely extracts a nested map from an unstructured object.
func extractMap(obj map[string]interface{}, key string) map[string]interface{} {
	val, ok := obj[key].(map[string]interface{})
	if !ok {
		return nil
	}
	return val
}

// extractString safely extracts a string from a map.
func extractString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	val, ok := m[key].(string)
	if !ok {
		return ""
	}
	return val
}
