package discovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ppiankov/trustwatch/internal/store"
)

// fakeWithCertManager creates a fake Kubernetes client whose discovery
// endpoint reports cert-manager.io/v1 as an available API group.
func fakeWithCertManager(objs ...runtime.Object) *fake.Clientset {
	cs := fake.NewClientset(objs...)
	fd := cs.Discovery().(*fakediscovery.FakeDiscovery)
	fd.Resources = append(fd.Resources, &metav1.APIResourceList{
		GroupVersion: "cert-manager.io/v1",
		APIResources: []metav1.APIResource{
			{Name: "certificates", Kind: "Certificate", Namespaced: true},
		},
	})
	return cs
}

// newDynamicClient creates a fake dynamic client with cert-manager Certificate objects.
func newDynamicClient(t *testing.T, certs ...*unstructured.Unstructured) *dynamicfake.FakeDynamicClient {
	t.Helper()
	scheme := runtime.NewScheme()
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"},
		&unstructured.Unstructured{},
	)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "CertificateList"},
		&unstructured.UnstructuredList{},
	)
	var objs []runtime.Object
	for _, c := range certs {
		objs = append(objs, c)
	}
	return dynamicfake.NewSimpleDynamicClient(scheme, objs...)
}

// makeCertificateCR builds an unstructured cert-manager Certificate object.
func makeCertificateCR(name, namespace string, opts ...func(map[string]interface{})) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "cert-manager.io",
		Version: "v1",
		Kind:    "Certificate",
	})
	obj.SetName(name)
	obj.SetNamespace(namespace)
	obj.Object["spec"] = map[string]interface{}{
		"secretName": name + "-tls",
		"commonName": name + ".example.com",
		"dnsNames":   []interface{}{name + ".example.com"},
		"issuerRef": map[string]interface{}{
			"name": "letsencrypt-prod",
			"kind": "ClusterIssuer",
		},
	}
	for _, o := range opts {
		o(obj.Object)
	}
	return obj
}

func withNotAfter(t time.Time) func(map[string]interface{}) {
	return func(obj map[string]interface{}) {
		status, ok := obj["status"].(map[string]interface{})
		if !ok {
			status = map[string]interface{}{}
		}
		status["notAfter"] = t.Format(time.RFC3339)
		obj["status"] = status
	}
}

func withSecretName(name string) func(map[string]interface{}) {
	return func(obj map[string]interface{}) {
		spec, ok := obj["spec"].(map[string]interface{})
		if !ok {
			spec = map[string]interface{}{}
		}
		spec["secretName"] = name
		obj["spec"] = spec
	}
}

func withNoSecretName() func(map[string]interface{}) {
	return func(obj map[string]interface{}) {
		spec, ok := obj["spec"].(map[string]interface{})
		if !ok {
			return
		}
		delete(spec, "secretName")
	}
}

// generateTestCertPEM creates a self-signed PEM certificate for tests.
func generateTestCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"test.example.com"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestCertManagerDiscoverer_Name(t *testing.T) {
	d := NewCertManagerDiscoverer(
		newDynamicClient(t),
		fakeWithCertManager(),
	)
	if d.Name() != "certmanager" {
		t.Errorf("expected name 'certmanager', got %q", d.Name())
	}
}

func TestCertManagerDiscoverer_CRDsAbsent(t *testing.T) {
	// Use a core client without cert-manager discovery
	coreClient := fake.NewClientset()
	dynClient := newDynamicClient(t)

	d := NewCertManagerDiscoverer(dynClient, coreClient)
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings when CRDs absent, got %d", len(findings))
	}
}

func TestCertManagerDiscoverer_ValidCertificate(t *testing.T) {
	notAfter := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	cert := makeCertificateCR("my-cert", testNS1, withNotAfter(notAfter))

	dynClient := newDynamicClient(t, cert)
	coreClient := fakeWithCertManager()

	d := NewCertManagerDiscoverer(dynClient, coreClient)
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Source != store.SourceCertManager {
		t.Errorf("expected source %q, got %q", store.SourceCertManager, f.Source)
	}
	if f.Name != "my-cert" {
		t.Errorf("expected name 'my-cert', got %q", f.Name)
	}
	if f.Namespace != testNS1 {
		t.Errorf("expected namespace %q, got %q", testNS1, f.Namespace)
	}
	if !f.ProbeOK {
		t.Error("expected ProbeOK true")
	}
	if !f.NotAfter.Equal(notAfter) {
		t.Errorf("expected notAfter %v, got %v", notAfter, f.NotAfter)
	}
	if f.Subject != "my-cert.example.com" {
		t.Errorf("expected subject 'my-cert.example.com', got %q", f.Subject)
	}
	if f.Issuer != "ClusterIssuer/letsencrypt-prod" {
		t.Errorf("expected issuer 'ClusterIssuer/letsencrypt-prod', got %q", f.Issuer)
	}
}

func TestCertManagerDiscoverer_FallbackToSecret(t *testing.T) {
	notAfter := time.Now().Add(15 * 24 * time.Hour).UTC().Truncate(time.Second)
	cert := makeCertificateCR("my-cert", testNS1, withSecretName("my-cert-tls"))

	pemData := generateTestCertPEM(t, notAfter)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "my-cert-tls", Namespace: testNS1},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("fake")},
	}

	dynClient := newDynamicClient(t, cert)
	coreClient := fakeWithCertManager(secret)

	d := NewCertManagerDiscoverer(dynClient, coreClient)
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if !f.ProbeOK {
		t.Errorf("expected ProbeOK true, got probeErr: %s", f.ProbeErr)
	}
	if f.Serial == "" {
		t.Error("expected serial from Secret cert, got empty")
	}
}

func TestCertManagerDiscoverer_SecretNotFound(t *testing.T) {
	cert := makeCertificateCR("my-cert", testNS1, withSecretName("nonexistent-secret"))

	dynClient := newDynamicClient(t, cert)
	coreClient := fakeWithCertManager()

	d := NewCertManagerDiscoverer(dynClient, coreClient)
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ProbeOK {
		t.Error("expected ProbeOK false when secret not found")
	}
	if f.ProbeErr == "" {
		t.Error("expected non-empty probeErr when secret not found")
	}
}

func TestCertManagerDiscoverer_NoCertificates(t *testing.T) {
	dynClient := newDynamicClient(t)
	coreClient := fakeWithCertManager()

	d := NewCertManagerDiscoverer(dynClient, coreClient)
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestCertManagerDiscoverer_NamespaceFiltered(t *testing.T) {
	notAfter := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	cert1 := makeCertificateCR("cert-in-ns1", testNS1, withNotAfter(notAfter))
	cert2 := makeCertificateCR("cert-in-ns2", testNS2, withNotAfter(notAfter))

	dynClient := newDynamicClient(t, cert1, cert2)
	coreClient := fakeWithCertManager()

	d := NewCertManagerDiscoverer(dynClient, coreClient, WithCertManagerNamespaces([]string{testNS1}))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (namespace filtered), got %d", len(findings))
	}
	if findings[0].Namespace != testNS1 {
		t.Errorf("expected finding in %q, got %q", testNS1, findings[0].Namespace)
	}
}

func TestCertManagerDiscoverer_NoSecretName(t *testing.T) {
	cert := makeCertificateCR("my-cert", testNS1, withNoSecretName())

	dynClient := newDynamicClient(t, cert)
	coreClient := fakeWithCertManager()

	d := NewCertManagerDiscoverer(dynClient, coreClient)
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ProbeOK {
		t.Error("expected ProbeOK false when no secretName and no status.notAfter")
	}
	if f.ProbeErr != "no status.notAfter and no spec.secretName" {
		t.Errorf("expected specific probeErr, got %q", f.ProbeErr)
	}
}
