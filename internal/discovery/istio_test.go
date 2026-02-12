package discovery

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ppiankov/trustwatch/internal/store"
)

func istioNamespaceObj() *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: istioNamespace},
	}
}

func TestIstioDiscoverer_ImplementsDiscoverer(_ *testing.T) {
	var _ Discoverer = (*IstioDiscoverer)(nil)
}

func TestIstioDiscoverer_Name(t *testing.T) {
	d := NewIstioDiscoverer(fake.NewClientset())
	if d.Name() != "istio" {
		t.Errorf("expected name %q, got %q", "istio", d.Name())
	}
}

func TestIstioDiscoverer_NoIstioNamespace(t *testing.T) {
	d := NewIstioDiscoverer(fake.NewClientset())
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when Istio not installed, got %d", len(findings))
	}
}

func TestIstioDiscoverer_PluginCA(t *testing.T) {
	issuerNotAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	rootNotAfter := time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second)

	issuerPEM := testCert(t, issuerNotAfter, []string{"istiod.istio-system.svc"})
	rootPEM := testCert(t, rootNotAfter, []string{"istio-ca-root"})

	objs := []runtime.Object{
		istioNamespaceObj(),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: istioCACertsName, Namespace: istioNamespace},
			Data: map[string][]byte{
				istioCACertKey:   issuerPEM,
				istioRootCertKey: rootPEM,
			},
		},
	}

	d := NewIstioDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (issuer + root from cacerts), got %d", len(findings))
	}

	// Issuer cert
	iss := findings[0]
	if iss.Source != store.SourceIstio {
		t.Errorf("issuer: expected source %q, got %q", store.SourceIstio, iss.Source)
	}
	if iss.Severity != store.SeverityCritical {
		t.Errorf("issuer: expected severity %q, got %q", store.SeverityCritical, iss.Severity)
	}
	if iss.Name != "cacerts/ca-cert.pem" {
		t.Errorf("issuer: expected name %q, got %q", "cacerts/ca-cert.pem", iss.Name)
	}
	if !iss.ProbeOK {
		t.Errorf("issuer: expected ProbeOK=true, got error: %s", iss.ProbeErr)
	}
	if !iss.NotAfter.Equal(issuerNotAfter) {
		t.Errorf("issuer: expected NotAfter %v, got %v", issuerNotAfter, iss.NotAfter)
	}
	if iss.Notes != "CA issuer" {
		t.Errorf("issuer: expected notes %q, got %q", "CA issuer", iss.Notes)
	}

	// Root cert
	root := findings[1]
	if root.Severity != store.SeverityInfo {
		t.Errorf("root: expected severity %q, got %q", store.SeverityInfo, root.Severity)
	}
	if root.Name != "cacerts/root-cert.pem" {
		t.Errorf("root: expected name %q, got %q", "cacerts/root-cert.pem", root.Name)
	}
	if !root.NotAfter.Equal(rootNotAfter) {
		t.Errorf("root: expected NotAfter %v, got %v", rootNotAfter, root.NotAfter)
	}
	if root.Notes != "root cert" {
		t.Errorf("root: expected notes %q, got %q", "root cert", root.Notes)
	}
}

func TestIstioDiscoverer_SelfSignedCA(t *testing.T) {
	caNotAfter := time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second)
	caPEM := testCert(t, caNotAfter, []string{"istio-ca"})

	objs := []runtime.Object{
		istioNamespaceObj(),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: istioCASecretName, Namespace: istioNamespace},
			Data:       map[string][]byte{istioCACertKey: caPEM},
		},
	}

	d := NewIstioDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (self-signed CA), got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != store.SeverityCritical {
		t.Errorf("expected severity %q, got %q", store.SeverityCritical, f.Severity)
	}
	if f.Name != "istio-ca-secret/ca-cert.pem" {
		t.Errorf("expected name %q, got %q", "istio-ca-secret/ca-cert.pem", f.Name)
	}
	if !f.ProbeOK {
		t.Errorf("expected ProbeOK=true, got error: %s", f.ProbeErr)
	}
	if f.Notes != "self-signed CA" {
		t.Errorf("expected notes %q, got %q", "self-signed CA", f.Notes)
	}
}

func TestIstioDiscoverer_PluginCATakesPrecedence(t *testing.T) {
	pem := testCert(t, time.Now().Add(time.Hour), nil)

	objs := []runtime.Object{
		istioNamespaceObj(),
		// Both secrets exist — plug-in CA should take precedence
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: istioCACertsName, Namespace: istioNamespace},
			Data:       map[string][]byte{istioCACertKey: pem},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: istioCASecretName, Namespace: istioNamespace},
			Data:       map[string][]byte{istioCACertKey: pem},
		},
	}

	d := NewIstioDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have 1 finding from cacerts, NOT from istio-ca-secret
	hasPluginCA := false
	hasSelfSigned := false
	for _, f := range findings {
		if f.Name == "cacerts/ca-cert.pem" {
			hasPluginCA = true
		}
		if f.Name == "istio-ca-secret/ca-cert.pem" {
			hasSelfSigned = true
		}
	}
	if !hasPluginCA {
		t.Error("expected plug-in CA finding")
	}
	if hasSelfSigned {
		t.Error("self-signed CA should be skipped when plug-in CA exists")
	}
}

func TestIstioDiscoverer_RootCertConfigMap(t *testing.T) {
	rootNotAfter := time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second)
	rootPEM := testCert(t, rootNotAfter, []string{"istio-root"})

	objs := []runtime.Object{
		istioNamespaceObj(),
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: istioRootCertCMName, Namespace: istioNamespace},
			Data:       map[string]string{istioRootCertKey: string(rootPEM)},
		},
	}

	d := NewIstioDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (root cert CM), got %d", len(findings))
	}

	f := findings[0]
	if f.Source != store.SourceIstio {
		t.Errorf("expected source %q, got %q", store.SourceIstio, f.Source)
	}
	if f.Severity != store.SeverityInfo {
		t.Errorf("expected severity %q, got %q", store.SeverityInfo, f.Severity)
	}
	if f.Name != istioRootCertCMName {
		t.Errorf("expected name %q, got %q", istioRootCertCMName, f.Name)
	}
	if !f.ProbeOK {
		t.Errorf("expected ProbeOK=true, got error: %s", f.ProbeErr)
	}
	if !f.NotAfter.Equal(rootNotAfter) {
		t.Errorf("expected NotAfter %v, got %v", rootNotAfter, f.NotAfter)
	}
	if f.Notes != "distributed root cert" {
		t.Errorf("expected notes %q, got %q", "distributed root cert", f.Notes)
	}
}

func TestIstioDiscoverer_RootCertCMMissingKey(t *testing.T) {
	objs := []runtime.Object{
		istioNamespaceObj(),
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: istioRootCertCMName, Namespace: istioNamespace},
			Data:       map[string]string{"wrong-key": "data"},
		},
	}

	d := NewIstioDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ProbeOK {
		t.Error("expected ProbeOK=false for missing key")
	}
	if f.ProbeErr == "" {
		t.Error("expected non-empty ProbeErr")
	}
}

func TestIstioDiscoverer_MalformedPEM(t *testing.T) {
	objs := []runtime.Object{
		istioNamespaceObj(),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: istioCASecretName, Namespace: istioNamespace},
			Data:       map[string][]byte{istioCACertKey: []byte("not-valid-pem")},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: istioRootCertCMName, Namespace: istioNamespace},
			Data:       map[string]string{istioRootCertKey: "not-valid-pem"},
		},
	}

	d := NewIstioDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	for _, f := range findings {
		if f.ProbeOK {
			t.Errorf("%s: expected ProbeOK=false for malformed PEM", f.Name)
		}
		if f.ProbeErr == "" {
			t.Errorf("%s: expected non-empty ProbeErr", f.Name)
		}
	}
}

func TestIstioDiscoverer_NamespaceOnly(t *testing.T) {
	// Namespace exists but no secrets or configmaps
	objs := []runtime.Object{istioNamespaceObj()}

	d := NewIstioDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no CA material exists, got %d", len(findings))
	}
}

func TestIstioDiscoverer_AllFieldsPopulated(t *testing.T) {
	pem := testCert(t, time.Now().Add(time.Hour), []string{"test.local"})

	objs := []runtime.Object{
		istioNamespaceObj(),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: istioCACertsName, Namespace: istioNamespace},
			Data:       map[string][]byte{istioCACertKey: pem, istioRootCertKey: pem},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: istioRootCertCMName, Namespace: istioNamespace},
			Data:       map[string]string{istioRootCertKey: string(pem)},
		},
	}

	d := NewIstioDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Namespace != istioNamespace {
			t.Errorf("%s: expected namespace %q, got %q", f.Name, istioNamespace, f.Namespace)
		}
		if f.Source != store.SourceIstio {
			t.Errorf("%s: expected source %q, got %q", f.Name, store.SourceIstio, f.Source)
		}
		if !f.ProbeOK {
			t.Errorf("%s: expected ProbeOK=true, got error: %s", f.Name, f.ProbeErr)
		}
		if f.Subject == "" {
			t.Errorf("%s: expected non-empty Subject", f.Name)
		}
		if f.Issuer == "" {
			t.Errorf("%s: expected non-empty Issuer", f.Name)
		}
		if f.Serial == "" {
			t.Errorf("%s: expected non-empty Serial", f.Name)
		}
	}
}
