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

func linkerdNamespaceObj() *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: linkerdNamespace},
	}
}

func TestLinkerdDiscoverer_ImplementsDiscoverer(_ *testing.T) {
	var _ Discoverer = (*LinkerdDiscoverer)(nil)
}

func TestLinkerdDiscoverer_Name(t *testing.T) {
	d := NewLinkerdDiscoverer(fake.NewClientset())
	if d.Name() != "linkerd" {
		t.Errorf("expected name %q, got %q", "linkerd", d.Name())
	}
}

func TestLinkerdDiscoverer_NoLinkerdNamespace(t *testing.T) {
	d := NewLinkerdDiscoverer(fake.NewClientset())
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when Linkerd not installed, got %d", len(findings))
	}
}

func TestLinkerdDiscoverer_BothPresent(t *testing.T) {
	trustAnchorNotAfter := time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second)
	issuerNotAfter := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)

	trustAnchorPEM := testCert(t, trustAnchorNotAfter, []string{"root.linkerd.cluster.local"})
	issuerPEM := testCert(t, issuerNotAfter, []string{"identity.linkerd.cluster.local"})

	objs := []runtime.Object{
		linkerdNamespaceObj(),
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: linkerdTrustRootsConfigMap, Namespace: linkerdNamespace},
			Data:       map[string]string{linkerdTrustRootsKey: string(trustAnchorPEM)},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: linkerdIssuerSecret, Namespace: linkerdNamespace},
			Data:       map[string][]byte{linkerdIssuerKey: issuerPEM},
		},
	}

	d := NewLinkerdDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// Trust anchor finding
	ta := findings[0]
	if ta.Source != store.SourceLinkerd {
		t.Errorf("trust anchor: expected source %q, got %q", store.SourceLinkerd, ta.Source)
	}
	if ta.Severity != store.SeverityInfo {
		t.Errorf("trust anchor: expected severity %q, got %q", store.SeverityInfo, ta.Severity)
	}
	if ta.Name != linkerdTrustRootsConfigMap {
		t.Errorf("trust anchor: expected name %q, got %q", linkerdTrustRootsConfigMap, ta.Name)
	}
	if !ta.ProbeOK {
		t.Errorf("trust anchor: expected ProbeOK=true, got error: %s", ta.ProbeErr)
	}
	if !ta.NotAfter.Equal(trustAnchorNotAfter) {
		t.Errorf("trust anchor: expected NotAfter %v, got %v", trustAnchorNotAfter, ta.NotAfter)
	}
	if ta.Notes != "trust anchor" {
		t.Errorf("trust anchor: expected notes %q, got %q", "trust anchor", ta.Notes)
	}

	// Issuer finding
	iss := findings[1]
	if iss.Source != store.SourceLinkerd {
		t.Errorf("issuer: expected source %q, got %q", store.SourceLinkerd, iss.Source)
	}
	if iss.Severity != store.SeverityCritical {
		t.Errorf("issuer: expected severity %q, got %q", store.SeverityCritical, iss.Severity)
	}
	if iss.Name != linkerdIssuerSecret {
		t.Errorf("issuer: expected name %q, got %q", linkerdIssuerSecret, iss.Name)
	}
	if !iss.ProbeOK {
		t.Errorf("issuer: expected ProbeOK=true, got error: %s", iss.ProbeErr)
	}
	if !iss.NotAfter.Equal(issuerNotAfter) {
		t.Errorf("issuer: expected NotAfter %v, got %v", issuerNotAfter, iss.NotAfter)
	}
	if iss.Notes != "identity issuer" {
		t.Errorf("issuer: expected notes %q, got %q", "identity issuer", iss.Notes)
	}
}

func TestLinkerdDiscoverer_TrustRootsMissingKey(t *testing.T) {
	objs := []runtime.Object{
		linkerdNamespaceObj(),
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: linkerdTrustRootsConfigMap, Namespace: linkerdNamespace},
			Data:       map[string]string{"wrong-key": "data"},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: linkerdIssuerSecret, Namespace: linkerdNamespace},
			Data:       map[string][]byte{linkerdIssuerKey: testCert(t, time.Now().Add(time.Hour), nil)},
		},
	}

	d := NewLinkerdDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	ta := findings[0]
	if ta.ProbeOK {
		t.Error("trust anchor: expected ProbeOK=false for missing key")
	}
	if ta.ProbeErr == "" {
		t.Error("trust anchor: expected non-empty ProbeErr")
	}
}

func TestLinkerdDiscoverer_IssuerMissingKey(t *testing.T) {
	objs := []runtime.Object{
		linkerdNamespaceObj(),
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: linkerdTrustRootsConfigMap, Namespace: linkerdNamespace},
			Data:       map[string]string{linkerdTrustRootsKey: string(testCert(t, time.Now().Add(time.Hour), nil))},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: linkerdIssuerSecret, Namespace: linkerdNamespace},
			Data:       map[string][]byte{"wrong-key": []byte("data")},
		},
	}

	d := NewLinkerdDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	iss := findings[1]
	if iss.ProbeOK {
		t.Error("issuer: expected ProbeOK=false for missing key")
	}
	if iss.ProbeErr == "" {
		t.Error("issuer: expected non-empty ProbeErr")
	}
}

func TestLinkerdDiscoverer_MalformedPEM(t *testing.T) {
	objs := []runtime.Object{
		linkerdNamespaceObj(),
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: linkerdTrustRootsConfigMap, Namespace: linkerdNamespace},
			Data:       map[string]string{linkerdTrustRootsKey: "not-valid-pem"},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: linkerdIssuerSecret, Namespace: linkerdNamespace},
			Data:       map[string][]byte{linkerdIssuerKey: []byte("not-valid-pem")},
		},
	}

	d := NewLinkerdDiscoverer(fake.NewClientset(objs...))
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

func TestLinkerdDiscoverer_NamespaceAllFields(t *testing.T) {
	objs := []runtime.Object{
		linkerdNamespaceObj(),
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: linkerdTrustRootsConfigMap, Namespace: linkerdNamespace},
			Data:       map[string]string{linkerdTrustRootsKey: string(testCert(t, time.Now().Add(time.Hour), nil))},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: linkerdIssuerSecret, Namespace: linkerdNamespace},
			Data:       map[string][]byte{linkerdIssuerKey: testCert(t, time.Now().Add(time.Hour), nil)},
		},
	}

	d := NewLinkerdDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Namespace != linkerdNamespace {
			t.Errorf("%s: expected namespace %q, got %q", f.Name, linkerdNamespace, f.Namespace)
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
