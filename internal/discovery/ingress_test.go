package discovery

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ppiankov/trustwatch/internal/store"
)

func TestIngressDiscoverer_ImplementsDiscoverer(_ *testing.T) {
	var _ Discoverer = (*IngressDiscoverer)(nil)
}

func TestIngressDiscoverer_Name(t *testing.T) {
	d := NewIngressDiscoverer(fake.NewClientset())
	if d.Name() != "ingress" {
		t.Errorf("expected name %q, got %q", "ingress", d.Name())
	}
}

func TestIngressDiscoverer_NoIngresses(t *testing.T) {
	d := NewIngressDiscoverer(fake.NewClientset())
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestIngressDiscoverer_ValidTLSSecret(t *testing.T) {
	notAfter := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	pemData := testCert(t, notAfter, []string{"app.example.com"})

	objs := []runtime.Object{
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "my-ingress", Namespace: "default"},
			Spec: networkingv1.IngressSpec{
				TLS: []networkingv1.IngressTLS{
					{Hosts: []string{"app.example.com"}, SecretName: "app-tls"},
				},
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "app-tls", Namespace: "default"},
			Type:       corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": pemData,
				"tls.key": []byte("fake-key"),
			},
		},
	}

	d := NewIngressDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Source != store.SourceIngressTLS {
		t.Errorf("expected source %q, got %q", store.SourceIngressTLS, f.Source)
	}
	if f.Severity != store.SeverityInfo {
		t.Errorf("expected severity %q, got %q", store.SeverityInfo, f.Severity)
	}
	if f.Namespace != "default" {
		t.Errorf("expected namespace %q, got %q", "default", f.Namespace)
	}
	if f.Name != "my-ingress/app-tls" {
		t.Errorf("expected name %q, got %q", "my-ingress/app-tls", f.Name)
	}
	if !f.ProbeOK {
		t.Errorf("expected ProbeOK=true, got error: %s", f.ProbeErr)
	}
	if !f.NotAfter.Equal(notAfter) {
		t.Errorf("expected NotAfter %v, got %v", notAfter, f.NotAfter)
	}
	if len(f.DNSNames) != 1 || f.DNSNames[0] != "app.example.com" {
		t.Errorf("expected DNSNames [app.example.com], got %v", f.DNSNames)
	}
	if f.Subject == "" {
		t.Error("expected non-empty Subject")
	}
	if f.Issuer == "" {
		t.Error("expected non-empty Issuer")
	}
	if f.Serial != "1" {
		t.Errorf("expected serial %q, got %q", "1", f.Serial)
	}
}

func TestIngressDiscoverer_SecretNotFound(t *testing.T) {
	objs := []runtime.Object{
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "orphan-ing", Namespace: "web"},
			Spec: networkingv1.IngressSpec{
				TLS: []networkingv1.IngressTLS{
					{Hosts: []string{"orphan.example.com"}, SecretName: "missing-secret"},
				},
			},
		},
	}

	d := NewIngressDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ProbeOK {
		t.Error("expected ProbeOK=false for missing secret")
	}
	if f.ProbeErr == "" {
		t.Error("expected non-empty ProbeErr")
	}
	if f.Source != store.SourceIngressTLS {
		t.Errorf("expected source %q, got %q", store.SourceIngressTLS, f.Source)
	}
	if f.Namespace != "web" {
		t.Errorf("expected namespace %q, got %q", "web", f.Namespace)
	}
	if f.Name != "orphan-ing/missing-secret" {
		t.Errorf("expected name %q, got %q", "orphan-ing/missing-secret", f.Name)
	}
}

func TestIngressDiscoverer_EmptySecretName(t *testing.T) {
	objs := []runtime.Object{
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "no-secret-ing", Namespace: "default"},
			Spec: networkingv1.IngressSpec{
				TLS: []networkingv1.IngressTLS{
					{Hosts: []string{"auto.example.com"}},
				},
			},
		},
	}

	d := NewIngressDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty secretName, got %d", len(findings))
	}
}

func TestIngressDiscoverer_WrongSecretType(t *testing.T) {
	objs := []runtime.Object{
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-type-ing", Namespace: "default"},
			Spec: networkingv1.IngressSpec{
				TLS: []networkingv1.IngressTLS{
					{Hosts: []string{"bad.example.com"}, SecretName: "opaque-secret"},
				},
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "opaque-secret", Namespace: "default"},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{"data": []byte("not-a-cert")},
		},
	}

	d := NewIngressDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ProbeOK {
		t.Error("expected ProbeOK=false for wrong secret type")
	}
	if f.ProbeErr == "" {
		t.Error("expected non-empty ProbeErr")
	}
}

func TestIngressDiscoverer_MalformedPEM(t *testing.T) {
	objs := []runtime.Object{
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-pem-ing", Namespace: "default"},
			Spec: networkingv1.IngressSpec{
				TLS: []networkingv1.IngressTLS{
					{Hosts: []string{"bad.example.com"}, SecretName: "bad-pem"},
				},
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-pem", Namespace: "default"},
			Type:       corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": []byte("not-valid-pem"),
				"tls.key": []byte("fake-key"),
			},
		},
	}

	d := NewIngressDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ProbeOK {
		t.Error("expected ProbeOK=false for malformed PEM")
	}
	if f.ProbeErr == "" {
		t.Error("expected non-empty ProbeErr")
	}
}

func TestIngressDiscoverer_MissingTLSCrtKey(t *testing.T) {
	objs := []runtime.Object{
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "no-crt-ing", Namespace: "default"},
			Spec: networkingv1.IngressSpec{
				TLS: []networkingv1.IngressTLS{
					{Hosts: []string{"no-crt.example.com"}, SecretName: "no-crt-secret"},
				},
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "no-crt-secret", Namespace: "default"},
			Type:       corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.key": []byte("fake-key"),
			},
		},
	}

	d := NewIngressDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ProbeOK {
		t.Error("expected ProbeOK=false for missing tls.crt")
	}
	if f.ProbeErr != errMissingTLSCrt {
		t.Errorf("expected ProbeErr %q, got %q", errMissingTLSCrt, f.ProbeErr)
	}
}

func TestIngressDiscoverer_MultipleIngressesMultipleTLS(t *testing.T) {
	pemData := testCert(t, time.Now().Add(30*24*time.Hour), []string{"a.example.com"})

	objs := []runtime.Object{
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "ing-1", Namespace: "ns1"},
			Spec: networkingv1.IngressSpec{
				TLS: []networkingv1.IngressTLS{
					{Hosts: []string{"a.example.com"}, SecretName: "tls-a"},
					{Hosts: []string{"b.example.com"}, SecretName: "tls-b"},
				},
			},
		},
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "ing-2", Namespace: "ns2"},
			Spec: networkingv1.IngressSpec{
				TLS: []networkingv1.IngressTLS{
					{Hosts: []string{"c.example.com"}, SecretName: "tls-c"},
				},
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-a", Namespace: "ns1"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("k")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-b", Namespace: "ns1"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("k")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-c", Namespace: "ns2"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("k")},
		},
	}

	d := NewIngressDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	// Verify all findings are ProbeOK and have correct source
	for _, f := range findings {
		if f.Source != store.SourceIngressTLS {
			t.Errorf("expected source %q, got %q", store.SourceIngressTLS, f.Source)
		}
		if !f.ProbeOK {
			t.Errorf("expected ProbeOK=true for %s, got error: %s", f.Name, f.ProbeErr)
		}
	}
}

func TestIngressDiscoverer_NoTLSBlock(t *testing.T) {
	objs := []runtime.Object{
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "plain-ing", Namespace: "default"},
			Spec: networkingv1.IngressSpec{
				Rules: []networkingv1.IngressRule{
					{Host: "plain.example.com"},
				},
			},
		},
	}

	d := NewIngressDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for ingress without TLS, got %d", len(findings))
	}
}
