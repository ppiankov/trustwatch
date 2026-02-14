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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ppiankov/trustwatch/internal/store"
)

func testCert(t *testing.T, notAfter time.Time, dnsNames []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestSecretDiscoverer_ImplementsDiscoverer(_ *testing.T) {
	var _ Discoverer = (*SecretDiscoverer)(nil)
}

func TestSecretDiscoverer_Name(t *testing.T) {
	d := NewSecretDiscoverer(fake.NewClientset())
	if d.Name() != "secrets" {
		t.Errorf("expected name %q, got %q", "secrets", d.Name())
	}
}

func TestSecretDiscoverer_ValidTLSSecret(t *testing.T) {
	notAfter := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	pemData := testCert(t, notAfter, []string{"example.com", "www.example.com"})

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "my-tls", Namespace: "default"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": pemData,
			"tls.key": []byte("fake-key"),
		},
	}

	d := NewSecretDiscoverer(fake.NewClientset(secret))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Source != store.SourceTLSSecret {
		t.Errorf("expected source %q, got %q", store.SourceTLSSecret, f.Source)
	}
	if f.Severity != store.SeverityInfo {
		t.Errorf("expected severity %q, got %q", store.SeverityInfo, f.Severity)
	}
	if f.Namespace != "default" {
		t.Errorf("expected namespace %q, got %q", "default", f.Namespace)
	}
	if f.Name != "my-tls" {
		t.Errorf("expected name %q, got %q", "my-tls", f.Name)
	}
	if f.Target != "" {
		t.Errorf("expected empty target, got %q", f.Target)
	}
	if !f.ProbeOK {
		t.Errorf("expected ProbeOK=true, got error: %s", f.ProbeErr)
	}
	if !f.NotAfter.Equal(notAfter) {
		t.Errorf("expected NotAfter %v, got %v", notAfter, f.NotAfter)
	}
	if len(f.DNSNames) != 2 || f.DNSNames[0] != "example.com" || f.DNSNames[1] != "www.example.com" {
		t.Errorf("expected DNSNames [example.com www.example.com], got %v", f.DNSNames)
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

func TestSecretDiscoverer_MultiCertBundle(t *testing.T) {
	leafNotAfter := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	caNotAfter := time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second)

	leafPEM := testCert(t, leafNotAfter, []string{"leaf.example.com"})
	caPEM := testCert(t, caNotAfter, []string{"ca.example.com"})

	// Bundle: leaf first, then CA
	bundle := make([]byte, 0, len(leafPEM)+len(caPEM))
	bundle = append(bundle, leafPEM...)
	bundle = append(bundle, caPEM...)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "bundle-tls", Namespace: "certs"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": bundle,
			"tls.key": []byte("fake-key"),
		},
	}

	d := NewSecretDiscoverer(fake.NewClientset(secret))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	// Should use the leaf (first cert in bundle)
	if !findings[0].NotAfter.Equal(leafNotAfter) {
		t.Errorf("expected leaf NotAfter %v, got %v", leafNotAfter, findings[0].NotAfter)
	}
	if len(findings[0].DNSNames) != 1 || findings[0].DNSNames[0] != "leaf.example.com" {
		t.Errorf("expected leaf DNSNames, got %v", findings[0].DNSNames)
	}
}

func TestSecretDiscoverer_NonTLSSecretSkipped(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "opaque-secret", Namespace: "default"},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"password": []byte("s3cret"),
		},
	}

	d := NewSecretDiscoverer(fake.NewClientset(secret))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-TLS secret, got %d", len(findings))
	}
}

func TestSecretDiscoverer_NoSecrets(t *testing.T) {
	d := NewSecretDiscoverer(fake.NewClientset())
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestSecretDiscoverer_MultipleTLSSecrets(t *testing.T) {
	pemData := testCert(t, time.Now().Add(30*24*time.Hour), []string{"a.example.com"})

	objs := []runtime.Object{
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-1", Namespace: "ns1"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("k")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-2", Namespace: "ns2"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("k")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-3", Namespace: "ns3"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("k")},
		},
	}

	d := NewSecretDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
}

func TestSecretDiscoverer_MalformedPEM(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-pem", Namespace: "default"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte("not-valid-pem-data"),
			"tls.key": []byte("fake-key"),
		},
	}

	d := NewSecretDiscoverer(fake.NewClientset(secret))
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
		t.Error("expected non-empty ProbeErr for malformed PEM")
	}
	if f.Source != store.SourceTLSSecret {
		t.Errorf("expected source %q, got %q", store.SourceTLSSecret, f.Source)
	}
}

func TestSecretDiscoverer_MissingTLSCrtKey(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "no-crt", Namespace: "default"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.key": []byte("fake-key"),
		},
	}

	d := NewSecretDiscoverer(fake.NewClientset(secret))
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

func TestSecretDiscoverer_NamespaceFiltered(t *testing.T) {
	pemData := testCert(t, time.Now().Add(30*24*time.Hour), []string{"a.example.com"})

	objs := []runtime.Object{
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-1", Namespace: "ns1"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("k")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-2", Namespace: "ns2"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("k")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-3", Namespace: "ns3"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("k")},
		},
	}

	d := NewSecretDiscoverer(fake.NewClientset(objs...), WithSecretNamespaces([]string{"ns1", "ns3"}))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (ns1+ns3), got %d", len(findings))
	}
	if findings[0].Namespace != "ns1" {
		t.Errorf("expected finding[0] namespace ns1, got %q", findings[0].Namespace)
	}
	if findings[1].Namespace != "ns3" {
		t.Errorf("expected finding[1] namespace ns3, got %q", findings[1].Namespace)
	}
}
