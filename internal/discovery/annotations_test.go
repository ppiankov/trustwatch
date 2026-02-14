package discovery

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ppiankov/trustwatch/internal/probe"
	"github.com/ppiankov/trustwatch/internal/store"
)

const testProbeErrConnRefused = "connection refused"

func mockProbeResult(result probe.Result) func(string) probe.Result {
	return func(_ string) probe.Result { return result }
}

func successProbeResult() probe.Result {
	return probe.Result{
		ProbeOK: true,
		Cert: &x509.Certificate{
			NotAfter:     time.Now().Add(30 * 24 * time.Hour),
			DNSNames:     []string{"test.example.com"},
			Issuer:       pkix.Name{CommonName: "test-issuer"},
			Subject:      pkix.Name{CommonName: "test-subject"},
			SerialNumber: big.NewInt(42),
		},
	}
}

func failProbeResult() probe.Result {
	return probe.Result{ProbeOK: false, ProbeErr: testProbeErrConnRefused}
}

func TestAnnotationDiscoverer_ImplementsDiscoverer(_ *testing.T) {
	var _ Discoverer = (*AnnotationDiscoverer)(nil)
}

func TestAnnotationDiscoverer_Name(t *testing.T) {
	d := NewAnnotationDiscoverer(fake.NewClientset())
	if d.Name() != "annotations" {
		t.Errorf("expected name %q, got %q", "annotations", d.Name())
	}
}

func TestAnnotationDiscoverer_NoAnnotatedObjects(t *testing.T) {
	objs := []runtime.Object{
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "plain-svc", Namespace: "default"},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "plain-dep", Namespace: "default"},
		},
	}

	d := NewAnnotationDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestAnnotationDiscoverer_ServiceDefaultPort(t *testing.T) {
	objs := []runtime.Object{
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-svc",
				Namespace: "web",
				Annotations: map[string]string{
					annoEnabled: "true",
				},
			},
		},
	}

	d := NewAnnotationDiscoverer(fake.NewClientset(objs...))
	d.probeFn = mockProbeResult(successProbeResult())

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Source != store.SourceAnnotation {
		t.Errorf("expected source %q, got %q", store.SourceAnnotation, f.Source)
	}
	if f.Target != "my-svc.web.svc:443" {
		t.Errorf("expected target %q, got %q", "my-svc.web.svc:443", f.Target)
	}
	if f.Namespace != "web" {
		t.Errorf("expected namespace %q, got %q", "web", f.Namespace)
	}
	if f.Name != "my-svc" {
		t.Errorf("expected name %q, got %q", "my-svc", f.Name)
	}
	if !f.ProbeOK {
		t.Errorf("expected ProbeOK=true, got error: %s", f.ProbeErr)
	}
	if f.Severity != store.SeverityInfo {
		t.Errorf("expected severity %q, got %q", store.SeverityInfo, f.Severity)
	}
}

func TestAnnotationDiscoverer_ServiceCustomPorts(t *testing.T) {
	objs := []runtime.Object{
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "multi-port",
				Namespace: "default",
				Annotations: map[string]string{
					annoEnabled: "true",
					annoPorts:   "8443, 9443",
				},
			},
		},
	}

	var probedTargets []string
	d := NewAnnotationDiscoverer(fake.NewClientset(objs...))
	d.probeFn = func(raw string) probe.Result {
		probedTargets = append(probedTargets, raw)
		return successProbeResult()
	}

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	if findings[0].Target != "multi-port.default.svc:8443" {
		t.Errorf("expected target with port 8443, got %q", findings[0].Target)
	}
	if findings[1].Target != "multi-port.default.svc:9443" {
		t.Errorf("expected target with port 9443, got %q", findings[1].Target)
	}
}

func TestAnnotationDiscoverer_ServiceWithSNI(t *testing.T) {
	objs := []runtime.Object{
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sni-svc",
				Namespace: "default",
				Annotations: map[string]string{
					annoEnabled: "true",
					annoSNI:     "api.internal",
				},
			},
		},
	}

	var probedURL string
	d := NewAnnotationDiscoverer(fake.NewClientset(objs...))
	d.probeFn = func(raw string) probe.Result {
		probedURL = raw
		return successProbeResult()
	}

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].SNI != "api.internal" {
		t.Errorf("expected SNI %q, got %q", "api.internal", findings[0].SNI)
	}
	// Probe URL should include SNI
	if probedURL == "" {
		t.Error("expected probeFn to be called")
	}
}

func TestAnnotationDiscoverer_SeverityOverride(t *testing.T) {
	objs := []runtime.Object{
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "critical-svc",
				Namespace: "default",
				Annotations: map[string]string{
					annoEnabled:  "true",
					annoSeverity: "critical",
				},
			},
		},
	}

	d := NewAnnotationDiscoverer(fake.NewClientset(objs...))
	d.probeFn = mockProbeResult(successProbeResult())

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != store.SeverityCritical {
		t.Errorf("expected severity %q, got %q", store.SeverityCritical, findings[0].Severity)
	}
}

func TestAnnotationDiscoverer_TLSSecret(t *testing.T) {
	notAfter := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	pemData := testCert(t, notAfter, []string{"secret.example.com"})

	objs := []runtime.Object{
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "secret-svc",
				Namespace: "default",
				Annotations: map[string]string{
					annoEnabled:   "true",
					annoTLSSecret: "my-cert",
				},
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cert", Namespace: "default"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("k")},
		},
	}

	d := NewAnnotationDiscoverer(fake.NewClientset(objs...))
	// probeFn should NOT be called when tls-secret is set
	d.probeFn = func(_ string) probe.Result {
		t.Error("probeFn should not be called when tls-secret is set")
		return probe.Result{}
	}

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if !f.ProbeOK {
		t.Errorf("expected ProbeOK=true, got error: %s", f.ProbeErr)
	}
	if f.Name != "secret-svc/my-cert" {
		t.Errorf("expected name %q, got %q", "secret-svc/my-cert", f.Name)
	}
	if !f.NotAfter.Equal(notAfter) {
		t.Errorf("expected NotAfter %v, got %v", notAfter, f.NotAfter)
	}
	if f.Target != "" {
		t.Errorf("expected empty target for secret-based finding, got %q", f.Target)
	}
}

func TestAnnotationDiscoverer_TLSSecretNotFound(t *testing.T) {
	objs := []runtime.Object{
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "missing-secret-svc",
				Namespace: "default",
				Annotations: map[string]string{
					annoEnabled:   "true",
					annoTLSSecret: "nonexistent",
				},
			},
		},
	}

	d := NewAnnotationDiscoverer(fake.NewClientset(objs...))
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
}

func TestAnnotationDiscoverer_ExternalTargets(t *testing.T) {
	objs := []runtime.Object{
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ext-svc",
				Namespace: "default",
				Annotations: map[string]string{
					annoEnabled:         "true",
					annoTLSSecret:       "my-cert",
					annoExternalTargets: "api.stripe.com:443\napi.github.com:443\n",
				},
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cert", Namespace: "default"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": testCert(t, time.Now().Add(time.Hour), nil), "tls.key": []byte("k")},
		},
	}

	d := NewAnnotationDiscoverer(fake.NewClientset(objs...))
	d.probeFn = mockProbeResult(successProbeResult())

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 1 from tls-secret + 2 from external targets
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	// External target findings should have notes
	if findings[1].Notes != "external target" {
		t.Errorf("expected notes %q, got %q", "external target", findings[1].Notes)
	}
	if findings[1].Target != "api.stripe.com:443" {
		t.Errorf("expected target %q, got %q", "api.stripe.com:443", findings[1].Target)
	}
	if findings[2].Target != "api.github.com:443" {
		t.Errorf("expected target %q, got %q", "api.github.com:443", findings[2].Target)
	}
}

func TestAnnotationDiscoverer_Deployment(t *testing.T) {
	notAfter := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	pemData := testCert(t, notAfter, []string{"dep.example.com"})

	objs := []runtime.Object{
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-dep",
				Namespace: "apps",
				Annotations: map[string]string{
					annoEnabled:   "true",
					annoTLSSecret: "dep-cert",
				},
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "dep-cert", Namespace: "apps"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("k")},
		},
	}

	d := NewAnnotationDiscoverer(fake.NewClientset(objs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Source != store.SourceAnnotation {
		t.Errorf("expected source %q, got %q", store.SourceAnnotation, f.Source)
	}
	if f.Namespace != "apps" {
		t.Errorf("expected namespace %q, got %q", "apps", f.Namespace)
	}
	if f.Name != "my-dep/dep-cert" {
		t.Errorf("expected name %q, got %q", "my-dep/dep-cert", f.Name)
	}
	if !f.ProbeOK {
		t.Errorf("expected ProbeOK=true, got error: %s", f.ProbeErr)
	}
}

func TestAnnotationDiscoverer_DeploymentNoProbeWithoutSecret(t *testing.T) {
	// Deployments without tls-secret or external-targets produce no findings
	objs := []runtime.Object{
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bare-dep",
				Namespace: "default",
				Annotations: map[string]string{
					annoEnabled: "true",
				},
			},
		},
	}

	d := NewAnnotationDiscoverer(fake.NewClientset(objs...))
	d.probeFn = func(_ string) probe.Result {
		t.Error("probeFn should not be called for Deployment without tls-secret")
		return probe.Result{}
	}

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for bare deployment, got %d", len(findings))
	}
}

func TestAnnotationDiscoverer_ProbeFailure(t *testing.T) {
	objs := []runtime.Object{
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "fail-svc",
				Namespace: "default",
				Annotations: map[string]string{
					annoEnabled: "true",
				},
			},
		},
	}

	d := NewAnnotationDiscoverer(fake.NewClientset(objs...))
	d.probeFn = mockProbeResult(failProbeResult())

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ProbeOK {
		t.Error("expected ProbeOK=false")
	}
	if f.ProbeErr != testProbeErrConnRefused {
		t.Errorf("expected ProbeErr %q, got %q", testProbeErrConnRefused, f.ProbeErr)
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", []string{"443"}},
		{"8443", []string{"8443"}},
		{"443,8443", []string{"443", "8443"}},
		{" 443 , 8443 , 9443 ", []string{"443", "8443", "9443"}},
		{",,,", []string{"443"}},
	}
	for _, tt := range tests {
		got := parsePorts(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("parsePorts(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parsePorts(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  store.Severity
	}{
		{"critical", store.SeverityCritical},
		{"warn", store.SeverityWarn},
		{"info", store.SeverityInfo},
		{"", store.SeverityInfo},
		{"unknown", store.SeverityInfo},
	}
	for _, tt := range tests {
		got := parseSeverity(tt.input)
		if got != tt.want {
			t.Errorf("parseSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseExternalTargets(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"api.stripe.com:443", []string{"api.stripe.com:443"}},
		{"a:443\nb:443\n", []string{"a:443", "b:443"}},
		{" a:443 \n\n b:443 \n\n", []string{"a:443", "b:443"}},
	}
	for _, tt := range tests {
		got := parseExternalTargets(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("parseExternalTargets(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseExternalTargets(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestAnnotationDiscoverer_NamespaceFiltered(t *testing.T) {
	objs := []runtime.Object{
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name: "svc-1", Namespace: testNS1,
				Annotations: map[string]string{annoEnabled: "true"},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name: "svc-2", Namespace: testNS2,
				Annotations: map[string]string{annoEnabled: "true"},
			},
		},
	}

	d := NewAnnotationDiscoverer(fake.NewClientset(objs...),
		WithAnnotationProbeFn(mockProbeResult(successProbeResult())),
		WithAnnotationNamespaces([]string{testNS1}),
	)

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (ns1 only), got %d", len(findings))
	}
	if findings[0].Namespace != testNS1 {
		t.Errorf("expected namespace ns1, got %q", findings[0].Namespace)
	}
}
