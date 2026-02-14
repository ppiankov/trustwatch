package discovery

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"

	"github.com/ppiankov/trustwatch/internal/store"
)

const testDefaultNS = "default"

var gatewayGVR = schema.GroupVersionResource{
	Group:    "gateway.networking.k8s.io",
	Version:  "v1",
	Resource: "gateways",
}

// fakeWithGatewayAPI creates a fake Kubernetes client whose discovery
// endpoint reports gateway.networking.k8s.io/v1 as an available API group.
func fakeWithGatewayAPI(objs ...runtime.Object) *fake.Clientset {
	cs := fake.NewClientset(objs...)
	fd := cs.Discovery().(*fakediscovery.FakeDiscovery)
	fd.Resources = append(fd.Resources, &metav1.APIResourceList{
		GroupVersion: "gateway.networking.k8s.io/v1",
		APIResources: []metav1.APIResource{
			{Name: "gateways", Kind: "Gateway", Namespaced: true},
		},
	})
	return cs
}

// newGatewayClientset creates a fake gateway-api clientset and seeds it with
// Gateway objects via the tracker (NewSimpleClientset doesn't seed correctly).
func newGatewayClientset(t *testing.T, gateways ...*gatewayv1.Gateway) *gatewayfake.Clientset {
	t.Helper()
	cs := gatewayfake.NewSimpleClientset()
	for _, gw := range gateways {
		if err := cs.Tracker().Create(gatewayGVR, gw, gw.Namespace); err != nil {
			t.Fatalf("seeding gateway %s/%s: %v", gw.Namespace, gw.Name, err)
		}
	}
	return cs
}

func TestGatewayDiscoverer_ImplementsDiscoverer(_ *testing.T) {
	var _ Discoverer = (*GatewayDiscoverer)(nil)
}

func TestGatewayDiscoverer_Name(t *testing.T) {
	d := NewGatewayDiscoverer(gatewayfake.NewSimpleClientset(), fakeWithGatewayAPI())
	if d.Name() != "gateway" {
		t.Errorf("expected name %q, got %q", "gateway", d.Name())
	}
}

func TestGatewayDiscoverer_NoGateways(t *testing.T) {
	d := NewGatewayDiscoverer(gatewayfake.NewSimpleClientset(), fakeWithGatewayAPI())
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestGatewayDiscoverer_ValidTLSSecret(t *testing.T) {
	notAfter := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	pemData := testCert(t, notAfter, []string{"app.example.com"})

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: testDefaultNS},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "istio",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Protocol: gatewayv1.HTTPSProtocolType,
					Port:     443,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "app-tls"},
						},
					},
				},
			},
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "app-tls", Namespace: testDefaultNS},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": pemData,
			"tls.key": []byte("fake-key"),
		},
	}

	d := NewGatewayDiscoverer(newGatewayClientset(t, gw), fakeWithGatewayAPI(secret))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Source != store.SourceGateway {
		t.Errorf("expected source %q, got %q", store.SourceGateway, f.Source)
	}
	if f.Severity != store.SeverityInfo {
		t.Errorf("expected severity %q, got %q", store.SeverityInfo, f.Severity)
	}
	if f.Namespace != testDefaultNS {
		t.Errorf("expected namespace %q, got %q", testDefaultNS, f.Namespace)
	}
	if f.Name != "my-gateway/https/app-tls" {
		t.Errorf("expected name %q, got %q", "my-gateway/https/app-tls", f.Name)
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

func TestGatewayDiscoverer_SecretNotFound(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: testDefaultNS},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "istio",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Protocol: gatewayv1.HTTPSProtocolType,
					Port:     443,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "missing-secret"},
						},
					},
				},
			},
		},
	}

	d := NewGatewayDiscoverer(newGatewayClientset(t, gw), fakeWithGatewayAPI())
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

func TestGatewayDiscoverer_NoTLSListeners(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: testDefaultNS},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "istio",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Protocol: gatewayv1.HTTPProtocolType,
					Port:     80,
				},
			},
		},
	}

	d := NewGatewayDiscoverer(newGatewayClientset(t, gw), fakeWithGatewayAPI())
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-TLS listener, got %d", len(findings))
	}
}

func TestGatewayDiscoverer_MultipleListeners(t *testing.T) {
	notAfter := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	pemData := testCert(t, notAfter, []string{"a.example.com"})

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "multi-gw", Namespace: testDefaultNS},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "istio",
			Listeners: []gatewayv1.Listener{
				{
					Name: "https-a", Protocol: gatewayv1.HTTPSProtocolType, Port: 443,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "cert-a"},
						},
					},
				},
				{
					Name: "https-b", Protocol: gatewayv1.HTTPSProtocolType, Port: 8443,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "cert-b"},
						},
					},
				},
			},
		},
	}

	coreObjs := []runtime.Object{
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "cert-a", Namespace: testDefaultNS},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("k")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "cert-b", Namespace: testDefaultNS},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("k")},
		},
	}

	d := NewGatewayDiscoverer(newGatewayClientset(t, gw), fakeWithGatewayAPI(coreObjs...))
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	if findings[0].Name != "multi-gw/https-a/cert-a" {
		t.Errorf("expected finding[0] name %q, got %q", "multi-gw/https-a/cert-a", findings[0].Name)
	}
	if findings[1].Name != "multi-gw/https-b/cert-b" {
		t.Errorf("expected finding[1] name %q, got %q", "multi-gw/https-b/cert-b", findings[1].Name)
	}
}

func TestGatewayDiscoverer_UnsupportedRefKind(t *testing.T) {
	customKind := gatewayv1.Kind("ConfigMap")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: testDefaultNS},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "istio",
			Listeners: []gatewayv1.Listener{
				{
					Name: "https", Protocol: gatewayv1.HTTPSProtocolType, Port: 443,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "my-cert", Kind: &customKind},
						},
					},
				},
			},
		},
	}

	d := NewGatewayDiscoverer(newGatewayClientset(t, gw), fakeWithGatewayAPI())
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ProbeOK {
		t.Error("expected ProbeOK=false for unsupported kind")
	}
	if f.ProbeErr == "" {
		t.Error("expected non-empty ProbeErr")
	}
}

func TestGatewayDiscoverer_UnsupportedRefGroup(t *testing.T) {
	customGroup := gatewayv1.Group("cert-manager.io")
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: testDefaultNS},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "istio",
			Listeners: []gatewayv1.Listener{
				{
					Name: "https", Protocol: gatewayv1.HTTPSProtocolType, Port: 443,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "my-cert", Group: &customGroup},
						},
					},
				},
			},
		},
	}

	d := NewGatewayDiscoverer(newGatewayClientset(t, gw), fakeWithGatewayAPI())
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ProbeOK {
		t.Error("expected ProbeOK=false for unsupported group")
	}
	if f.ProbeErr == "" {
		t.Error("expected non-empty ProbeErr")
	}
}

func TestGatewayDiscoverer_CRDsAbsent(t *testing.T) {
	d := NewGatewayDiscoverer(gatewayfake.NewSimpleClientset(), fake.NewClientset())
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when CRDs absent, got %d", len(findings))
	}
}

func TestGatewayDiscoverer_NamespaceFiltered(t *testing.T) {
	notAfter := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	pemData := testCert(t, notAfter, []string{"a.example.com"})

	gw1 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-1", Namespace: testNS1},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "istio",
			Listeners: []gatewayv1.Listener{
				{
					Name: "https", Protocol: gatewayv1.HTTPSProtocolType, Port: 443,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "cert-1"},
						},
					},
				},
			},
		},
	}
	gw2 := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-2", Namespace: testNS2},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "istio",
			Listeners: []gatewayv1.Listener{
				{
					Name: "https", Protocol: gatewayv1.HTTPSProtocolType, Port: 443,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "cert-2"},
						},
					},
				},
			},
		},
	}

	coreObjs := []runtime.Object{
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "cert-1", Namespace: testNS1},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("k")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "cert-2", Namespace: testNS2},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": pemData, "tls.key": []byte("k")},
		},
	}

	d := NewGatewayDiscoverer(
		newGatewayClientset(t, gw1, gw2),
		fakeWithGatewayAPI(coreObjs...),
		WithGatewayNamespaces([]string{testNS1}),
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

func TestGatewayDiscoverer_CrossNamespaceRef(t *testing.T) {
	notAfter := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	pemData := testCert(t, notAfter, []string{"cross.example.com"})
	otherNS := gatewayv1.Namespace("cert-store")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: testDefaultNS},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "istio",
			Listeners: []gatewayv1.Listener{
				{
					Name: "https", Protocol: gatewayv1.HTTPSProtocolType, Port: 443,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "cross-cert", Namespace: &otherNS},
						},
					},
				},
			},
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cross-cert", Namespace: "cert-store"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": pemData,
			"tls.key": []byte("fake-key"),
		},
	}

	d := NewGatewayDiscoverer(newGatewayClientset(t, gw), fakeWithGatewayAPI(secret))
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
	if f.Namespace != testDefaultNS {
		t.Errorf("expected namespace %q (gateway's ns), got %q", testDefaultNS, f.Namespace)
	}
}
