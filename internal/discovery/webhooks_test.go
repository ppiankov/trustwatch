package discovery

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ppiankov/trustwatch/internal/probe"
	"github.com/ppiankov/trustwatch/internal/store"
)

const wantFailPolicyNote = "failurePolicy=Fail"

func TestWebhookDiscoverer_ImplementsDiscoverer(_ *testing.T) {
	var _ Discoverer = (*WebhookDiscoverer)(nil)
}

func TestWebhookDiscoverer_Name(t *testing.T) {
	d := NewWebhookDiscoverer(fake.NewClientset())
	if d.Name() != "webhooks" {
		t.Errorf("expected name %q, got %q", "webhooks", d.Name())
	}
}

func TestWebhookDiscoverer_ValidatingFailPolicy(t *testing.T) {
	fail := admissionregistrationv1.Fail
	port := int32(443)
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "my-vwc"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name:          "validate.example.com",
				FailurePolicy: &fail,
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Name:      "webhook-svc",
						Namespace: "webhook-ns",
						Port:      &port,
					},
				},
			},
		},
	}

	client := fake.NewClientset(vwc)
	d := NewWebhookDiscoverer(client)

	notAfter := time.Now().Add(24 * time.Hour)
	d.probeFn = mockProbeFn(notAfter)

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Source != store.SourceWebhook {
		t.Errorf("expected source %q, got %q", store.SourceWebhook, f.Source)
	}
	if f.Severity != store.SeverityCritical {
		t.Errorf("expected severity %q, got %q", store.SeverityCritical, f.Severity)
	}
	if f.Namespace != "webhook-ns" {
		t.Errorf("expected namespace %q, got %q", "webhook-ns", f.Namespace)
	}
	if f.Name != "my-vwc/validate.example.com" {
		t.Errorf("expected name %q, got %q", "my-vwc/validate.example.com", f.Name)
	}
	if f.Target != "webhook-svc.webhook-ns.svc:443" {
		t.Errorf("expected target %q, got %q", "webhook-svc.webhook-ns.svc:443", f.Target)
	}
	if !f.ProbeOK {
		t.Errorf("expected probe OK, got error: %s", f.ProbeErr)
	}
	if f.Notes != wantFailPolicyNote {
		t.Errorf("expected notes %q, got %q", wantFailPolicyNote, f.Notes)
	}
	if !f.NotAfter.Equal(notAfter) {
		t.Errorf("expected NotAfter %v, got %v", notAfter, f.NotAfter)
	}
}

func TestWebhookDiscoverer_MutatingIgnorePolicy(t *testing.T) {
	ignore := admissionregistrationv1.Ignore
	port := int32(443)
	mwc := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "my-mwc"},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name:          "mutate.example.com",
				FailurePolicy: &ignore,
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Name:      "mutate-svc",
						Namespace: "mutate-ns",
						Port:      &port,
					},
				},
			},
		},
	}

	client := fake.NewClientset(mwc)
	d := NewWebhookDiscoverer(client)
	d.probeFn = mockProbeFn(time.Now().Add(24 * time.Hour))

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != store.SeverityInfo {
		t.Errorf("expected severity %q, got %q", store.SeverityInfo, f.Severity)
	}
	if f.Notes != "failurePolicy=Ignore" {
		t.Errorf("expected notes %q, got %q", "failurePolicy=Ignore", f.Notes)
	}
}

func TestWebhookDiscoverer_DefaultPort(t *testing.T) {
	fail := admissionregistrationv1.Fail
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "default-port-vwc"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name:          "validate.example.com",
				FailurePolicy: &fail,
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Name:      "svc",
						Namespace: "ns",
						// Port is nil — should default to 443
					},
				},
			},
		},
	}

	client := fake.NewClientset(vwc)
	d := NewWebhookDiscoverer(client)
	d.probeFn = mockProbeFn(time.Now().Add(24 * time.Hour))

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Target != "svc.ns.svc:443" {
		t.Errorf("expected target %q, got %q", "svc.ns.svc:443", findings[0].Target)
	}
}

func TestWebhookDiscoverer_CustomPort(t *testing.T) {
	fail := admissionregistrationv1.Fail
	port := int32(8443)
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "custom-port-vwc"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name:          "validate.example.com",
				FailurePolicy: &fail,
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Name:      "svc",
						Namespace: "ns",
						Port:      &port,
					},
				},
			},
		},
	}

	client := fake.NewClientset(vwc)
	d := NewWebhookDiscoverer(client)
	d.probeFn = mockProbeFn(time.Now().Add(24 * time.Hour))

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Target != "svc.ns.svc:8443" {
		t.Errorf("expected target %q, got %q", "svc.ns.svc:8443", findings[0].Target)
	}
}

func TestWebhookDiscoverer_URLBasedSkipped(t *testing.T) {
	fail := admissionregistrationv1.Fail
	url := "https://external-webhook.example.com/validate"
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "url-vwc"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name:          "validate.example.com",
				FailurePolicy: &fail,
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					URL: &url,
				},
			},
		},
	}

	client := fake.NewClientset(vwc)
	d := NewWebhookDiscoverer(client)
	d.probeFn = func(_ string) probe.Result {
		t.Fatal("probeFn should not be called for URL-based webhooks")
		return probe.Result{}
	}

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for URL-based webhook, got %d", len(findings))
	}
}

func TestWebhookDiscoverer_NoWebhooks(t *testing.T) {
	client := fake.NewClientset()
	d := NewWebhookDiscoverer(client)
	d.probeFn = func(_ string) probe.Result {
		t.Fatal("probeFn should not be called when there are no webhooks")
		return probe.Result{}
	}

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestWebhookDiscoverer_MultipleWebhooks(t *testing.T) {
	fail := admissionregistrationv1.Fail
	port := int32(443)

	objs := []runtime.Object{
		&admissionregistrationv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "vwc-1"},
			Webhooks: []admissionregistrationv1.ValidatingWebhook{
				{
					Name:          "v1.example.com",
					FailurePolicy: &fail,
					ClientConfig: admissionregistrationv1.WebhookClientConfig{
						Service: &admissionregistrationv1.ServiceReference{
							Name: "svc1", Namespace: "ns1", Port: &port,
						},
					},
				},
			},
		},
		&admissionregistrationv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "vwc-2"},
			Webhooks: []admissionregistrationv1.ValidatingWebhook{
				{
					Name:          "v2.example.com",
					FailurePolicy: &fail,
					ClientConfig: admissionregistrationv1.WebhookClientConfig{
						Service: &admissionregistrationv1.ServiceReference{
							Name: "svc2", Namespace: "ns2", Port: &port,
						},
					},
				},
			},
		},
		&admissionregistrationv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "mwc-1"},
			Webhooks: []admissionregistrationv1.MutatingWebhook{
				{
					Name:          "m1.example.com",
					FailurePolicy: &fail,
					ClientConfig: admissionregistrationv1.WebhookClientConfig{
						Service: &admissionregistrationv1.ServiceReference{
							Name: "svc3", Namespace: "ns3", Port: &port,
						},
					},
				},
			},
		},
	}

	client := fake.NewClientset(objs...)
	d := NewWebhookDiscoverer(client)
	d.probeFn = mockProbeFn(time.Now().Add(24 * time.Hour))

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
}

func TestWebhookDiscoverer_ProbeFailure(t *testing.T) {
	fail := admissionregistrationv1.Fail
	port := int32(443)
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "fail-vwc"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name:          "validate.example.com",
				FailurePolicy: &fail,
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Name: "svc", Namespace: "ns", Port: &port,
					},
				},
			},
		},
	}

	client := fake.NewClientset(vwc)
	d := NewWebhookDiscoverer(client)
	d.probeFn = func(_ string) probe.Result {
		return probe.Result{ProbeOK: false, ProbeErr: "connection refused"}
	}

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ProbeOK {
		t.Error("expected probe failure")
	}
	if f.ProbeErr != "connection refused" {
		t.Errorf("expected probe error %q, got %q", "connection refused", f.ProbeErr)
	}
	if f.NotAfter.IsZero() == false {
		t.Error("expected zero NotAfter on probe failure")
	}
}

func TestWebhookDiscoverer_NilFailurePolicy(t *testing.T) {
	// nil failurePolicy defaults to Fail in Kubernetes
	port := int32(443)
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "nil-policy-vwc"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "validate.example.com",
				// FailurePolicy is nil — should be treated as Fail
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Name: "svc", Namespace: "ns", Port: &port,
					},
				},
			},
		},
	}

	client := fake.NewClientset(vwc)
	d := NewWebhookDiscoverer(client)
	d.probeFn = mockProbeFn(time.Now().Add(24 * time.Hour))

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Severity != store.SeverityCritical {
		t.Errorf("expected severity %q for nil failurePolicy, got %q", store.SeverityCritical, findings[0].Severity)
	}
	if findings[0].Notes != wantFailPolicyNote {
		t.Errorf("expected notes %q, got %q", wantFailPolicyNote, findings[0].Notes)
	}
}

func mockProbeFn(notAfter time.Time) func(string) probe.Result {
	return func(_ string) probe.Result {
		return probe.Result{
			ProbeOK: true,
			Cert: &x509.Certificate{
				NotAfter:     notAfter,
				DNSNames:     []string{"webhook.example.com"},
				SerialNumber: big.NewInt(123),
			},
		}
	}
}
