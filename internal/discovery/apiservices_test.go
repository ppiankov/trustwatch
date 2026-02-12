package discovery

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	aggregatorfake "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"

	"github.com/ppiankov/trustwatch/internal/probe"
	"github.com/ppiankov/trustwatch/internal/store"
)

// newFakeAggregatorClient wraps the deprecated NewSimpleClientset.
// NewClientset is not available in kube-aggregator (no apply configs generated).
func newFakeAggregatorClient(objs ...runtime.Object) aggregatorclient.Interface {
	//nolint:staticcheck // NewClientset not available in kube-aggregator
	return aggregatorfake.NewSimpleClientset(objs...)
}

func TestAPIServiceDiscoverer_ImplementsDiscoverer(_ *testing.T) {
	var _ Discoverer = (*APIServiceDiscoverer)(nil)
}

func TestAPIServiceDiscoverer_Name(t *testing.T) {
	d := NewAPIServiceDiscoverer(newFakeAggregatorClient())
	if d.Name() != "apiservices" {
		t.Errorf("expected name %q, got %q", "apiservices", d.Name())
	}
}

func TestAPIServiceDiscoverer_WithServiceRef(t *testing.T) {
	port := int32(443)
	as := &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: "v1beta1.metrics.k8s.io"},
		Spec: apiregistrationv1.APIServiceSpec{
			Service: &apiregistrationv1.ServiceReference{
				Name:      "metrics-server",
				Namespace: "kube-system",
				Port:      &port,
			},
		},
	}

	client := newFakeAggregatorClient(as)
	d := NewAPIServiceDiscoverer(client)

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
	if f.Source != store.SourceAPIService {
		t.Errorf("expected source %q, got %q", store.SourceAPIService, f.Source)
	}
	if f.Severity != store.SeverityCritical {
		t.Errorf("expected severity %q, got %q", store.SeverityCritical, f.Severity)
	}
	if f.Namespace != "kube-system" {
		t.Errorf("expected namespace %q, got %q", "kube-system", f.Namespace)
	}
	if f.Name != "v1beta1.metrics.k8s.io" {
		t.Errorf("expected name %q, got %q", "v1beta1.metrics.k8s.io", f.Name)
	}
	if f.Target != "metrics-server.kube-system.svc:443" {
		t.Errorf("expected target %q, got %q", "metrics-server.kube-system.svc:443", f.Target)
	}
	if !f.ProbeOK {
		t.Errorf("expected probe OK, got error: %s", f.ProbeErr)
	}
	if !f.NotAfter.Equal(notAfter) {
		t.Errorf("expected NotAfter %v, got %v", notAfter, f.NotAfter)
	}
}

func TestAPIServiceDiscoverer_DefaultPort(t *testing.T) {
	as := &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: "v1.custom.example.com"},
		Spec: apiregistrationv1.APIServiceSpec{
			Service: &apiregistrationv1.ServiceReference{
				Name:      "custom-api",
				Namespace: "custom-ns",
				// Port is nil — should default to 443
			},
		},
	}

	client := newFakeAggregatorClient(as)
	d := NewAPIServiceDiscoverer(client)
	d.probeFn = mockProbeFn(time.Now().Add(24 * time.Hour))

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Target != "custom-api.custom-ns.svc:443" {
		t.Errorf("expected target %q, got %q", "custom-api.custom-ns.svc:443", findings[0].Target)
	}
}

func TestAPIServiceDiscoverer_CustomPort(t *testing.T) {
	port := int32(8443)
	as := &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: "v1.custom.example.com"},
		Spec: apiregistrationv1.APIServiceSpec{
			Service: &apiregistrationv1.ServiceReference{
				Name:      "custom-api",
				Namespace: "custom-ns",
				Port:      &port,
			},
		},
	}

	client := newFakeAggregatorClient(as)
	d := NewAPIServiceDiscoverer(client)
	d.probeFn = mockProbeFn(time.Now().Add(24 * time.Hour))

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Target != "custom-api.custom-ns.svc:8443" {
		t.Errorf("expected target %q, got %q", "custom-api.custom-ns.svc:8443", findings[0].Target)
	}
}

func TestAPIServiceDiscoverer_LocalSkipped(t *testing.T) {
	as := &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: "v1."},
		Spec:       apiregistrationv1.APIServiceSpec{
			// Service is nil — handled locally by kube-apiserver
		},
	}

	client := newFakeAggregatorClient(as)
	d := NewAPIServiceDiscoverer(client)
	d.probeFn = func(_ string) probe.Result {
		t.Fatal("probeFn should not be called for local APIServices")
		return probe.Result{}
	}

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for local APIService, got %d", len(findings))
	}
}

func TestAPIServiceDiscoverer_NoAPIServices(t *testing.T) {
	client := newFakeAggregatorClient()
	d := NewAPIServiceDiscoverer(client)
	d.probeFn = func(_ string) probe.Result {
		t.Fatal("probeFn should not be called when there are no APIServices")
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

func TestAPIServiceDiscoverer_Multiple(t *testing.T) {
	port := int32(443)
	objs := []runtime.Object{
		&apiregistrationv1.APIService{
			ObjectMeta: metav1.ObjectMeta{Name: "v1beta1.metrics.k8s.io"},
			Spec: apiregistrationv1.APIServiceSpec{
				Service: &apiregistrationv1.ServiceReference{
					Name: "metrics-server", Namespace: "kube-system", Port: &port,
				},
			},
		},
		&apiregistrationv1.APIService{
			ObjectMeta: metav1.ObjectMeta{Name: "v1.custom.example.com"},
			Spec: apiregistrationv1.APIServiceSpec{
				Service: &apiregistrationv1.ServiceReference{
					Name: "custom-api", Namespace: "custom-ns", Port: &port,
				},
			},
		},
		&apiregistrationv1.APIService{
			ObjectMeta: metav1.ObjectMeta{Name: "v1."},
			Spec:       apiregistrationv1.APIServiceSpec{
				// Local — no service ref
			},
		},
	}

	client := newFakeAggregatorClient(objs...)
	d := NewAPIServiceDiscoverer(client)
	d.probeFn = mockProbeFn(time.Now().Add(24 * time.Hour))

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (skipping local), got %d", len(findings))
	}
}

func TestAPIServiceDiscoverer_ProbeFailure(t *testing.T) {
	port := int32(443)
	as := &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: "v1beta1.metrics.k8s.io"},
		Spec: apiregistrationv1.APIServiceSpec{
			Service: &apiregistrationv1.ServiceReference{
				Name: "metrics-server", Namespace: "kube-system", Port: &port,
			},
		},
	}

	client := newFakeAggregatorClient(as)
	d := NewAPIServiceDiscoverer(client)
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
	if !f.NotAfter.IsZero() {
		t.Error("expected zero NotAfter on probe failure")
	}
}
