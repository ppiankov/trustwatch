package discovery

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ppiankov/trustwatch/internal/store"
)

func fakeWithCertManagerRenewal() *fake.Clientset {
	cs := fake.NewClientset()
	fd := cs.Discovery().(*fakediscovery.FakeDiscovery)
	fd.Resources = append(fd.Resources,
		&metav1.APIResourceList{
			GroupVersion: "cert-manager.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "certificates", Kind: "Certificate", Namespaced: true},
				{Name: "certificaterequests", Kind: "CertificateRequest", Namespaced: true},
			},
		},
		&metav1.APIResourceList{
			GroupVersion: "acme.cert-manager.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "challenges", Kind: "Challenge", Namespaced: true},
			},
		},
	)
	return cs
}

func renewalDynClient(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{
			certRequestGVR: "CertificateRequestList",
			challengeGVR:   "ChallengeList",
			certGVR:        "CertificateList",
		},
		objs...,
	)
}

func makeCertRequest(name, ns string, createdAgo time.Duration, readyStatus, message string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "cert-manager.io/v1",
			"kind":       "CertificateRequest",
			"metadata": map[string]interface{}{
				"name":              name,
				"namespace":         ns,
				"creationTimestamp": time.Now().Add(-createdAgo).UTC().Format(time.RFC3339),
			},
		},
	}
	if readyStatus != "" {
		obj.Object["status"] = map[string]interface{}{
			"conditions": []interface{}{
				map[string]interface{}{
					"type":    "Ready",
					"status":  readyStatus,
					"message": message,
				},
			},
		}
	}
	return obj
}

func makeChallenge(name, ns, state, reason string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "acme.cert-manager.io/v1",
			"kind":       "Challenge",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": ns,
			},
			"status": map[string]interface{}{
				"state":  state,
				"reason": reason,
			},
		},
	}
}

func makeCertWithCondition(name, ns, readyStatus, message string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "cert-manager.io/v1",
			"kind":       "Certificate",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": ns,
			},
			"status": map[string]interface{}{
				"conditions": []interface{}{
					map[string]interface{}{
						"type":    "Ready",
						"status":  readyStatus,
						"message": message,
					},
				},
			},
		},
	}
}

func TestCertManagerRenewalDiscoverer_Name(t *testing.T) {
	d := NewCertManagerRenewalDiscoverer(renewalDynClient(), fake.NewClientset())
	if d.Name() != "certmanager.renewal" {
		t.Errorf("expected name 'certmanager.renewal', got %q", d.Name())
	}
}

func TestCertManagerRenewalDiscoverer_CRDsAbsent(t *testing.T) {
	d := NewCertManagerRenewalDiscoverer(renewalDynClient(), fake.NewClientset())
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings when CRDs absent, got %d", len(findings))
	}
}

func TestCertManagerRenewalDiscoverer_StalledRequest(t *testing.T) {
	now := time.Now()
	cr := makeCertRequest("stale-req", "prod", 2*time.Hour, "False", "Waiting for approval")
	dyn := renewalDynClient(cr)
	core := fakeWithCertManagerRenewal()

	d := NewCertManagerRenewalDiscoverer(dyn, core, func(d *CertManagerRenewalDiscoverer) {
		d.nowFn = func() time.Time { return now }
	})
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Source != store.SourceCertManagerRenewal {
		t.Errorf("source = %q, want %q", f.Source, store.SourceCertManagerRenewal)
	}
	if f.FindingType != FindingRenewalStalled {
		t.Errorf("findingType = %q, want %q", f.FindingType, FindingRenewalStalled)
	}
	if f.Name != "stale-req" {
		t.Errorf("name = %q, want %q", f.Name, "stale-req")
	}
}

func TestCertManagerRenewalDiscoverer_RecentRequestIgnored(t *testing.T) {
	now := time.Now()
	cr := makeCertRequest("fresh-req", "prod", 30*time.Minute, "False", "Waiting")
	dyn := renewalDynClient(cr)
	core := fakeWithCertManagerRenewal()

	d := NewCertManagerRenewalDiscoverer(dyn, core, func(d *CertManagerRenewalDiscoverer) {
		d.nowFn = func() time.Time { return now }
	})
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Fresh request should not be stalled, but Certificate might still be not-ready
	for _, f := range findings {
		if f.FindingType == FindingRenewalStalled {
			t.Error("did not expect RENEWAL_STALLED for recent request")
		}
	}
}

func TestCertManagerRenewalDiscoverer_ReadyRequestIgnored(t *testing.T) {
	now := time.Now()
	cr := makeCertRequest("ready-req", "prod", 2*time.Hour, "True", "Certificate issued")
	dyn := renewalDynClient(cr)
	core := fakeWithCertManagerRenewal()

	d := NewCertManagerRenewalDiscoverer(dyn, core, func(d *CertManagerRenewalDiscoverer) {
		d.nowFn = func() time.Time { return now }
	})
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.FindingType == FindingRenewalStalled {
			t.Error("did not expect RENEWAL_STALLED for ready request")
		}
	}
}

func TestCertManagerRenewalDiscoverer_FailedChallenge(t *testing.T) {
	ch := makeChallenge("chal-1", "prod", "errored", "DNS01 validation failed")
	dyn := renewalDynClient(ch)
	core := fakeWithCertManagerRenewal()

	d := NewCertManagerRenewalDiscoverer(dyn, core)
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.FindingType == FindingChallengeFailed {
			found = true
			if f.Name != "chal-1" {
				t.Errorf("name = %q, want %q", f.Name, "chal-1")
			}
		}
	}
	if !found {
		t.Error("expected CHALLENGE_FAILED finding")
	}
}

func TestCertManagerRenewalDiscoverer_PendingChallenge(t *testing.T) {
	ch := makeChallenge("chal-pending", "prod", "pending", "")
	dyn := renewalDynClient(ch)
	core := fakeWithCertManagerRenewal()

	d := NewCertManagerRenewalDiscoverer(dyn, core)
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.FindingType == FindingChallengeFailed {
			t.Error("pending challenge should not produce CHALLENGE_FAILED")
		}
	}
}

func TestCertManagerRenewalDiscoverer_CertificateNotReady(t *testing.T) {
	cert := makeCertWithCondition("my-cert", "prod", "False", "Issuing certificate")
	dyn := renewalDynClient(cert)
	core := fakeWithCertManagerRenewal()

	d := NewCertManagerRenewalDiscoverer(dyn, core)
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.FindingType == FindingRequestPending {
			found = true
			if f.Name != "my-cert" {
				t.Errorf("name = %q, want %q", f.Name, "my-cert")
			}
		}
	}
	if !found {
		t.Error("expected REQUEST_PENDING finding")
	}
}

func TestCertManagerRenewalDiscoverer_CertificateReady(t *testing.T) {
	cert := makeCertWithCondition("ready-cert", "prod", "True", "Certificate is up to date")
	dyn := renewalDynClient(cert)
	core := fakeWithCertManagerRenewal()

	d := NewCertManagerRenewalDiscoverer(dyn, core)
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.FindingType == FindingRequestPending {
			t.Error("ready certificate should not produce REQUEST_PENDING")
		}
	}
}

func TestCertManagerRenewalDiscoverer_CustomStaleDuration(t *testing.T) {
	now := time.Now()
	// 45 minutes old, custom threshold of 30 minutes
	cr := makeCertRequest("slow-req", "prod", 45*time.Minute, "False", "Pending")
	dyn := renewalDynClient(cr)
	core := fakeWithCertManagerRenewal()

	d := NewCertManagerRenewalDiscoverer(dyn, core,
		WithStaleDuration(30*time.Minute),
		func(d *CertManagerRenewalDiscoverer) {
			d.nowFn = func() time.Time { return now }
		},
	)
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var found bool
	for _, f := range findings {
		if f.FindingType == FindingRenewalStalled {
			found = true
		}
	}
	if !found {
		t.Error("expected RENEWAL_STALLED with custom 30m threshold")
	}
}

func TestCertManagerRenewalDiscoverer_NamespaceFiltered(t *testing.T) {
	now := time.Now()
	cr1 := makeCertRequest("req-ns1", testNS1, 2*time.Hour, "False", "Pending")
	cr2 := makeCertRequest("req-ns2", testNS2, 2*time.Hour, "False", "Pending")
	dyn := renewalDynClient(cr1, cr2)
	core := fakeWithCertManagerRenewal()

	d := NewCertManagerRenewalDiscoverer(dyn, core,
		WithRenewalNamespaces([]string{testNS1}),
		func(d *CertManagerRenewalDiscoverer) {
			d.nowFn = func() time.Time { return now }
		},
	)
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Namespace == testNS2 {
			t.Errorf("found finding in %q, expected only %q", testNS2, testNS1)
		}
	}
}
