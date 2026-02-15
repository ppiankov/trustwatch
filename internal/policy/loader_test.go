package policy

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

func fakeWithTrustPolicy() *fake.Clientset {
	cs := fake.NewClientset()
	fd := cs.Discovery().(*fakediscovery.FakeDiscovery)
	fd.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "trustwatch.dev/v1alpha1",
			APIResources: []metav1.APIResource{
				{Name: "trustpolicies", Kind: "TrustPolicy", Namespaced: true},
			},
		},
	}
	return cs
}

func fakeWithoutTrustPolicy() *fake.Clientset {
	return fake.NewClientset()
}

func newDynamicClient(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{
			trustPolicyGVR: "TrustPolicyList",
		},
		objs...,
	)
}

func makeTrustPolicy(name, namespace string, spec map[string]interface{}) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "trustwatch.dev/v1alpha1",
			"kind":       "TrustPolicy",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
		},
	}
	if spec != nil {
		obj.Object["spec"] = spec
	}
	return obj
}

func TestCRDInstalled_True(t *testing.T) {
	cs := fakeWithTrustPolicy()
	if !CRDInstalled(cs.Discovery()) {
		t.Error("expected CRD installed = true")
	}
}

func TestCRDInstalled_False(t *testing.T) {
	cs := fakeWithoutTrustPolicy()
	if CRDInstalled(cs.Discovery()) {
		t.Error("expected CRD installed = false")
	}
}

func TestLoadPolicies_CRDNotInstalled(t *testing.T) {
	cs := fakeWithoutTrustPolicy()
	dynClient := newDynamicClient()

	policies, err := LoadPolicies(context.Background(), cs.Discovery(), dynClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policies != nil {
		t.Errorf("expected nil policies, got %d", len(policies))
	}
}

func TestLoadPolicies_NoPolicies(t *testing.T) {
	cs := fakeWithTrustPolicy()
	dynClient := newDynamicClient()

	policies, err := LoadPolicies(context.Background(), cs.Discovery(), dynClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 0 {
		t.Errorf("expected 0 policies, got %d", len(policies))
	}
}

func TestLoadPolicies_SinglePolicy(t *testing.T) {
	cs := fakeWithTrustPolicy()
	tp := makeTrustPolicy("web-certs", "prod", map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"kind":      "Service",
				"namespace": "prod",
				"name":      "api",
				"ports":     []interface{}{float64(443), float64(8443)},
			},
			map[string]interface{}{
				"kind": "External",
				"urls": []interface{}{"https://vault.internal:8200"},
			},
		},
		"thresholds": map[string]interface{}{
			"warnBefore": "360h",
			"critBefore": "168h",
		},
		"rules": []interface{}{
			map[string]interface{}{
				"name":   "min-rsa",
				"type":   "minKeySize",
				"params": map[string]interface{}{"algorithm": "RSA", "minBits": "2048"},
			},
		},
	})
	dynClient := newDynamicClient(tp)

	policies, err := LoadPolicies(context.Background(), cs.Discovery(), dynClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}

	p := policies[0]
	if p.Name != "web-certs" {
		t.Errorf("name = %q, want %q", p.Name, "web-certs")
	}
	if p.Namespace != "prod" {
		t.Errorf("namespace = %q, want %q", p.Namespace, "prod")
	}
	if len(p.Spec.Targets) != 2 {
		t.Errorf("targets = %d, want 2", len(p.Spec.Targets))
	}
	if p.Spec.Targets[0].Kind != "Service" {
		t.Errorf("target[0].kind = %q, want %q", p.Spec.Targets[0].Kind, "Service")
	}
	if len(p.Spec.Targets[0].Ports) != 2 {
		t.Errorf("target[0].ports = %d, want 2", len(p.Spec.Targets[0].Ports))
	}
	if p.Spec.Targets[1].URLs[0] != "https://vault.internal:8200" {
		t.Errorf("target[1].urls[0] = %q", p.Spec.Targets[1].URLs[0])
	}
	if p.Spec.Thresholds.WarnBefore != "360h" {
		t.Errorf("warnBefore = %q, want %q", p.Spec.Thresholds.WarnBefore, "360h")
	}
	if len(p.Spec.Rules) != 1 {
		t.Errorf("rules = %d, want 1", len(p.Spec.Rules))
	}
	if p.Spec.Rules[0].Params["minBits"] != "2048" {
		t.Errorf("rule params minBits = %q, want %q", p.Spec.Rules[0].Params["minBits"], "2048")
	}
}

func TestLoadPolicies_MultiplePolicies(t *testing.T) {
	cs := fakeWithTrustPolicy()
	tp1 := makeTrustPolicy("policy-a", "ns1", map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"kind": "Service", "name": "svc-a"},
		},
	})
	tp2 := makeTrustPolicy("policy-b", "ns2", map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{"kind": "External", "urls": []interface{}{"https://example.com:443"}},
		},
	})
	dynClient := newDynamicClient(tp1, tp2)

	policies, err := LoadPolicies(context.Background(), cs.Discovery(), dynClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}
}

func TestLoadPolicies_EmptySpec(t *testing.T) {
	cs := fakeWithTrustPolicy()
	tp := makeTrustPolicy("empty", "default", nil)
	dynClient := newDynamicClient(tp)

	policies, err := LoadPolicies(context.Background(), cs.Discovery(), dynClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if len(policies[0].Spec.Targets) != 0 {
		t.Errorf("expected 0 targets, got %d", len(policies[0].Spec.Targets))
	}
}
