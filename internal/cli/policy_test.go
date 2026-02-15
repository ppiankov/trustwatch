package cli

import (
	"bytes"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

var trustPolicyGVR = schema.GroupVersionResource{
	Group:    "trustwatch.dev",
	Version:  "v1alpha1",
	Resource: "trustpolicies",
}

func policyFakeWithCRD() *fake.Clientset {
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

func policyDynClient(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{
			trustPolicyGVR: "TrustPolicyList",
		},
		objs...,
	)
}

func makeTrustPolicyObj(name, namespace string, targets, rules int) *unstructured.Unstructured {
	spec := map[string]interface{}{}
	if targets > 0 {
		ts := make([]interface{}, targets)
		for i := range ts {
			ts[i] = map[string]interface{}{"kind": "Service", "name": "svc"}
		}
		spec["targets"] = ts
	}
	if rules > 0 {
		rs := make([]interface{}, rules)
		for i := range rs {
			rs[i] = map[string]interface{}{"name": "rule", "type": "minKeySize"}
		}
		spec["rules"] = rs
	}
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "trustwatch.dev/v1alpha1",
			"kind":       "TrustPolicy",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": spec,
		},
	}
}

func TestListPolicies_CRDNotInstalled(t *testing.T) {
	cs := fake.NewClientset()
	dyn := policyDynClient()
	buf := new(bytes.Buffer)

	if err := listPolicies(buf, cs.Discovery(), dyn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "not installed") {
		t.Errorf("expected 'not installed' message, got %q", buf.String())
	}
}

func TestListPolicies_NoPolicies(t *testing.T) {
	cs := policyFakeWithCRD()
	dyn := policyDynClient()
	buf := new(bytes.Buffer)

	if err := listPolicies(buf, cs.Discovery(), dyn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "No TrustPolicy") {
		t.Errorf("expected 'No TrustPolicy' message, got %q", buf.String())
	}
}

func TestListPolicies_WithPolicies(t *testing.T) {
	cs := policyFakeWithCRD()
	tp1 := makeTrustPolicyObj("web-certs", "prod", 2, 1)
	tp2 := makeTrustPolicyObj("api-certs", "staging", 1, 0)
	dyn := policyDynClient(tp1, tp2)
	buf := new(bytes.Buffer)

	if err := listPolicies(buf, cs.Discovery(), dyn); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "NAMESPACE") {
		t.Error("expected table header")
	}
	if !strings.Contains(out, "web-certs") {
		t.Error("expected web-certs in output")
	}
	if !strings.Contains(out, "api-certs") {
		t.Error("expected api-certs in output")
	}
	if !strings.Contains(out, "prod") {
		t.Error("expected prod namespace in output")
	}
}
