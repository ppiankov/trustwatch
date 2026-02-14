package discovery

import (
	"context"
	"testing"

	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const (
	testNS1 = "ns1"
	testNS2 = "ns2"
	testNS3 = "ns3"
)

func TestResolveNamespaces_Explicit(t *testing.T) {
	cs := fake.NewClientset()
	explicit := []string{testNS1, testNS2}
	result, err := ResolveNamespaces(context.Background(), cs, explicit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 || result[0] != testNS1 || result[1] != testNS2 {
		t.Errorf("expected %v, got %v", explicit, result)
	}
}

func TestResolveNamespaces_AllNamespaces(t *testing.T) {
	objs := []runtime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}},
	}
	cs := fake.NewClientset(objs...)
	result, err := ResolveNamespaces(context.Background(), cs, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("expected 3 namespaces, got %d", len(result))
	}
}

func TestFilterAccessible_AllAllowed(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "selfsubjectaccessreviews",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			review := action.(k8stesting.CreateAction).GetObject().(*authv1.SelfSubjectAccessReview)
			review.Status.Allowed = true
			return true, review, nil
		})

	result := FilterAccessible(context.Background(), cs, []string{testNS1, testNS2, testNS3}, "", "secrets")
	if len(result) != 3 {
		t.Errorf("expected 3 accessible namespaces, got %d: %v", len(result), result)
	}
}

func TestFilterAccessible_SomeDenied(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "selfsubjectaccessreviews",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			review := action.(k8stesting.CreateAction).GetObject().(*authv1.SelfSubjectAccessReview)
			ns := review.Spec.ResourceAttributes.Namespace
			review.Status.Allowed = ns != "denied-ns"
			return true, review, nil
		})

	result := FilterAccessible(context.Background(), cs,
		[]string{"allowed-ns", "denied-ns", "other-ns"}, "", "secrets")
	if len(result) != 2 {
		t.Fatalf("expected 2 accessible namespaces, got %d: %v", len(result), result)
	}
	if result[0] != "allowed-ns" || result[1] != "other-ns" {
		t.Errorf("expected [allowed-ns other-ns], got %v", result)
	}
}

func TestFilterAccessible_APIErrorAssumesAllowed(t *testing.T) {
	cs := fake.NewClientset()
	// Default fake returns empty SSAR without reactor — no error, but Status is empty.
	// We need to simulate an actual error by returning one from the reactor.
	cs.PrependReactor("create", "selfsubjectaccessreviews",
		func(_ k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, context.DeadlineExceeded
		})

	result := FilterAccessible(context.Background(), cs, []string{testNS1, testNS2}, "", "secrets")
	if len(result) != 2 {
		t.Errorf("expected 2 namespaces (assume allowed on error), got %d: %v", len(result), result)
	}
}

func TestFilterAccessible_ChecksGroupAndResource(t *testing.T) {
	cs := fake.NewClientset()
	var capturedGroup, capturedResource string
	cs.PrependReactor("create", "selfsubjectaccessreviews",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			review := action.(k8stesting.CreateAction).GetObject().(*authv1.SelfSubjectAccessReview)
			capturedGroup = review.Spec.ResourceAttributes.Group
			capturedResource = review.Spec.ResourceAttributes.Resource
			review.Status.Allowed = true
			return true, review, nil
		})

	FilterAccessible(context.Background(), cs, []string{testNS1}, "networking.k8s.io", "ingresses")
	if capturedGroup != "networking.k8s.io" {
		t.Errorf("expected group %q, got %q", "networking.k8s.io", capturedGroup)
	}
	if capturedResource != "ingresses" {
		t.Errorf("expected resource %q, got %q", "ingresses", capturedResource)
	}
}

func TestNamespacesOrAll_Empty(t *testing.T) {
	result := namespacesOrAll(nil)
	if len(result) != 1 || result[0] != "" {
		t.Errorf("expected [\"\"], got %v", result)
	}
}

func TestNamespacesOrAll_WithNamespaces(t *testing.T) {
	result := namespacesOrAll([]string{testNS1, testNS2})
	if len(result) != 2 || result[0] != testNS1 || result[1] != testNS2 {
		t.Errorf("expected [ns1 ns2], got %v", result)
	}
}
