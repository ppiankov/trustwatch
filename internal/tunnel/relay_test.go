package tunnel

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func TestPodSpec_Labels(t *testing.T) {
	r := NewRelay(fake.NewClientset(), &rest.Config{}, "default")
	pod := r.podSpec()

	want := map[string]string{
		"app.kubernetes.io/name":       "trustwatch-relay",
		"app.kubernetes.io/managed-by": "trustwatch",
	}

	for k, v := range want {
		got, ok := pod.Labels[k]
		if !ok {
			t.Errorf("expected label %q, not found", k)
			continue
		}
		if got != v {
			t.Errorf("label %q: expected %q, got %q", k, v, got)
		}
	}
}

func TestPodSpec_Image(t *testing.T) {
	r := NewRelay(fake.NewClientset(), &rest.Config{}, "default")
	pod := r.podSpec()

	if len(pod.Spec.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(pod.Spec.Containers))
	}

	if pod.Spec.Containers[0].Image != relayImage {
		t.Errorf("expected image %q, got %q", relayImage, pod.Spec.Containers[0].Image)
	}
}

func TestPodSpec_ActiveDeadline(t *testing.T) {
	r := NewRelay(fake.NewClientset(), &rest.Config{}, "default")
	pod := r.podSpec()

	if pod.Spec.ActiveDeadlineSeconds == nil {
		t.Fatal("expected ActiveDeadlineSeconds to be set")
	}
	if *pod.Spec.ActiveDeadlineSeconds != activeDeadSec {
		t.Errorf("expected ActiveDeadlineSeconds %d, got %d", activeDeadSec, *pod.Spec.ActiveDeadlineSeconds)
	}
}

func TestPodSpec_RestartPolicy(t *testing.T) {
	r := NewRelay(fake.NewClientset(), &rest.Config{}, "default")
	pod := r.podSpec()

	if pod.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Errorf("expected RestartPolicy %q, got %q", corev1.RestartPolicyNever, pod.Spec.RestartPolicy)
	}
}

func TestPodSpec_Resources(t *testing.T) {
	r := NewRelay(fake.NewClientset(), &rest.Config{}, "default")
	pod := r.podSpec()

	c := pod.Spec.Containers[0]

	wantReqCPU := resource.MustParse("10m")
	if !c.Resources.Requests.Cpu().Equal(wantReqCPU) {
		t.Errorf("expected CPU request %s, got %s", wantReqCPU.String(), c.Resources.Requests.Cpu().String())
	}

	wantReqMem := resource.MustParse("16Mi")
	if !c.Resources.Requests.Memory().Equal(wantReqMem) {
		t.Errorf("expected memory request %s, got %s", wantReqMem.String(), c.Resources.Requests.Memory().String())
	}

	wantLimCPU := resource.MustParse("100m")
	if !c.Resources.Limits.Cpu().Equal(wantLimCPU) {
		t.Errorf("expected CPU limit %s, got %s", wantLimCPU.String(), c.Resources.Limits.Cpu().String())
	}

	wantLimMem := resource.MustParse("64Mi")
	if !c.Resources.Limits.Memory().Equal(wantLimMem) {
		t.Errorf("expected memory limit %s, got %s", wantLimMem.String(), c.Resources.Limits.Memory().String())
	}
}

func TestPodSpec_Port(t *testing.T) {
	r := NewRelay(fake.NewClientset(), &rest.Config{}, "default")
	pod := r.podSpec()

	c := pod.Spec.Containers[0]
	if len(c.Ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(c.Ports))
	}
	if c.Ports[0].ContainerPort != relayPort {
		t.Errorf("expected container port %d, got %d", relayPort, c.Ports[0].ContainerPort)
	}
	if c.Ports[0].Protocol != corev1.ProtocolTCP {
		t.Errorf("expected protocol TCP, got %s", c.Ports[0].Protocol)
	}
}

func TestPodSpec_Namespace(t *testing.T) {
	r := NewRelay(fake.NewClientset(), &rest.Config{}, "kube-system")
	pod := r.podSpec()

	if pod.Namespace != "kube-system" {
		t.Errorf("expected namespace %q, got %q", "kube-system", pod.Namespace)
	}
}

func TestNewRelay_PodNamePrefix(t *testing.T) {
	r := NewRelay(fake.NewClientset(), &rest.Config{}, "default")
	if r.podName == "" {
		t.Error("expected non-empty pod name")
	}
	const prefix = "trustwatch-relay-"
	if len(r.podName) < len(prefix) || r.podName[:len(prefix)] != prefix {
		t.Errorf("expected pod name to start with %q, got %q", prefix, r.podName)
	}
}

func TestClose_Idempotent(t *testing.T) {
	cs := fake.NewClientset()
	r := NewRelay(cs, &rest.Config{}, "default")

	// Close without Start — should not panic
	if err := r.Close(); err != nil {
		t.Errorf("first Close: unexpected error: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("second Close: unexpected error: %v", err)
	}
}

func TestProbeFn_ReturnsFunction(t *testing.T) {
	r := NewRelay(fake.NewClientset(), &rest.Config{}, "default")
	fn := r.ProbeFn()
	if fn == nil {
		t.Fatal("expected non-nil ProbeFn")
	}

	// Calling it without a running relay should return an error (SOCKS5 connect fails)
	result := fn("tcp://example.com:443")
	if result.ProbeOK {
		t.Error("expected probe to fail without running relay")
	}
	if result.ProbeErr == "" {
		t.Error("expected non-empty error from probe without running relay")
	}
}
