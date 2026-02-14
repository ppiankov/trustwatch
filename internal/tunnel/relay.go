// Package tunnel provides a SOCKS5 relay for routing TLS probes through
// an in-cluster proxy pod, enabling trustwatch to resolve cluster-internal
// DNS from a laptop.
package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

	"github.com/ppiankov/trustwatch/internal/probe"
)

const (
	// DefaultImage is the default SOCKS5 proxy image.
	// Override with --tunnel-image if your cluster can't pull from Docker Hub.
	DefaultImage = "serjs/go-socks5-proxy:latest"

	relayPort     = 1080
	podWaitPoll   = 2 * time.Second
	podWaitMax    = 120 * time.Second
	activeDeadSec = 300
)

// Relay manages the lifecycle of a disposable SOCKS5 proxy pod + port-forward.
type Relay struct {
	clientset  kubernetes.Interface
	restConfig *rest.Config
	stopChan   chan struct{}
	image      string
	namespace  string
	podName    string
	pullSecret string
	command    []string
	closeOnce  sync.Once
	localPort  uint16
}

// NewRelay creates a relay that will deploy a SOCKS5 proxy pod in the given namespace.
// If command is non-empty, it overrides the container's default entrypoint.
// If pullSecret is non-empty, it is set as an imagePullSecret on the pod.
func NewRelay(cs kubernetes.Interface, cfg *rest.Config, ns, image string, command []string, pullSecret string) *Relay {
	if image == "" {
		image = DefaultImage
	}
	return &Relay{
		clientset:  cs,
		restConfig: cfg,
		namespace:  ns,
		image:      image,
		command:    command,
		pullSecret: pullSecret,
		podName:    fmt.Sprintf("trustwatch-relay-%d", time.Now().UnixNano()%100000),
		stopChan:   make(chan struct{}),
	}
}

// Start creates the proxy pod, waits for it to become ready, and establishes
// a port-forward from a random local port to the pod's SOCKS5 port.
func (r *Relay) Start(ctx context.Context) error {
	pod := r.podSpec()
	created, err := r.clientset.CoreV1().Pods(r.namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("creating relay pod: %w", err)
	}
	r.podName = created.Name

	// Wait for pod to be Running (image pull can take a while on cold clusters)
	var lastPhase corev1.PodPhase
	var lastReason string
	err = wait.PollUntilContextTimeout(ctx, podWaitPoll, podWaitMax, true, func(ctx context.Context) (bool, error) {
		p, getErr := r.clientset.CoreV1().Pods(r.namespace).Get(ctx, r.podName, metav1.GetOptions{})
		if getErr != nil {
			return false, nil // transient API error, retry
		}
		if p.Status.Phase != lastPhase {
			lastPhase = p.Status.Phase
			slog.Debug("relay pod status", "pod", r.podName, "phase", lastPhase)
		}
		// Extract container-level detail for better error messages
		lastReason = containerWaitReason(p)
		if lastReason != "" && lastReason != "ContainerCreating" && lastReason != "PodInitializing" {
			slog.Debug("relay pod container", "pod", r.podName, "reason", lastReason)
		}
		if p.Status.Phase == corev1.PodFailed {
			msg := "relay pod failed"
			if lastReason != "" {
				msg = fmt.Sprintf("relay pod failed: %s", lastReason)
			}
			return false, fmt.Errorf("%s", msg)
		}
		// Container exited cleanly — image has no long-running process
		if p.Status.Phase == corev1.PodSucceeded {
			return false, fmt.Errorf("relay pod exited (image has no long-running SOCKS5 server; use --tunnel-command)")
		}
		// Bail early on permanent image pull failures
		if isImagePullFailure(lastReason) {
			return false, fmt.Errorf("image pull failed for %s: %s", r.image, lastReason)
		}
		return p.Status.Phase == corev1.PodRunning, nil
	})
	if err != nil {
		r.deletePod(context.Background()) //nolint:errcheck // best-effort cleanup
		return fmt.Errorf("waiting for relay pod (phase: %s): %w", lastPhase, err)
	}

	// Establish port-forward
	localPort, err := r.portForward(ctx)
	if err != nil {
		r.deletePod(context.Background()) //nolint:errcheck // best-effort cleanup
		return fmt.Errorf("port-forwarding to relay pod: %w", err)
	}
	r.localPort = localPort

	return nil
}

// ProbeFn returns a probe function that routes TLS connections through the SOCKS5 relay.
func (r *Relay) ProbeFn() func(string) probe.Result {
	return func(raw string) probe.Result {
		socksDialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", r.localPort), nil, proxy.Direct)
		if err != nil {
			return probe.Result{ProbeErr: fmt.Sprintf("creating SOCKS5 dialer: %v", err)}
		}
		ctxDialer, ok := socksDialer.(proxy.ContextDialer)
		if !ok {
			return probe.Result{ProbeErr: "SOCKS5 dialer does not support DialContext"}
		}
		return probe.ProbeWithDialer(raw, ctxDialer.DialContext)
	}
}

// Close deletes the relay pod and stops the port-forward. Safe to call multiple times.
func (r *Relay) Close() error {
	var closeErr error
	r.closeOnce.Do(func() {
		close(r.stopChan)
		closeErr = r.deletePod(context.Background())
	})
	return closeErr
}

// LocalPort returns the local port used for the SOCKS5 connection.
func (r *Relay) LocalPort() uint16 {
	return r.localPort
}

// PodName returns the name of the relay pod.
func (r *Relay) PodName() string {
	return r.podName
}

func (r *Relay) podSpec() *corev1.Pod {
	activeDeadline := int64(activeDeadSec)
	pullPolicy := corev1.PullIfNotPresent
	if strings.HasSuffix(r.image, ":latest") {
		pullPolicy = corev1.PullAlways
	}
	var imagePullSecrets []corev1.LocalObjectReference
	if r.pullSecret != "" {
		imagePullSecrets = []corev1.LocalObjectReference{{Name: r.pullSecret}}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.podName,
			Namespace: r.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "trustwatch-relay",
				"app.kubernetes.io/managed-by": "trustwatch",
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy:         corev1.RestartPolicyNever,
			ActiveDeadlineSeconds: &activeDeadline,
			ImagePullSecrets:      imagePullSecrets,
			Containers: []corev1.Container{
				{
					Name:            "socks5",
					Image:           r.image,
					Command:         r.command,
					ImagePullPolicy: pullPolicy,
					Ports: []corev1.ContainerPort{
						{ContainerPort: relayPort, Protocol: corev1.ProtocolTCP},
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("10m"),
							corev1.ResourceMemory: resource.MustParse("16Mi"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("100m"),
							corev1.ResourceMemory: resource.MustParse("64Mi"),
						},
					},
				},
			},
		},
	}
}

func (r *Relay) portForward(ctx context.Context) (uint16, error) {
	reqURL := r.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(r.namespace).
		Name(r.podName).
		SubResource("portforward").
		URL()

	transport, upgrader, err := spdy.RoundTripperFor(r.restConfig)
	if err != nil {
		return 0, fmt.Errorf("creating SPDY round-tripper: %w", err)
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, reqURL)

	readyChan := make(chan struct{})
	errChan := make(chan error, 1)

	// 0:1080 means random local port → pod port 1080
	fw, err := portforward.New(dialer, []string{fmt.Sprintf("0:%d", relayPort)}, r.stopChan, readyChan, io.Discard, io.Discard)
	if err != nil {
		return 0, fmt.Errorf("creating port-forwarder: %w", err)
	}

	go func() {
		errChan <- fw.ForwardPorts()
	}()

	select {
	case <-readyChan:
		// Port-forward is ready
	case fwErr := <-errChan:
		return 0, fmt.Errorf("port-forward failed: %w", fwErr)
	case <-ctx.Done():
		return 0, ctx.Err()
	}

	ports, err := fw.GetPorts()
	if err != nil {
		return 0, fmt.Errorf("getting forwarded ports: %w", err)
	}
	if len(ports) == 0 {
		return 0, fmt.Errorf("no ports forwarded")
	}

	return ports[0].Local, nil
}

func (r *Relay) deletePod(ctx context.Context) error {
	err := r.clientset.CoreV1().Pods(r.namespace).Delete(ctx, r.podName, metav1.DeleteOptions{})
	if err != nil && !strings.Contains(err.Error(), "not found") {
		return fmt.Errorf("deleting relay pod: %w", err)
	}
	return nil
}

// containerWaitReason extracts the waiting reason from the first container status.
func containerWaitReason(p *corev1.Pod) string {
	for i := range p.Status.ContainerStatuses {
		cs := &p.Status.ContainerStatuses[i]
		if cs.State.Waiting != nil {
			reason := cs.State.Waiting.Reason
			if cs.State.Waiting.Message != "" {
				return fmt.Sprintf("%s: %s", reason, cs.State.Waiting.Message)
			}
			return reason
		}
		if cs.State.Terminated != nil && cs.State.Terminated.Reason != "" {
			reason := cs.State.Terminated.Reason
			if cs.State.Terminated.Message != "" {
				return fmt.Sprintf("%s: %s", reason, cs.State.Terminated.Message)
			}
			return reason
		}
	}
	return ""
}

// isImagePullFailure returns true for container reasons that indicate
// a permanent image pull failure (not a transient retry).
func isImagePullFailure(reason string) bool {
	return strings.HasPrefix(reason, "ErrImagePull") ||
		strings.HasPrefix(reason, "ImagePullBackOff") ||
		strings.HasPrefix(reason, "InvalidImageName")
}
