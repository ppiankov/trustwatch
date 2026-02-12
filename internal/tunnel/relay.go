// Package tunnel provides a SOCKS5 relay for routing TLS probes through
// an in-cluster proxy pod, enabling trustwatch to resolve cluster-internal
// DNS from a laptop.
package tunnel

import (
	"context"
	"fmt"
	"io"
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
	relayImage    = "serjs/go-socks5-proxy:latest"
	relayPort     = 1080
	podWaitPoll   = 1 * time.Second
	podWaitMax    = 60 * time.Second
	activeDeadSec = 300
)

// Relay manages the lifecycle of a disposable SOCKS5 proxy pod + port-forward.
type Relay struct {
	clientset  kubernetes.Interface
	restConfig *rest.Config
	stopChan   chan struct{}
	closeOnce  sync.Once
	namespace  string
	podName    string
	localPort  uint16
}

// NewRelay creates a relay that will deploy a SOCKS5 proxy pod in the given namespace.
func NewRelay(cs kubernetes.Interface, cfg *rest.Config, ns string) *Relay {
	return &Relay{
		clientset:  cs,
		restConfig: cfg,
		namespace:  ns,
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

	// Wait for pod to be Running
	err = wait.PollUntilContextTimeout(ctx, podWaitPoll, podWaitMax, true, func(ctx context.Context) (bool, error) {
		p, getErr := r.clientset.CoreV1().Pods(r.namespace).Get(ctx, r.podName, metav1.GetOptions{})
		if getErr != nil {
			return false, getErr
		}
		return p.Status.Phase == corev1.PodRunning, nil
	})
	if err != nil {
		r.deletePod(context.Background()) //nolint:errcheck // best-effort cleanup
		return fmt.Errorf("waiting for relay pod: %w", err)
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
			Containers: []corev1.Container{
				{
					Name:  "socks5",
					Image: relayImage,
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
