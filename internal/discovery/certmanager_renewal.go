package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/ppiankov/trustwatch/internal/store"
)

const defaultStaleDuration = time.Hour

// FindingRenewalStalled indicates a CertificateRequest pending beyond the stale threshold.
const FindingRenewalStalled = "RENEWAL_STALLED"

// FindingChallengeFailed indicates an ACME Challenge in an errored or invalid state.
const FindingChallengeFailed = "CHALLENGE_FAILED"

// FindingRequestPending indicates a Certificate whose Ready condition is False.
const FindingRequestPending = "REQUEST_PENDING"

var (
	certRequestGVR = schema.GroupVersionResource{
		Group:    "cert-manager.io",
		Version:  "v1",
		Resource: "certificaterequests",
	}
	challengeGVR = schema.GroupVersionResource{
		Group:    "acme.cert-manager.io",
		Version:  "v1",
		Resource: "challenges",
	}
)

// CertManagerRenewalDiscoverer detects stuck cert-manager renewals.
type CertManagerRenewalDiscoverer struct {
	dynamicClient dynamic.Interface
	coreClient    kubernetes.Interface
	nowFn         func() time.Time
	namespaces    []string
	staleDuration time.Duration
}

// NewCertManagerRenewalDiscoverer creates a discoverer for cert-manager renewal health.
func NewCertManagerRenewalDiscoverer(dyn dynamic.Interface, core kubernetes.Interface, opts ...func(*CertManagerRenewalDiscoverer)) *CertManagerRenewalDiscoverer {
	d := &CertManagerRenewalDiscoverer{
		dynamicClient: dyn,
		coreClient:    core,
		staleDuration: defaultStaleDuration,
		nowFn:         time.Now,
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// WithRenewalNamespaces restricts discovery to the given namespaces.
func WithRenewalNamespaces(ns []string) func(*CertManagerRenewalDiscoverer) {
	return func(d *CertManagerRenewalDiscoverer) {
		d.namespaces = ns
	}
}

// WithStaleDuration overrides the default stale threshold for pending CertificateRequests.
func WithStaleDuration(dur time.Duration) func(*CertManagerRenewalDiscoverer) {
	return func(d *CertManagerRenewalDiscoverer) {
		d.staleDuration = dur
	}
}

// Name returns the discoverer label.
func (d *CertManagerRenewalDiscoverer) Name() string {
	return "certmanager.renewal"
}

// Discover checks for stuck renewals, failed challenges, and non-ready certificates.
// Returns nil, nil if cert-manager CRDs are not installed.
func (d *CertManagerRenewalDiscoverer) Discover() ([]store.CertFinding, error) {
	if !d.certManagerInstalled() {
		slog.Debug("cert-manager CRDs not installed, skipping renewal check")
		return nil, nil
	}

	ctx := context.Background()
	var findings []store.CertFinding

	stalledFindings, err := d.findStalledRequests(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking stalled requests: %w", err)
	}
	findings = append(findings, stalledFindings...)

	failedFindings, err := d.findFailedChallenges(ctx)
	if err != nil {
		// Challenges CRD may not exist (non-ACME setups); log and continue
		slog.Debug("skipping challenge check", "err", err)
	} else {
		findings = append(findings, failedFindings...)
	}

	pendingFindings, err := d.findPendingCertificates(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking pending certificates: %w", err)
	}
	findings = append(findings, pendingFindings...)

	return findings, nil
}

// certManagerInstalled checks if cert-manager CRDs are registered.
func (d *CertManagerRenewalDiscoverer) certManagerInstalled() bool {
	_, err := d.coreClient.Discovery().ServerResourcesForGroupVersion("cert-manager.io/v1")
	return err == nil
}

// findStalledRequests finds CertificateRequests that have been pending longer than staleDuration.
func (d *CertManagerRenewalDiscoverer) findStalledRequests(ctx context.Context) ([]store.CertFinding, error) {
	var findings []store.CertFinding
	now := d.nowFn()

	for _, ns := range namespacesOrAll(d.namespaces) {
		list, err := d.dynamicClient.Resource(certRequestGVR).Namespace(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("listing certificaterequests in %s: %w", ns, err)
		}

		for i := range list.Items {
			obj := &list.Items[i]
			created := obj.GetCreationTimestamp().Time
			age := now.Sub(created)
			if age < d.staleDuration {
				continue
			}

			// Check if Ready condition is not True
			if isConditionTrue(obj.Object, "Ready") {
				continue
			}

			reason := conditionMessage(obj.Object, "Ready")
			findings = append(findings, store.CertFinding{
				Source:      store.SourceCertManagerRenewal,
				FindingType: FindingRenewalStalled,
				Severity:    store.SeverityWarn,
				Name:        obj.GetName(),
				Namespace:   obj.GetNamespace(),
				ProbeOK:     true,
				Notes:       fmt.Sprintf("CertificateRequest pending for %s: %s", age.Truncate(time.Minute), reason),
			})
		}
	}

	return findings, nil
}

// findFailedChallenges finds ACME challenges in a failed state.
func (d *CertManagerRenewalDiscoverer) findFailedChallenges(ctx context.Context) ([]store.CertFinding, error) {
	var findings []store.CertFinding

	for _, ns := range namespacesOrAll(d.namespaces) {
		list, err := d.dynamicClient.Resource(challengeGVR).Namespace(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("listing challenges in %s: %w", ns, err)
		}

		for i := range list.Items {
			obj := &list.Items[i]
			state := extractString(extractMap(obj.Object, "status"), "state")
			if state != "errored" && state != "invalid" {
				continue
			}

			reason := extractString(extractMap(obj.Object, "status"), "reason")
			findings = append(findings, store.CertFinding{
				Source:      store.SourceCertManagerRenewal,
				FindingType: FindingChallengeFailed,
				Severity:    store.SeverityWarn,
				Name:        obj.GetName(),
				Namespace:   obj.GetNamespace(),
				ProbeOK:     true,
				Notes:       fmt.Sprintf("ACME challenge %s: %s", state, reason),
			})
		}
	}

	return findings, nil
}

// findPendingCertificates finds Certificate resources where the Ready condition is False.
func (d *CertManagerRenewalDiscoverer) findPendingCertificates(ctx context.Context) ([]store.CertFinding, error) {
	var findings []store.CertFinding

	for _, ns := range namespacesOrAll(d.namespaces) {
		list, err := d.dynamicClient.Resource(certGVR).Namespace(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("listing certificates in %s: %w", ns, err)
		}

		for i := range list.Items {
			obj := &list.Items[i]
			if isConditionTrue(obj.Object, "Ready") {
				continue
			}
			// Only report if Ready condition explicitly exists and is False
			if !hasCondition(obj.Object, "Ready") {
				continue
			}

			reason := conditionMessage(obj.Object, "Ready")
			findings = append(findings, store.CertFinding{
				Source:      store.SourceCertManagerRenewal,
				FindingType: FindingRequestPending,
				Severity:    store.SeverityWarn,
				Name:        obj.GetName(),
				Namespace:   obj.GetNamespace(),
				ProbeOK:     true,
				Notes:       fmt.Sprintf("Certificate not ready: %s", reason),
			})
		}
	}

	return findings, nil
}

// isConditionTrue checks if a named condition has status "True" in status.conditions.
func isConditionTrue(obj map[string]interface{}, condType string) bool {
	status := extractMap(obj, "status")
	if status == nil {
		return false
	}
	conditions, ok := status["conditions"].([]interface{})
	if !ok {
		return false
	}
	for _, raw := range conditions {
		c, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if extractString(c, "type") == condType {
			return extractString(c, "status") == "True"
		}
	}
	return false
}

// hasCondition checks if a named condition exists in status.conditions.
func hasCondition(obj map[string]interface{}, condType string) bool {
	status := extractMap(obj, "status")
	if status == nil {
		return false
	}
	conditions, ok := status["conditions"].([]interface{})
	if !ok {
		return false
	}
	for _, raw := range conditions {
		c, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if extractString(c, "type") == condType {
			return true
		}
	}
	return false
}

// conditionMessage extracts the message from a named condition.
func conditionMessage(obj map[string]interface{}, condType string) string {
	status := extractMap(obj, "status")
	if status == nil {
		return ""
	}
	conditions, ok := status["conditions"].([]interface{})
	if !ok {
		return ""
	}
	for _, raw := range conditions {
		c, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if extractString(c, "type") == condType {
			msg := extractString(c, "message")
			if msg != "" {
				return msg
			}
			return extractString(c, "reason")
		}
	}
	return ""
}
