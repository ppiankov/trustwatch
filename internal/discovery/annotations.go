package discovery

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ppiankov/trustwatch/internal/probe"
	"github.com/ppiankov/trustwatch/internal/store"
)

const (
	annoEnabled         = "trustwatch.dev/enabled"
	annoPorts           = "trustwatch.dev/ports"
	annoSNI             = "trustwatch.dev/sni"
	annoSeverity        = "trustwatch.dev/severity"
	annoTLSSecret       = "trustwatch.dev/tls-secret"
	annoExternalTargets = "trustwatch.dev/external-targets"
	defaultAnnotPort    = "443"
)

// AnnotationDiscoverer finds TLS targets from trustwatch.dev/* annotations on Services and Deployments.
type AnnotationDiscoverer struct {
	client  kubernetes.Interface
	probeFn func(string) probe.Result
}

// NewAnnotationDiscoverer creates a discoverer that scans annotations for TLS targets.
func NewAnnotationDiscoverer(client kubernetes.Interface) *AnnotationDiscoverer {
	return &AnnotationDiscoverer{
		client:  client,
		probeFn: probe.Probe,
	}
}

// Name returns the discoverer label.
func (d *AnnotationDiscoverer) Name() string {
	return "annotations"
}

// Discover scans Services and Deployments for trustwatch.dev annotations.
func (d *AnnotationDiscoverer) Discover() ([]store.CertFinding, error) {
	ctx := context.Background()
	var findings []store.CertFinding

	svcs, err := d.client.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing services: %w", err)
	}
	for i := range svcs.Items {
		svc := &svcs.Items[i]
		if svc.Annotations[annoEnabled] != "true" {
			continue
		}
		findings = append(findings, d.processAnnotated(ctx, svc.Namespace, svc.Name, "Service", svc.Annotations)...)
	}

	deps, err := d.client.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing deployments: %w", err)
	}
	for i := range deps.Items {
		dep := &deps.Items[i]
		if dep.Annotations[annoEnabled] != "true" {
			continue
		}
		findings = append(findings, d.processAnnotated(ctx, dep.Namespace, dep.Name, "Deployment", dep.Annotations)...)
	}

	return findings, nil
}

// processAnnotated handles a single annotated object and returns its findings.
func (d *AnnotationDiscoverer) processAnnotated(ctx context.Context, namespace, name, kind string, annotations map[string]string) []store.CertFinding {
	var findings []store.CertFinding

	severity := parseSeverity(annotations[annoSeverity])
	sni := annotations[annoSNI]

	// If tls-secret is specified, read from the secret instead of probing
	if secretName := annotations[annoTLSSecret]; secretName != "" {
		f := d.findingFromSecret(ctx, namespace, name, secretName, severity)
		findings = append(findings, f)
	} else if kind == "Service" {
		// Probe the service endpoints
		ports := parsePorts(annotations[annoPorts])
		for _, port := range ports {
			target := fmt.Sprintf("%s.%s.svc:%s", name, namespace, port)
			f := d.probeTarget(target, sni, namespace, name, severity)
			findings = append(findings, f)
		}
	}

	// External targets (available for both Services and Deployments)
	if targets := annotations[annoExternalTargets]; targets != "" {
		for _, target := range parseExternalTargets(targets) {
			f := d.probeTarget(target, sni, namespace, name, severity)
			f.Notes = "external target"
			findings = append(findings, f)
		}
	}

	return findings
}

// probeTarget probes a TLS endpoint and returns a finding.
func (d *AnnotationDiscoverer) probeTarget(target, sni, namespace, name string, severity store.Severity) store.CertFinding {
	finding := store.CertFinding{
		Source:    store.SourceAnnotation,
		Severity:  severity,
		Namespace: namespace,
		Name:      name,
		Target:    target,
		SNI:       sni,
	}

	result := d.probeFn(probe.FormatTarget(target, sni))
	finding.ProbeOK = result.ProbeOK
	finding.ProbeErr = result.ProbeErr

	if result.ProbeOK && result.Cert != nil {
		finding.NotAfter = result.Cert.NotAfter
		finding.DNSNames = result.Cert.DNSNames
		finding.Issuer = result.Cert.Issuer.String()
		finding.Subject = result.Cert.Subject.String()
		finding.Serial = result.Cert.SerialNumber.String()
	}

	return finding
}

// findingFromSecret reads a TLS secret and returns a finding.
func (d *AnnotationDiscoverer) findingFromSecret(ctx context.Context, namespace, objName, secretName string, severity store.Severity) store.CertFinding {
	finding := store.CertFinding{
		Source:    store.SourceAnnotation,
		Severity:  severity,
		Namespace: namespace,
		Name:      fmt.Sprintf("%s/%s", objName, secretName),
	}

	secret, err := d.client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		finding.ProbeOK = false
		finding.ProbeErr = fmt.Sprintf("getting secret %s/%s: %s", namespace, secretName, err)
		return finding
	}

	if secret.Type != corev1.SecretTypeTLS {
		finding.ProbeOK = false
		finding.ProbeErr = fmt.Sprintf("secret %s/%s has type %s, expected %s", namespace, secretName, secret.Type, corev1.SecretTypeTLS)
		return finding
	}

	pemData, ok := secret.Data["tls.crt"]
	if !ok {
		finding.ProbeOK = false
		finding.ProbeErr = errMissingTLSCrt
		return finding
	}

	cert, err := parsePEMCert(pemData)
	if err != nil {
		finding.ProbeOK = false
		finding.ProbeErr = err.Error()
		return finding
	}

	finding.ProbeOK = true
	finding.NotAfter = cert.NotAfter
	finding.DNSNames = cert.DNSNames
	finding.Issuer = cert.Issuer.String()
	finding.Subject = cert.Subject.String()
	finding.Serial = cert.SerialNumber.String()

	return finding
}

// parsePorts splits a comma-separated port list, defaulting to "443".
func parsePorts(s string) []string {
	if s == "" {
		return []string{defaultAnnotPort}
	}
	var ports []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return []string{defaultAnnotPort}
	}
	return ports
}

// parseSeverity converts a string severity to a Severity constant, defaulting to info.
func parseSeverity(s string) store.Severity {
	switch store.Severity(s) {
	case store.SeverityCritical:
		return store.SeverityCritical
	case store.SeverityWarn:
		return store.SeverityWarn
	default:
		return store.SeverityInfo
	}
}

// parseExternalTargets splits a multiline target list, trimming whitespace and skipping blanks.
func parseExternalTargets(s string) []string {
	var targets []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			targets = append(targets, line)
		}
	}
	return targets
}
