package discovery

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	"github.com/ppiankov/trustwatch/internal/probe"
	"github.com/ppiankov/trustwatch/internal/store"
)

const defaultAPIServicePort = 443

// APIServiceDiscoverer finds TLS certificates on Kubernetes API aggregation layer endpoints.
type APIServiceDiscoverer struct {
	client  aggregatorclient.Interface
	probeFn func(string) probe.Result
}

// NewAPIServiceDiscoverer creates a discoverer that checks APIService objects
// for expiring TLS certificates on their backing services.
func NewAPIServiceDiscoverer(client aggregatorclient.Interface, opts ...func(*APIServiceDiscoverer)) *APIServiceDiscoverer {
	d := &APIServiceDiscoverer{
		client:  client,
		probeFn: probe.Probe,
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// WithAPIServiceProbeFn sets a custom probe function for APIService discovery.
func WithAPIServiceProbeFn(fn func(string) probe.Result) func(*APIServiceDiscoverer) {
	return func(d *APIServiceDiscoverer) {
		d.probeFn = fn
	}
}

// Name returns the discoverer label.
func (d *APIServiceDiscoverer) Name() string {
	return "apiservices"
}

// Discover lists all APIService objects and probes those backed by an external service.
func (d *APIServiceDiscoverer) Discover() ([]store.CertFinding, error) {
	ctx := context.Background()

	apiServices, err := d.client.ApiregistrationV1().APIServices().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing apiservices: %w", err)
	}

	var findings []store.CertFinding

	for i := range apiServices.Items {
		spec := &apiServices.Items[i].Spec
		svc := spec.Service
		if svc == nil {
			continue
		}

		// When the API server skips TLS verification, an expired cert won't
		// break anything — report for inventory but don't probe or escalate.
		if spec.InsecureSkipTLSVerify {
			port := int32(defaultAPIServicePort)
			if svc.Port != nil {
				port = *svc.Port
			}
			findings = append(findings, store.CertFinding{
				Source:    store.SourceAPIService,
				Severity:  store.SeverityInfo,
				Namespace: svc.Namespace,
				Name:      apiServices.Items[i].Name,
				Target:    fmt.Sprintf("%s.%s.svc:%d", svc.Name, svc.Namespace, port),
				Notes:     "insecureSkipTLSVerify=true",
			})
			continue
		}

		port := int32(defaultAPIServicePort)
		if svc.Port != nil {
			port = *svc.Port
		}

		target := fmt.Sprintf("%s.%s.svc:%d", svc.Name, svc.Namespace, port)
		result := d.probeFn(probe.FormatTarget(target, ""))

		finding := store.CertFinding{
			Source:    store.SourceAPIService,
			Severity:  store.SeverityCritical,
			Namespace: svc.Namespace,
			Name:      apiServices.Items[i].Name,
			Target:    target,
			ProbeOK:   result.ProbeOK,
			ProbeErr:  result.ProbeErr,
		}

		if result.ProbeOK && result.Cert != nil {
			finding.NotAfter = result.Cert.NotAfter
			finding.DNSNames = result.Cert.DNSNames
			finding.Issuer = result.Cert.Issuer.String()
			finding.Subject = result.Cert.Subject.String()
			finding.Serial = result.Cert.SerialNumber.String()
			applyProbeChainValidation(&finding, result.Chain, extractHostFromTarget(target))
		}

		findings = append(findings, finding)
	}

	return findings, nil
}
