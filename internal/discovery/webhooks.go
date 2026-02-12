package discovery

import (
	"context"
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ppiankov/trustwatch/internal/probe"
	"github.com/ppiankov/trustwatch/internal/store"
)

const defaultWebhookPort = 443

// WebhookDiscoverer finds TLS certificates on admission webhook endpoints.
type WebhookDiscoverer struct {
	client  kubernetes.Interface
	probeFn func(string) probe.Result
}

// NewWebhookDiscoverer creates a discoverer that checks ValidatingWebhookConfigurations
// and MutatingWebhookConfigurations for expiring TLS certificates.
func NewWebhookDiscoverer(client kubernetes.Interface) *WebhookDiscoverer {
	return &WebhookDiscoverer{
		client:  client,
		probeFn: probe.Probe,
	}
}

// Name returns the discoverer label.
func (d *WebhookDiscoverer) Name() string {
	return "webhooks"
}

// Discover lists all admission webhooks and probes their service endpoints.
func (d *WebhookDiscoverer) Discover() ([]store.CertFinding, error) {
	ctx := context.Background()

	vwcs, err := d.client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing validating webhook configurations: %w", err)
	}

	mwcs, err := d.client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing mutating webhook configurations: %w", err)
	}

	var findings []store.CertFinding

	for i := range vwcs.Items {
		for j := range vwcs.Items[i].Webhooks {
			wh := &vwcs.Items[i].Webhooks[j]
			if f, ok := d.processWebhook(vwcs.Items[i].Name, wh.Name, wh.FailurePolicy, &wh.ClientConfig); ok {
				findings = append(findings, f)
			}
		}
	}

	for i := range mwcs.Items {
		for j := range mwcs.Items[i].Webhooks {
			wh := &mwcs.Items[i].Webhooks[j]
			if f, ok := d.processWebhook(mwcs.Items[i].Name, wh.Name, wh.FailurePolicy, &wh.ClientConfig); ok {
				findings = append(findings, f)
			}
		}
	}

	return findings, nil
}

func (d *WebhookDiscoverer) processWebhook(configName, webhookName string, failurePolicy *admissionregistrationv1.FailurePolicyType, clientConfig *admissionregistrationv1.WebhookClientConfig) (store.CertFinding, bool) {
	if clientConfig.Service == nil {
		return store.CertFinding{}, false
	}

	svc := clientConfig.Service
	port := int32(defaultWebhookPort)
	if svc.Port != nil {
		port = *svc.Port
	}

	target := fmt.Sprintf("%s.%s.svc:%d", svc.Name, svc.Namespace, port)
	result := d.probeFn(probe.FormatTarget(target, ""))

	severity := store.SeverityCritical
	notes := "failurePolicy=Fail"
	if failurePolicy != nil && *failurePolicy == admissionregistrationv1.Ignore {
		severity = store.SeverityInfo
		notes = ""
	}

	finding := store.CertFinding{
		Source:    store.SourceWebhook,
		Severity:  severity,
		Namespace: svc.Namespace,
		Name:      fmt.Sprintf("%s/%s", configName, webhookName),
		Target:    target,
		ProbeOK:   result.ProbeOK,
		ProbeErr:  result.ProbeErr,
		Notes:     notes,
	}

	if result.ProbeOK && result.Cert != nil {
		finding.NotAfter = result.Cert.NotAfter
		finding.DNSNames = result.Cert.DNSNames
		finding.Issuer = result.Cert.Issuer.String()
		finding.Subject = result.Cert.Subject.String()
		finding.Serial = result.Cert.SerialNumber.String()
	}

	return finding, true
}
