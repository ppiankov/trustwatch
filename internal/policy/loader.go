package policy

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
)

var trustPolicyGVR = schema.GroupVersionResource{
	Group:    "trustwatch.dev",
	Version:  "v1alpha1",
	Resource: "trustpolicies",
}

// CRDInstalled checks if the TrustPolicy CRD is registered in the cluster.
func CRDInstalled(disc discovery.DiscoveryInterface) bool {
	_, err := disc.ServerResourcesForGroupVersion("trustwatch.dev/v1alpha1")
	return err == nil
}

// LoadPolicies lists all TrustPolicy CRs from the cluster.
// Returns nil, nil if the CRD is not installed.
func LoadPolicies(ctx context.Context, disc discovery.DiscoveryInterface, dynClient dynamic.Interface) ([]TrustPolicy, error) {
	if !CRDInstalled(disc) {
		return nil, nil
	}

	list, err := dynClient.Resource(trustPolicyGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing trust policies: %w", err)
	}

	policies := make([]TrustPolicy, 0, len(list.Items))
	for i := range list.Items {
		obj := list.Items[i]
		p := TrustPolicy{
			Name:      obj.GetName(),
			Namespace: obj.GetNamespace(),
		}

		spec := extractMap(obj.Object, "spec")
		if spec == nil {
			policies = append(policies, p)
			continue
		}

		p.Spec = parseSpec(spec)
		policies = append(policies, p)
	}

	return policies, nil
}

func parseSpec(spec map[string]interface{}) TrustPolicySpec {
	var s TrustPolicySpec

	if targets, ok := spec["targets"].([]interface{}); ok {
		for _, raw := range targets {
			if m, ok := raw.(map[string]interface{}); ok {
				s.Targets = append(s.Targets, parseTarget(m))
			}
		}
	}

	if thresholds := extractMap(spec, "thresholds"); thresholds != nil {
		s.Thresholds = ThresholdSpec{
			WarnBefore: extractString(thresholds, "warnBefore"),
			CritBefore: extractString(thresholds, "critBefore"),
		}
	}

	if rules, ok := spec["rules"].([]interface{}); ok {
		for _, raw := range rules {
			if m, ok := raw.(map[string]interface{}); ok {
				s.Rules = append(s.Rules, parseRule(m))
			}
		}
	}

	return s
}

func parseTarget(m map[string]interface{}) TargetSpec {
	t := TargetSpec{
		Kind:      extractString(m, "kind"),
		Namespace: extractString(m, "namespace"),
		Name:      extractString(m, "name"),
		SNI:       extractString(m, "sni"),
		Severity:  extractString(m, "severity"),
	}

	if ports, ok := m["ports"].([]interface{}); ok {
		for _, p := range ports {
			switch v := p.(type) {
			case float64:
				t.Ports = append(t.Ports, int(v))
			case int64:
				t.Ports = append(t.Ports, int(v))
			}
		}
	}

	if urls, ok := m["urls"].([]interface{}); ok {
		for _, u := range urls {
			if s, ok := u.(string); ok {
				t.URLs = append(t.URLs, s)
			}
		}
	}

	return t
}

func parseRule(m map[string]interface{}) RuleSpec {
	r := RuleSpec{
		Name:     extractString(m, "name"),
		Type:     extractString(m, "type"),
		Severity: extractString(m, "severity"),
	}

	if params := extractMap(m, "params"); params != nil {
		r.Params = make(map[string]string, len(params))
		for k, v := range params {
			if s, ok := v.(string); ok {
				r.Params[k] = s
			}
		}
	}

	return r
}

func extractMap(obj map[string]interface{}, key string) map[string]interface{} {
	val, ok := obj[key].(map[string]interface{})
	if !ok {
		return nil
	}
	return val
}

func extractString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	val, ok := m[key].(string)
	if !ok {
		return ""
	}
	return val
}
