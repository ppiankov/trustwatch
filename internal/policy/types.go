// Package policy manages TrustPolicy CRDs and policy evaluation.
package policy

// TrustPolicy represents a trust surface monitoring policy.
type TrustPolicy struct {
	Name      string          `json:"name"`
	Namespace string          `json:"namespace"`
	Spec      TrustPolicySpec `json:"spec"`
}

// TrustPolicySpec defines the targets, thresholds, and rules for a policy.
type TrustPolicySpec struct {
	Targets    []TargetSpec  `json:"targets,omitempty"`
	Thresholds ThresholdSpec `json:"thresholds,omitempty"`
	Rules      []RuleSpec    `json:"rules,omitempty"`
}

// TargetSpec defines a single monitoring target.
type TargetSpec struct {
	Kind      string   `json:"kind"` // "Service", "External", "Secret"
	Namespace string   `json:"namespace,omitempty"`
	Name      string   `json:"name,omitempty"`
	SNI       string   `json:"sni,omitempty"`
	Severity  string   `json:"severity,omitempty"`
	Ports     []int    `json:"ports,omitempty"`
	URLs      []string `json:"urls,omitempty"`
}

// ThresholdSpec overrides the global warn/crit thresholds for a policy.
type ThresholdSpec struct {
	WarnBefore string `json:"warnBefore,omitempty"` // duration string, e.g. "720h"
	CritBefore string `json:"critBefore,omitempty"`
}

// RuleSpec defines a policy rule that findings are evaluated against.
type RuleSpec struct {
	Name     string            `json:"name"`
	Type     string            `json:"type"` // "minKeySize", "noSHA1", "requiredIssuer", "noSelfSigned"
	Params   map[string]string `json:"params,omitempty"`
	Severity string            `json:"severity,omitempty"`
}
