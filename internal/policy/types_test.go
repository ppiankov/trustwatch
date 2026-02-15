package policy

import (
	"encoding/json"
	"testing"
)

func TestTrustPolicy_JSONRoundTrip(t *testing.T) {
	p := TrustPolicy{
		Name:      "test-policy",
		Namespace: "default",
		Spec: TrustPolicySpec{
			Targets: []TargetSpec{
				{Kind: "Service", Namespace: "prod", Name: "api", Ports: []int{443}},
				{Kind: "External", URLs: []string{"https://vault.internal:8200"}},
			},
			Thresholds: ThresholdSpec{
				WarnBefore: "720h",
				CritBefore: "336h",
			},
			Rules: []RuleSpec{
				{Name: "min-rsa-2048", Type: "minKeySize", Params: map[string]string{"algorithm": "RSA", "minBits": "2048"}},
			},
		},
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got TrustPolicy
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Name != p.Name {
		t.Errorf("name = %q, want %q", got.Name, p.Name)
	}
	if len(got.Spec.Targets) != 2 {
		t.Errorf("targets = %d, want 2", len(got.Spec.Targets))
	}
	if len(got.Spec.Rules) != 1 {
		t.Errorf("rules = %d, want 1", len(got.Spec.Rules))
	}
	if got.Spec.Thresholds.WarnBefore != "720h" {
		t.Errorf("warnBefore = %q, want %q", got.Spec.Thresholds.WarnBefore, "720h")
	}
}

func TestTrustPolicy_EmptySpec(t *testing.T) {
	p := TrustPolicy{Name: "empty"}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got TrustPolicy
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Name != "empty" {
		t.Errorf("name = %q, want %q", got.Name, "empty")
	}
	if len(got.Spec.Targets) != 0 {
		t.Errorf("targets = %d, want 0", len(got.Spec.Targets))
	}
}
