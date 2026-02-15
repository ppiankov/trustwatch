package policy

import (
	"testing"

	"github.com/ppiankov/trustwatch/internal/store"
)

func TestEngine_MinKeySize(t *testing.T) {
	policies := []TrustPolicy{{
		Name: "test-policy",
		Spec: TrustPolicySpec{
			Rules: []RuleSpec{{
				Name:   "min-key-size",
				Type:   "minKeySize",
				Params: map[string]string{"minBits": "2048"},
			}},
		},
	}}

	engine := NewEngine(policies)
	findings := []store.CertFinding{
		{Name: "weak-cert", KeyAlgorithm: "RSA", KeySize: 1024, ProbeOK: true},
		{Name: "strong-cert", KeyAlgorithm: "RSA", KeySize: 4096, ProbeOK: true},
	}

	violations := engine.Evaluate(findings)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Name != "weak-cert" {
		t.Errorf("name = %q, want %q", violations[0].Name, "weak-cert")
	}
	if violations[0].FindingType != "POLICY_VIOLATION" {
		t.Errorf("findingType = %q, want POLICY_VIOLATION", violations[0].FindingType)
	}
	if violations[0].PolicyName != "test-policy" {
		t.Errorf("policyName = %q, want %q", violations[0].PolicyName, "test-policy")
	}
}

func TestEngine_NoSHA1(t *testing.T) {
	policies := []TrustPolicy{{
		Name: "sha1-policy",
		Spec: TrustPolicySpec{
			Rules: []RuleSpec{{
				Name: "no-sha1",
				Type: "noSHA1",
			}},
		},
	}}

	engine := NewEngine(policies)
	findings := []store.CertFinding{
		{Name: "sha1-cert", SignatureAlgorithm: "SHA1-RSA", ProbeOK: true},
		{Name: "sha256-cert", SignatureAlgorithm: "SHA256-RSA", ProbeOK: true},
	}

	violations := engine.Evaluate(findings)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Name != "sha1-cert" {
		t.Errorf("name = %q, want %q", violations[0].Name, "sha1-cert")
	}
}

func TestEngine_RequiredIssuer(t *testing.T) {
	policies := []TrustPolicy{{
		Name: "issuer-policy",
		Spec: TrustPolicySpec{
			Rules: []RuleSpec{{
				Name:   "required-issuer",
				Type:   "requiredIssuer",
				Params: map[string]string{"issuer": "Let's Encrypt"},
			}},
		},
	}}

	engine := NewEngine(policies)
	findings := []store.CertFinding{
		{Name: "le-cert", Issuer: "CN=Let's Encrypt Authority X3", ProbeOK: true},
		{Name: "other-cert", Issuer: "CN=Internal CA", ProbeOK: true},
	}

	violations := engine.Evaluate(findings)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Name != "other-cert" {
		t.Errorf("name = %q, want %q", violations[0].Name, "other-cert")
	}
}

func TestEngine_NoSelfSigned(t *testing.T) {
	policies := []TrustPolicy{{
		Name: "selfsign-policy",
		Spec: TrustPolicySpec{
			Rules: []RuleSpec{{
				Name: "no-self-signed",
				Type: "noSelfSigned",
			}},
		},
	}}

	engine := NewEngine(policies)
	findings := []store.CertFinding{
		{Name: "self-cert", SelfSigned: true, ProbeOK: true},
		{Name: "ca-cert", SelfSigned: false, ProbeOK: true},
	}

	violations := engine.Evaluate(findings)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Name != "self-cert" {
		t.Errorf("name = %q, want %q", violations[0].Name, "self-cert")
	}
}

func TestEngine_EmptyPolicies(t *testing.T) {
	engine := NewEngine(nil)
	findings := []store.CertFinding{
		{Name: "cert", ProbeOK: true},
	}

	violations := engine.Evaluate(findings)
	if violations != nil {
		t.Errorf("expected nil violations, got %d", len(violations))
	}
}

func TestEngine_SkipsFailedProbes(t *testing.T) {
	policies := []TrustPolicy{{
		Name: "test-policy",
		Spec: TrustPolicySpec{
			Rules: []RuleSpec{{
				Name: "no-self-signed",
				Type: "noSelfSigned",
			}},
		},
	}}

	engine := NewEngine(policies)
	findings := []store.CertFinding{
		{Name: "failed-cert", SelfSigned: true, ProbeOK: false},
	}

	violations := engine.Evaluate(findings)
	if violations != nil {
		t.Errorf("expected nil violations for failed probes, got %d", len(violations))
	}
}

func TestEngine_CustomSeverity(t *testing.T) {
	policies := []TrustPolicy{{
		Name: "crit-policy",
		Spec: TrustPolicySpec{
			Rules: []RuleSpec{{
				Name:     "no-self-signed",
				Type:     "noSelfSigned",
				Severity: "critical",
			}},
		},
	}}

	engine := NewEngine(policies)
	findings := []store.CertFinding{
		{Name: "self-cert", SelfSigned: true, ProbeOK: true},
	}

	violations := engine.Evaluate(findings)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Severity != store.SeverityCritical {
		t.Errorf("severity = %q, want %q", violations[0].Severity, store.SeverityCritical)
	}
}
