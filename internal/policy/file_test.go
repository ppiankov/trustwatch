package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFile_ValidPolicy(t *testing.T) {
	content := `
name: ci-policy
spec:
  rules:
    - name: no-sha1
      type: noSHA1
      severity: critical
    - name: min-key
      type: minKeySize
      params:
        minBits: "2048"
  targets:
    - kind: External
      urls:
        - https://api.example.com:443
`
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	policies, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile() error: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}

	p := policies[0]
	if p.Name != "ci-policy" {
		t.Errorf("expected name %q, got %q", "ci-policy", p.Name)
	}
	if len(p.Spec.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(p.Spec.Rules))
	}
	if p.Spec.Rules[0].Type != "noSHA1" {
		t.Errorf("expected rule type %q, got %q", "noSHA1", p.Spec.Rules[0].Type)
	}
	if p.Spec.Rules[1].Params["minBits"] != "2048" {
		t.Errorf("expected minBits param %q, got %q", "2048", p.Spec.Rules[1].Params["minBits"])
	}
	if len(p.Spec.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(p.Spec.Targets))
	}
	if p.Spec.Targets[0].Kind != "External" {
		t.Errorf("expected target kind %q, got %q", "External", p.Spec.Targets[0].Kind)
	}
}

func TestLoadFromFile_NoName(t *testing.T) {
	content := `
spec:
  rules:
    - name: no-self-signed
      type: noSelfSigned
`
	path := filepath.Join(t.TempDir(), "unnamed.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	policies, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile() error: %v", err)
	}
	if policies[0].Name != path {
		t.Errorf("expected name to be file path %q, got %q", path, policies[0].Name)
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/policy.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadFromFile_InvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("{{invalid yaml"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}
