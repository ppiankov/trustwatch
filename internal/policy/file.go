package policy

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

// policyFile represents the YAML structure for a policy file.
// Wraps TrustPolicySpec with a name field.
type policyFile struct {
	Name string          `json:"name"`
	Spec TrustPolicySpec `json:"spec"`
}

// LoadFromFile reads a YAML policy file and returns TrustPolicy objects.
func LoadFromFile(path string) ([]TrustPolicy, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-provided policy file path
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	var pf policyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parsing policy file: %w", err)
	}

	name := pf.Name
	if name == "" {
		name = path
	}

	return []TrustPolicy{{
		Name: name,
		Spec: pf.Spec,
	}}, nil
}
