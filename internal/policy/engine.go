package policy

import (
	"github.com/ppiankov/trustwatch/internal/store"
)

// Engine evaluates policy rules against findings and produces violations.
type Engine struct {
	policies []TrustPolicy
}

// NewEngine creates an engine with the given policies.
func NewEngine(policies []TrustPolicy) *Engine {
	return &Engine{policies: policies}
}

// Evaluate runs all policy rules against the given findings and returns
// any POLICY_VIOLATION findings.
func (e *Engine) Evaluate(findings []store.CertFinding) []store.CertFinding {
	var violations []store.CertFinding
	for i := range e.policies {
		p := &e.policies[i]
		for j := range p.Spec.Rules {
			r := &p.Spec.Rules[j]
			for k := range findings {
				f := &findings[k]
				if !f.ProbeOK {
					continue
				}
				violated, reason := evaluateRule(r, f)
				if violated {
					sev := store.SeverityWarn
					if r.Severity != "" {
						sev = store.Severity(r.Severity)
					}
					violations = append(violations, store.CertFinding{
						NotAfter:    f.NotAfter,
						Name:        f.Name,
						Namespace:   f.Namespace,
						Source:      store.SourcePolicy,
						Severity:    sev,
						FindingType: "POLICY_VIOLATION",
						PolicyName:  p.Name,
						Notes:       r.Name + ": " + reason,
						ProbeOK:     true,
					})
				}
			}
		}
	}
	return violations
}

func evaluateRule(r *RuleSpec, f *store.CertFinding) (violated bool, reason string) {
	switch r.Type {
	case "minKeySize":
		return evalMinKeySize(f, r.Params)
	case "noSHA1":
		return evalNoSHA1(f)
	case "requiredIssuer":
		return evalRequiredIssuer(f, r.Params)
	case "noSelfSigned":
		return evalNoSelfSigned(f)
	default:
		return false, ""
	}
}
