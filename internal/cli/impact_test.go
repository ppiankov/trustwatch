package cli

import "testing"

func TestImpactCommand_Registered(t *testing.T) {
	found := false
	for _, c := range rootCmd.Commands() {
		if c.Use == "impact" {
			found = true
			break
		}
	}
	if !found {
		t.Error("impact command not registered on root")
	}
}

func TestImpactCommand_Flags(t *testing.T) {
	flags := []string{
		"issuer", "serial", "subject",
		"config", "kubeconfig", "context", "namespace",
		"warn-before", "crit-before",
		"tunnel", "tunnel-ns", "tunnel-image",
		"check-revocation", "ct-domains", "ct-allowed-issuers",
		"spiffe-socket", "output",
	}
	for _, name := range flags {
		if impactCmd.Flags().Lookup(name) == nil {
			t.Errorf("expected flag --%s on impact command", name)
		}
	}
}
