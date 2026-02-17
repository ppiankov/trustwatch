package cli

import (
	"bytes"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func executeRules(args ...string) (string, error) {
	buf := new(bytes.Buffer)
	cmd := rootCmd
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(append([]string{"rules"}, args...))
	err := cmd.Execute()
	return buf.String(), err
}

func TestRulesCommand_DefaultOutput(t *testing.T) {
	out, err := executeRules()
	if err != nil {
		t.Fatalf("rules command failed: %v", err)
	}

	// Must be valid YAML
	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid YAML: %v", err)
	}

	// Check apiVersion and kind
	if parsed["apiVersion"] != "monitoring.coreos.com/v1" {
		t.Errorf("expected apiVersion monitoring.coreos.com/v1, got %v", parsed["apiVersion"])
	}
	if parsed["kind"] != "PrometheusRule" {
		t.Errorf("expected kind PrometheusRule, got %v", parsed["kind"])
	}

	// Check default name
	meta, ok := parsed["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata is not a map")
	}
	if meta["name"] != "trustwatch-alerts" {
		t.Errorf("expected name trustwatch-alerts, got %v", meta["name"])
	}

	// Check all alert names exist
	expectedAlerts := []string{
		"TrustwatchCertExpiringSoon",
		"TrustwatchCertExpiryCritical",
		"TrustwatchCertExpired",
		"TrustwatchProbeFailed",
		"TrustwatchDiscoveryErrors",
		"TrustwatchScanStale",
	}
	for _, alert := range expectedAlerts {
		if !strings.Contains(out, alert) {
			t.Errorf("expected alert %q in output", alert)
		}
	}

	// Check default threshold values appear
	if !strings.Contains(out, "2592000") {
		t.Error("expected default warn threshold 2592000 in output")
	}
	if !strings.Contains(out, "1209600") {
		t.Error("expected default crit threshold 1209600 in output")
	}
}

func TestRulesCommand_CustomThresholds(t *testing.T) {
	out, err := executeRules("--warn-before", "360h", "--crit-before", "168h")
	if err != nil {
		t.Fatalf("rules command failed: %v", err)
	}

	// 360h = 1296000s, 168h = 604800s
	if !strings.Contains(out, "1296000") {
		t.Error("expected custom warn threshold 1296000 in output")
	}
	if !strings.Contains(out, "604800") {
		t.Error("expected custom crit threshold 604800 in output")
	}

	// Default values should not appear
	if strings.Contains(out, "2592000") {
		t.Error("did not expect default warn threshold 2592000 with custom thresholds")
	}
}

func TestRulesCommand_CustomName(t *testing.T) {
	out, err := executeRules("--name", "my-custom-alerts", "--namespace", "monitoring")
	if err != nil {
		t.Fatalf("rules command failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid YAML: %v", err)
	}

	meta, ok := parsed["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata is not a map")
	}
	if meta["name"] != "my-custom-alerts" {
		t.Errorf("expected name my-custom-alerts, got %v", meta["name"])
	}
	if meta["namespace"] != "monitoring" {
		t.Errorf("expected namespace monitoring, got %v", meta["namespace"])
	}
}

func TestRulesCommand_Labels(t *testing.T) {
	out, err := executeRules("--labels", "prometheus=kube,role=alert-rules")
	if err != nil {
		t.Fatalf("rules command failed: %v", err)
	}

	if !strings.Contains(out, "prometheus: kube") {
		t.Error("expected label 'prometheus: kube' in output")
	}
	if !strings.Contains(out, "role: alert-rules") {
		t.Error("expected label 'role: alert-rules' in output")
	}
}

func TestRulesCommand_Flags(t *testing.T) {
	expectedFlags := []string{"warn-before", "crit-before", "name", "namespace", "labels"}
	for _, name := range expectedFlags {
		if rulesCmd.Flags().Lookup(name) == nil {
			t.Errorf("expected --%s flag on 'rules' command", name)
		}
	}
}
