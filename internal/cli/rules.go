package cli

import (
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultWarnSeconds = 2592000 // 720h = 30 days
	defaultCritSeconds = 1209600 // 336h = 14 days
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Generate PrometheusRule YAML for trustwatch alerts",
	Long: `Output a static PrometheusRule YAML manifest with alert rules for
certificate expiry, probe failures, and discovery errors.

No cluster connection required. The output is valid
monitoring.coreos.com/v1 PrometheusRule YAML suitable for kubectl apply.`,
	Example: `  # Generate with default thresholds (30d warn, 14d crit)
  trustwatch rules

  # Custom thresholds
  trustwatch rules --warn-before 360h --crit-before 168h

  # Custom metadata
  trustwatch rules --name trustwatch-alerts --namespace monitoring

  # Add extra labels for PrometheusRule selection
  trustwatch rules --labels 'prometheus=kube,role=alert-rules'

  # Apply directly
  trustwatch rules | kubectl apply -f -`,
	RunE: runRules,
}

func init() {
	rootCmd.AddCommand(rulesCmd)
	rulesCmd.Flags().Duration("warn-before", 0, "Warn threshold (default: 720h / 30 days)")
	rulesCmd.Flags().Duration("crit-before", 0, "Critical threshold (default: 336h / 14 days)")
	rulesCmd.Flags().String("name", "trustwatch-alerts", "PrometheusRule metadata.name")
	rulesCmd.Flags().String("namespace", "", "PrometheusRule metadata.namespace")
	rulesCmd.Flags().String("labels", "", "Extra labels (comma-separated key=value pairs)")
}

type rulesData struct {
	Labels      map[string]string
	Name        string
	Namespace   string
	WarnSeconds int64
	CritSeconds int64
}

func runRules(cmd *cobra.Command, _ []string) error {
	name, _ := cmd.Flags().GetString("name")             //nolint:errcheck // flag registered above
	ns, _ := cmd.Flags().GetString("namespace")          //nolint:errcheck // flag registered above
	labelsStr, _ := cmd.Flags().GetString("labels")      //nolint:errcheck // flag registered above
	warnDur, _ := cmd.Flags().GetDuration("warn-before") //nolint:errcheck // flag registered above
	critDur, _ := cmd.Flags().GetDuration("crit-before") //nolint:errcheck // flag registered above

	warnSec := int64(defaultWarnSeconds)
	if warnDur > 0 {
		warnSec = int64(warnDur / time.Second)
	}
	critSec := int64(defaultCritSeconds)
	if critDur > 0 {
		critSec = int64(critDur / time.Second)
	}

	labels := make(map[string]string)
	if labelsStr != "" {
		for _, pair := range strings.Split(labelsStr, ",") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				labels[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}

	data := rulesData{
		Name:        name,
		Namespace:   ns,
		Labels:      labels,
		WarnSeconds: warnSec,
		CritSeconds: critSec,
	}

	tmpl, err := template.New("prometheusrule").Parse(prometheusRuleTemplate)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	return tmpl.Execute(cmd.OutOrStdout(), data)
}

const prometheusRuleTemplate = `apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: {{ .Name }}
{{- if .Namespace }}
  namespace: {{ .Namespace }}
{{- end }}
  labels:
    app.kubernetes.io/name: trustwatch
{{- range $k, $v := .Labels }}
    {{ $k }}: {{ $v }}
{{- end }}
spec:
  groups:
    - name: trustwatch.rules
      rules:
        - alert: TrustwatchCertExpiringSoon
          expr: trustwatch_cert_expires_in_seconds < {{ .WarnSeconds }} and trustwatch_cert_expires_in_seconds > {{ .CritSeconds }}
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "Certificate expiring soon: {{"{{"}} $labels.name {{"}}"}} in {{"{{"}} $labels.namespace {{"}}"}}"
            description: "Certificate {{"{{"}} $labels.name {{"}}"}} (source: {{"{{"}} $labels.source {{"}}"}}) in namespace {{"{{"}} $labels.namespace {{"}}"}} expires in less than {{ .WarnSeconds }}s."
        - alert: TrustwatchCertExpiryCritical
          expr: trustwatch_cert_expires_in_seconds < {{ .CritSeconds }} and trustwatch_cert_expires_in_seconds > 0
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "Certificate expiry critical: {{"{{"}} $labels.name {{"}}"}} in {{"{{"}} $labels.namespace {{"}}"}}"
            description: "Certificate {{"{{"}} $labels.name {{"}}"}} (source: {{"{{"}} $labels.source {{"}}"}}) in namespace {{"{{"}} $labels.namespace {{"}}"}} expires in less than {{ .CritSeconds }}s."
        - alert: TrustwatchCertExpired
          expr: trustwatch_cert_expires_in_seconds <= 0
          for: 0m
          labels:
            severity: critical
          annotations:
            summary: "Certificate expired: {{"{{"}} $labels.name {{"}}"}} in {{"{{"}} $labels.namespace {{"}}"}}"
            description: "Certificate {{"{{"}} $labels.name {{"}}"}} (source: {{"{{"}} $labels.source {{"}}"}}) in namespace {{"{{"}} $labels.namespace {{"}}"}} has expired."
        - alert: TrustwatchProbeFailed
          expr: trustwatch_probe_success == 0
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "TLS probe failed: {{"{{"}} $labels.name {{"}}"}} in {{"{{"}} $labels.namespace {{"}}"}}"
            description: "TLS probe for {{"{{"}} $labels.name {{"}}"}} (source: {{"{{"}} $labels.source {{"}}"}}) in namespace {{"{{"}} $labels.namespace {{"}}"}} has been failing for 10 minutes."
        - alert: TrustwatchDiscoveryErrors
          expr: increase(trustwatch_discovery_errors_total[5m]) > 0
          for: 15m
          labels:
            severity: warning
          annotations:
            summary: "Discovery errors from source: {{"{{"}} $labels.source {{"}}"}}"
            description: "trustwatch discoverer {{"{{"}} $labels.source {{"}}"}} has been producing errors for 15 minutes."
`
