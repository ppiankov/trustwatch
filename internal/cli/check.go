package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"github.com/ppiankov/trustwatch/internal/config"
	"github.com/ppiankov/trustwatch/internal/discovery"
	"github.com/ppiankov/trustwatch/internal/monitor"
	"github.com/ppiankov/trustwatch/internal/policy"
	"github.com/ppiankov/trustwatch/internal/probe"
	"github.com/ppiankov/trustwatch/internal/revocation"
	"github.com/ppiankov/trustwatch/internal/store"
	"github.com/ppiankov/trustwatch/internal/telemetry"
	"github.com/ppiankov/trustwatch/internal/tunnel"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "CI/CD gate — scan and exit non-zero on policy violations",
	Long: `Run discovery, probe, and policy evaluation, then exit with a code
based on findings. Designed for CI/CD pipelines — no TUI, just
scan → evaluate → exit code.

Exit codes:
  0  No problems found (or below --max-severity threshold)
  1  Warnings exist at or above --max-severity threshold
  2  Critical problems found
  3  Discovery or probe errors`,
	Example: `  # Basic check — fail on critical findings
  trustwatch check

  # Fail on warnings too
  trustwatch check --max-severity warn

  # Fail if any cert expires within 24h
  trustwatch check --deploy-window 24h

  # Use a policy file
  trustwatch check --policy policy.yaml

  # JSON output for pipeline parsing
  trustwatch check --output json

  # Quiet mode — exit code only
  trustwatch check --quiet

  # GitHub Actions example
  # - name: Trust surface check
  #   run: trustwatch check --policy policy.yaml --max-severity warn -o json`,
	RunE: runCheck,
}

func init() {
	rootCmd.AddCommand(checkCmd)
	checkCmd.Flags().String("config", "", "Path to config file")
	checkCmd.Flags().String("kubeconfig", "", "Path to kubeconfig")
	checkCmd.Flags().String("context", "", "Kubernetes context to use")
	checkCmd.Flags().StringSlice("namespace", nil, "Namespaces to scan (empty = all)")
	checkCmd.Flags().Duration("warn-before", 0, "Warn threshold (default from config)")
	checkCmd.Flags().Duration("crit-before", 0, "Critical threshold (default from config)")
	checkCmd.Flags().Bool("tunnel", false, "Deploy a SOCKS5 relay pod to route probes through in-cluster DNS")
	checkCmd.Flags().String("tunnel-ns", "default", "Namespace for the tunnel relay pod")
	checkCmd.Flags().String("tunnel-image", tunnel.DefaultImage, "SOCKS5 proxy image for --tunnel")
	checkCmd.Flags().StringSlice("tunnel-command", nil, "Override container command")
	checkCmd.Flags().String("tunnel-pull-secret", "", "imagePullSecret name for the tunnel relay pod")
	checkCmd.Flags().Bool("check-revocation", false, "Check certificate revocation via OCSP/CRL")
	checkCmd.Flags().String("spiffe-socket", "", "Path to SPIFFE workload API socket")
	checkCmd.Flags().StringP("output", "o", "", "Output format: json, table (default: table)")
	checkCmd.Flags().BoolP("quiet", "q", false, "Suppress output, exit code only")

	// CI-specific flags
	checkCmd.Flags().String("policy", "", "Path to YAML policy file")
	checkCmd.Flags().String("max-severity", "critical", "Fail threshold: info, warn, or critical")
	checkCmd.Flags().Duration("deploy-window", 0, "Fail if any cert expires within this duration")
}

func runCheck(cmd *cobra.Command, _ []string) error {
	cfgPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return err
	}
	cfg := config.Defaults()
	if cfgPath != "" {
		cfg, err = config.Load(cfgPath)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
	}

	// Override thresholds from flags
	warnDur, _ := cmd.Flags().GetDuration("warn-before") //nolint:errcheck // flag registered above
	if warnDur > 0 {
		cfg.WarnBefore = warnDur
	}
	critDur, _ := cmd.Flags().GetDuration("crit-before") //nolint:errcheck // flag registered above
	if critDur > 0 {
		cfg.CritBefore = critDur
	}
	ns, _ := cmd.Flags().GetStringSlice("namespace") //nolint:errcheck // flag registered above
	if len(ns) > 0 {
		cfg.Namespaces = ns
	}

	// Parse CI-specific flags
	maxSevStr, _ := cmd.Flags().GetString("max-severity") //nolint:errcheck // flag registered above
	maxSev, err := parseSeverity(maxSevStr)
	if err != nil {
		return err
	}
	deployWindow, _ := cmd.Flags().GetDuration("deploy-window") //nolint:errcheck // flag registered above
	policyPath, _ := cmd.Flags().GetString("policy")            //nolint:errcheck // flag registered above

	// Build Kubernetes client
	kubeconfig, err := cmd.Flags().GetString("kubeconfig")
	if err != nil {
		return err
	}
	kubeCtx, err := cmd.Flags().GetString("context")
	if err != nil {
		return err
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		loadingRules.ExplicitPath = kubeconfig
	}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{CurrentContext: kubeCtx},
	)

	restCfg, err := clientConfig.ClientConfig()
	if err != nil {
		return fmt.Errorf("building kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("creating kubernetes client: %w", err)
	}

	aggClient, err := aggregatorclient.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("creating aggregator client: %w", err)
	}

	gwClient, err := gatewayclient.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("creating gateway-api client: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("creating dynamic client: %w", err)
	}

	// Load policies: cluster CRDs + file-based
	loadedPolicies, loadErr := policy.LoadPolicies(context.Background(), clientset.Discovery(), dynClient)
	if loadErr != nil {
		slog.Warn("loading trust policies", "err", loadErr)
	}
	if len(loadedPolicies) > 0 {
		slog.Info("loaded cluster policies", "count", len(loadedPolicies))
		for i := range loadedPolicies {
			for j := range loadedPolicies[i].Spec.Targets {
				if loadedPolicies[i].Spec.Targets[j].Kind == "External" {
					for _, u := range loadedPolicies[i].Spec.Targets[j].URLs {
						cfg.External = append(cfg.External, config.ExternalTarget{URL: u})
					}
				}
			}
		}
	}

	if policyPath != "" {
		filePolicies, fileErr := policy.LoadFromFile(policyPath)
		if fileErr != nil {
			return fmt.Errorf("loading policy file: %w", fileErr)
		}
		loadedPolicies = append(loadedPolicies, filePolicies...)
		slog.Info("loaded file policy", "path", policyPath, "rules", len(filePolicies[0].Spec.Rules))
	}

	// Optionally start a SOCKS5 tunnel
	useTunnel, _ := cmd.Flags().GetBool("tunnel")                  //nolint:errcheck // flag registered above
	tunnelNS, _ := cmd.Flags().GetString("tunnel-ns")              //nolint:errcheck // flag registered above
	tunnelImg, _ := cmd.Flags().GetString("tunnel-image")          //nolint:errcheck // flag registered above
	tunnelCmd, _ := cmd.Flags().GetStringSlice("tunnel-command")   //nolint:errcheck // flag registered above
	tunnelSecret, _ := cmd.Flags().GetString("tunnel-pull-secret") //nolint:errcheck // flag registered above

	var relay *tunnel.Relay
	var tunnelProbeFn func(string) probe.Result
	if useTunnel {
		relay = tunnel.NewRelay(clientset, restCfg, tunnelNS, tunnelImg, tunnelCmd, tunnelSecret)
		slog.Info("deploying tunnel relay pod", "namespace", tunnelNS)
		if startErr := relay.Start(context.Background()); startErr != nil {
			return fmt.Errorf("starting tunnel relay: %w", startErr)
		}
		slog.Info("tunnel ready", "port", relay.LocalPort(), "pod", relay.PodName())
		tunnelProbeFn = relay.ProbeFn()
	}
	closeRelay := func() {
		if relay != nil {
			if closeErr := relay.Close(); closeErr != nil {
				slog.Warn("cleaning up relay pod", "err", closeErr)
			}
		}
	}
	defer closeRelay()

	// Derive API server host
	apiServerTarget := apiServerFromHost(restCfg.Host)

	// Resolve namespaces
	nsCtx := context.Background()
	allNS, err := discovery.ResolveNamespaces(nsCtx, clientset, cfg.Namespaces)
	if err != nil {
		return fmt.Errorf("resolving namespaces: %w", err)
	}
	secretNS := discovery.FilterAccessible(nsCtx, clientset, allNS, "", "secrets")
	ingressNS := discovery.FilterAccessible(nsCtx, clientset, allNS, "networking.k8s.io", "ingresses")
	svcNS := discovery.FilterAccessible(nsCtx, clientset, allNS, "", "services")
	gwNS := discovery.FilterAccessible(nsCtx, clientset, allNS, "gateway.networking.k8s.io", "gateways")
	certNS := discovery.FilterAccessible(nsCtx, clientset, allNS, "cert-manager.io", "certificates")

	// Build discoverers
	var webhookOpts []func(*discovery.WebhookDiscoverer)
	var apiSvcOpts []func(*discovery.APIServiceDiscoverer)
	var annotOpts []func(*discovery.AnnotationDiscoverer)
	var extOpts []func(*discovery.ExternalDiscoverer)
	if tunnelProbeFn != nil {
		webhookOpts = append(webhookOpts, discovery.WithWebhookProbeFn(tunnelProbeFn))
		apiSvcOpts = append(apiSvcOpts, discovery.WithAPIServiceProbeFn(tunnelProbeFn))
		annotOpts = append(annotOpts, discovery.WithAnnotationProbeFn(tunnelProbeFn))
		extOpts = append(extOpts, discovery.WithExternalProbeFn(tunnelProbeFn))
	}
	annotOpts = append(annotOpts, discovery.WithAnnotationNamespaces(svcNS))

	discoverers := []discovery.Discoverer{ //nolint:dupl // intentional parallel to now.go; commands may diverge
		discovery.NewWebhookDiscoverer(clientset, webhookOpts...),
		discovery.NewAPIServiceDiscoverer(aggClient, apiSvcOpts...),
		discovery.NewAPIServerDiscoverer(apiServerTarget, discovery.WithProbeFn(restProbe(restCfg))),
		discovery.NewSecretDiscoverer(clientset, discovery.WithSecretNamespaces(secretNS)),
		discovery.NewIngressDiscoverer(clientset, discovery.WithIngressNamespaces(ingressNS)),
		discovery.NewLinkerdDiscoverer(clientset),
		discovery.NewIstioDiscoverer(clientset),
		discovery.NewAnnotationDiscoverer(clientset, annotOpts...),
		discovery.NewGatewayDiscoverer(gwClient, clientset, discovery.WithGatewayNamespaces(gwNS)),
		discovery.NewCertManagerDiscoverer(dynClient, clientset, discovery.WithCertManagerNamespaces(certNS)),
		discovery.NewCertManagerRenewalDiscoverer(dynClient, clientset, discovery.WithRenewalNamespaces(certNS)),
	}
	if len(cfg.External) > 0 {
		discoverers = append(discoverers, discovery.NewExternalDiscoverer(cfg.External, extOpts...))
	}

	spiffeSocket, _ := cmd.Flags().GetString("spiffe-socket") //nolint:errcheck // flag registered above
	if spiffeSocket == "" {
		spiffeSocket = cfg.SPIFFESocket
	}
	if spiffeSocket != "" {
		discoverers = append(discoverers, discovery.NewSPIFFEDiscoverer(spiffeSocket))
	}
	discoverers = append(discoverers, discovery.CloudDiscoverers()...)

	// Initialize tracing
	otelEndpoint, _ := cmd.Flags().GetString("otel-endpoint") //nolint:errcheck // flag registered above
	tracer, tracerShutdown, tracerErr := telemetry.InitTracer(context.Background(), otelEndpoint, "trustwatch", version)
	if tracerErr != nil {
		slog.Warn("initializing tracer", "err", tracerErr)
	} else {
		defer tracerShutdown(context.Background()) //nolint:errcheck // best-effort flush
	}

	// Run discovery
	slog.Info("scanning discovery sources", "count", len(discoverers))
	var orchOpts []discovery.OrchestratorOption
	if len(loadedPolicies) > 0 {
		orchOpts = append(orchOpts, discovery.WithPolicies(loadedPolicies))
	}
	if tracer != nil {
		orchOpts = append(orchOpts, discovery.WithTracer(tracer))
	}
	checkRevocation, _ := cmd.Flags().GetBool("check-revocation") //nolint:errcheck // flag registered above
	if checkRevocation {
		orchOpts = append(orchOpts, discovery.WithCheckRevocation(revocation.NewCRLCache()))
	}
	orch := discovery.NewOrchestrator(discoverers, cfg.WarnBefore, cfg.CritBefore, orchOpts...)
	snap := orch.Run()
	slog.Info("scan complete", "findings", len(snap.Findings))

	// Apply deploy-window reclassification
	if deployWindow > 0 {
		applyDeployWindow(snap.Findings, deployWindow, snap.At)
	}

	// Calculate exit code with max-severity threshold
	exitCode := checkExitCode(snap, maxSev)

	// Output
	outputFlag, _ := cmd.Flags().GetString("output") //nolint:errcheck // flag registered above
	quiet, _ := cmd.Flags().GetBool("quiet")         //nolint:errcheck // flag registered above

	if outputFlag != "" && outputFlag != "json" && outputFlag != "table" {
		return fmt.Errorf("invalid --output value %q: must be json or table", outputFlag)
	}

	if !quiet {
		switch outputFlag {
		case "json":
			if err := monitor.WriteJSON(os.Stdout, snap, exitCode); err != nil {
				return fmt.Errorf("writing JSON output: %w", err)
			}
		default:
			fmt.Print(monitor.PlainText(snap))
		}
	}

	if exitCode != 0 {
		closeRelay()      // explicit cleanup because os.Exit bypasses defers
		os.Exit(exitCode) //nolint:gocritic // exitAfterDefer — defer is for the normal-return path; this is the nonzero-exit path
	}
	return nil
}

// applyDeployWindow escalates findings expiring within the window to critical.
func applyDeployWindow(findings []store.CertFinding, window time.Duration, now time.Time) {
	cutoff := now.Add(window)
	for i := range findings {
		f := &findings[i]
		if f.ProbeOK && !f.NotAfter.IsZero() && f.NotAfter.Before(cutoff) {
			f.Severity = store.SeverityCritical
		}
	}
}

// checkExitCode returns an exit code based on findings and a severity threshold.
// Findings at or above maxSev cause a non-zero exit.
func checkExitCode(snap store.Snapshot, maxSev store.Severity) int {
	if len(snap.Errors) > 0 {
		return 3
	}
	for i := range snap.Findings {
		if !snap.Findings[i].ProbeOK {
			return 3
		}
	}

	code := 0
	for i := range snap.Findings {
		sev := snap.Findings[i].Severity
		if !meetsThreshold(sev, maxSev) {
			continue
		}
		if sev == store.SeverityCritical {
			return 2
		}
		if code < 1 {
			code = 1
		}
	}
	return code
}

// meetsThreshold returns true if the finding severity is at or above the threshold.
func meetsThreshold(sev, threshold store.Severity) bool {
	return sevRank(sev) >= sevRank(threshold)
}

func sevRank(s store.Severity) int {
	switch s {
	case store.SeverityCritical:
		return 3
	case store.SeverityWarn:
		return 2
	case store.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func parseSeverity(s string) (store.Severity, error) {
	switch s {
	case "info":
		return store.SeverityInfo, nil
	case "warn":
		return store.SeverityWarn, nil
	case "critical":
		return store.SeverityCritical, nil
	default:
		return "", fmt.Errorf("invalid --max-severity %q: must be info, warn, or critical", s)
	}
}
