package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"github.com/ppiankov/trustwatch/internal/config"
	"github.com/ppiankov/trustwatch/internal/ct"
	"github.com/ppiankov/trustwatch/internal/discovery"
	"github.com/ppiankov/trustwatch/internal/policy"
	"github.com/ppiankov/trustwatch/internal/probe"
	"github.com/ppiankov/trustwatch/internal/report"
	"github.com/ppiankov/trustwatch/internal/revocation"
	"github.com/ppiankov/trustwatch/internal/telemetry"
	"github.com/ppiankov/trustwatch/internal/tunnel"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a self-contained HTML compliance report",
	Long: `Run discovery and probing, then generate a standalone HTML report
suitable for compliance audits, email distribution, or archival.

The report includes all findings with certificate details, severity
counts, and remediation guidance. All CSS is inlined — no external
dependencies. The output is print-friendly.`,
	Example: `  # Generate report to stdout
  trustwatch report > report.html

  # Save to a file
  trustwatch report --output-file report.html

  # Scan a specific cluster
  trustwatch report --context prod --output-file prod-report.html

  # Include cluster name in report header
  trustwatch report --cluster-name production --output-file report.html`,
	RunE: runReport,
}

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.Flags().String("config", "", "Path to config file")
	reportCmd.Flags().String("kubeconfig", "", "Path to kubeconfig")
	reportCmd.Flags().String("context", "", "Kubernetes context to use")
	reportCmd.Flags().StringSlice("namespace", nil, "Namespaces to scan (empty = all)")
	reportCmd.Flags().Duration("warn-before", 0, "Warn threshold (default from config)")
	reportCmd.Flags().Duration("crit-before", 0, "Critical threshold (default from config)")
	reportCmd.Flags().Bool("tunnel", false, "Deploy a SOCKS5 relay pod to route probes through in-cluster DNS")
	reportCmd.Flags().String("tunnel-ns", "default", "Namespace for the tunnel relay pod")
	reportCmd.Flags().String("tunnel-image", tunnel.DefaultImage, "SOCKS5 proxy image for --tunnel")
	reportCmd.Flags().StringSlice("tunnel-command", nil, "Override container command")
	reportCmd.Flags().String("tunnel-pull-secret", "", "imagePullSecret name for the tunnel relay pod")
	reportCmd.Flags().Bool("check-revocation", false, "Check certificate revocation via OCSP/CRL")
	reportCmd.Flags().StringSlice("ct-domains", nil, "Domains to monitor in CT logs")
	reportCmd.Flags().StringSlice("ct-allowed-issuers", nil, "Expected CA issuers (others flagged as rogue)")
	reportCmd.Flags().String("spiffe-socket", "", "Path to SPIFFE workload API socket")
	reportCmd.Flags().String("cluster-name", "", "Name for this cluster in the report header")
	reportCmd.Flags().Bool("ignore-managed", false, "Hide cert-manager managed expiry findings")
	reportCmd.Flags().StringP("output-file", "o", "", "Write report to file (default: stdout)")
}

func runReport(cmd *cobra.Command, _ []string) error { //nolint:dupl,cyclop // intentional parallel to now.go/check.go; commands may diverge
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

	// Load TrustPolicy CRs
	loadedPolicies, loadErr := policy.LoadPolicies(context.Background(), clientset.Discovery(), dynClient)
	if loadErr != nil {
		slog.Warn("loading trust policies", "err", loadErr)
	}
	if len(loadedPolicies) > 0 {
		slog.Info("loaded trust policies", "count", len(loadedPolicies))
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

	discoverers := []discovery.Discoverer{ //nolint:dupl // intentional parallel to now.go/check.go; commands may diverge
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
	ctDomains, _ := cmd.Flags().GetStringSlice("ct-domains") //nolint:errcheck // flag registered above
	if len(ctDomains) == 0 {
		ctDomains = cfg.CTDomains
	}
	ctIssuers, _ := cmd.Flags().GetStringSlice("ct-allowed-issuers") //nolint:errcheck // flag registered above
	if len(ctIssuers) == 0 {
		ctIssuers = cfg.CTAllowedIssuers
	}
	if len(ctDomains) > 0 {
		orchOpts = append(orchOpts, discovery.WithCTCheck(ctDomains, ctIssuers, ct.NewClient()))
	}
	orch := discovery.NewOrchestrator(discoverers, cfg.WarnBefore, cfg.CritBefore, orchOpts...)
	snap := orch.Run()
	slog.Info("scan complete", "findings", len(snap.Findings))

	ignoreManaged, _ := cmd.Flags().GetBool("ignore-managed") //nolint:errcheck // flag registered above
	if ignoreManaged {
		snap.Findings = filterManagedExpiry(snap.Findings)
	}

	// Get cluster name for the report header
	clusterName, _ := cmd.Flags().GetString("cluster-name") //nolint:errcheck // flag registered above
	if clusterName == "" {
		clusterName = cfg.ClusterName
	}

	// Generate HTML report
	html, err := report.Generate(snap, clusterName)
	if err != nil {
		return fmt.Errorf("generating report: %w", err)
	}

	// Write output
	outputFile, _ := cmd.Flags().GetString("output-file") //nolint:errcheck // flag registered above
	if outputFile != "" {
		if writeErr := os.WriteFile(outputFile, html, 0o644); writeErr != nil { //nolint:gosec // report is not sensitive
			return fmt.Errorf("writing report: %w", writeErr)
		}
		slog.Info("report written", "path", outputFile)
	} else {
		os.Stdout.Write(html) //nolint:errcheck // best-effort stdout write
	}

	return nil
}
