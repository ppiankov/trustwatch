package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"github.com/ppiankov/trustwatch/internal/config"
	"github.com/ppiankov/trustwatch/internal/ct"
	"github.com/ppiankov/trustwatch/internal/discovery"
	"github.com/ppiankov/trustwatch/internal/impact"
	"github.com/ppiankov/trustwatch/internal/monitor"
	"github.com/ppiankov/trustwatch/internal/policy"
	"github.com/ppiankov/trustwatch/internal/probe"
	"github.com/ppiankov/trustwatch/internal/revocation"
	"github.com/ppiankov/trustwatch/internal/store"
	"github.com/ppiankov/trustwatch/internal/telemetry"
	"github.com/ppiankov/trustwatch/internal/tunnel"
)

var impactCmd = &cobra.Command{
	Use:   "impact",
	Short: "Show blast radius of rotating a certificate or CA",
	Long: `Run discovery, build an issuer dependency graph, then query it to show
which findings would be affected by rotating a given CA, intermediate,
or leaf certificate.

Query modes (exactly one required):
  --issuer   Substring match against issuer DN and full issuer chain
  --serial   Exact match against certificate serial number
  --subject  Substring match against certificate subject DN`,
	Example: `  # What breaks if we rotate the intermediate CA?
  trustwatch impact --issuer "CN=My Intermediate CA"

  # Find a specific certificate by serial
  trustwatch impact --serial "0A:1B:2C:3D"

  # Which findings are issued to a given domain?
  trustwatch impact --subject "example.com"

  # JSON output for automation
  trustwatch impact --issuer "Root CA" --output json`,
	RunE: runImpact,
}

func init() {
	rootCmd.AddCommand(impactCmd)
	impactCmd.Flags().String("config", "", "Path to config file")
	impactCmd.Flags().String("kubeconfig", "", "Path to kubeconfig")
	impactCmd.Flags().String("context", "", "Kubernetes context to use")
	impactCmd.Flags().StringSlice("namespace", nil, "Namespaces to scan (empty = all)")
	impactCmd.Flags().Duration("warn-before", 0, "Warn threshold (default from config)")
	impactCmd.Flags().Duration("crit-before", 0, "Critical threshold (default from config)")
	impactCmd.Flags().Bool("tunnel", false, "Deploy a SOCKS5 relay pod to route probes through in-cluster DNS")
	impactCmd.Flags().String("tunnel-ns", "default", "Namespace for the tunnel relay pod")
	impactCmd.Flags().String("tunnel-image", tunnel.DefaultImage, "SOCKS5 proxy image for --tunnel")
	impactCmd.Flags().StringSlice("tunnel-command", nil, "Override container command")
	impactCmd.Flags().String("tunnel-pull-secret", "", "imagePullSecret name for the tunnel relay pod")
	impactCmd.Flags().Bool("check-revocation", false, "Check certificate revocation via OCSP/CRL")
	impactCmd.Flags().StringSlice("ct-domains", nil, "Domains to monitor in CT logs")
	impactCmd.Flags().StringSlice("ct-allowed-issuers", nil, "Expected CA issuers (others flagged as rogue)")
	impactCmd.Flags().String("spiffe-socket", "", "Path to SPIFFE workload API socket")
	impactCmd.Flags().StringP("output", "o", "", "Output format: json, table (default: table)")
	impactCmd.Flags().Bool("ignore-managed", false, "Hide cert-manager managed expiry findings")

	// Query flags
	impactCmd.Flags().String("issuer", "", "Query by issuer DN (substring match)")
	impactCmd.Flags().String("serial", "", "Query by certificate serial number (exact match)")
	impactCmd.Flags().String("subject", "", "Query by subject DN (substring match)")
}

func runImpact(cmd *cobra.Command, _ []string) error { //nolint:dupl // intentional parallel to now.go/check.go; commands may diverge
	issuerQ, _ := cmd.Flags().GetString("issuer")   //nolint:errcheck // flag registered above
	serialQ, _ := cmd.Flags().GetString("serial")   //nolint:errcheck // flag registered above
	subjectQ, _ := cmd.Flags().GetString("subject") //nolint:errcheck // flag registered above

	// Exactly one query flag required
	qCount := 0
	if issuerQ != "" {
		qCount++
	}
	if serialQ != "" {
		qCount++
	}
	if subjectQ != "" {
		qCount++
	}
	if qCount != 1 {
		return fmt.Errorf("exactly one of --issuer, --serial, or --subject is required")
	}

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

	// Load policies
	loadedPolicies, loadErr := policy.LoadPolicies(context.Background(), clientset.Discovery(), dynClient)
	if loadErr != nil {
		slog.Warn("loading trust policies", "err", loadErr)
	}
	if len(loadedPolicies) > 0 {
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

	// Tunnel setup
	useTunnel, _ := cmd.Flags().GetBool("tunnel")                  //nolint:errcheck // flag registered above
	tunnelNS, _ := cmd.Flags().GetString("tunnel-ns")              //nolint:errcheck // flag registered above
	tunnelImg, _ := cmd.Flags().GetString("tunnel-image")          //nolint:errcheck // flag registered above
	tunnelCmd, _ := cmd.Flags().GetStringSlice("tunnel-command")   //nolint:errcheck // flag registered above
	tunnelSecret, _ := cmd.Flags().GetString("tunnel-pull-secret") //nolint:errcheck // flag registered above

	var relay *tunnel.Relay
	var tunnelProbeFn func(string) probe.Result
	if useTunnel {
		relay = tunnel.NewRelay(clientset, restCfg, tunnelNS, tunnelImg, tunnelCmd, tunnelSecret)
		if startErr := relay.Start(context.Background()); startErr != nil {
			return fmt.Errorf("starting tunnel relay: %w", startErr)
		}
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

	// Build impact graph and query
	graph := impact.Build(snap.Findings)
	var qr impact.QueryResult
	switch {
	case issuerQ != "":
		qr = graph.QueryIssuer(issuerQ)
	case serialQ != "":
		qr = graph.QuerySerial(serialQ)
	case subjectQ != "":
		qr = graph.QuerySubject(subjectQ)
	}

	// Output
	outputFlag, _ := cmd.Flags().GetString("output") //nolint:errcheck // flag registered above
	if outputFlag != "" && outputFlag != "json" && outputFlag != "table" {
		return fmt.Errorf("invalid --output value %q: must be json or table", outputFlag)
	}

	switch outputFlag {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(qr); err != nil {
			return fmt.Errorf("writing JSON output: %w", err)
		}
	default:
		printImpactTable(&qr, &snap)
	}

	return nil
}

func printImpactTable(qr *impact.QueryResult, snap *store.Snapshot) {
	if len(qr.Findings) == 0 {
		fmt.Printf("No findings match %q\n", qr.MatchedPattern)
		return
	}

	fmt.Printf("Blast radius for %q:\n", qr.MatchedPattern)
	fmt.Printf("  Affected findings: %d\n", len(qr.Findings))
	if len(qr.Namespaces) > 0 {
		fmt.Printf("  Namespaces: %s\n", strings.Join(qr.Namespaces, ", "))
	}
	if len(qr.Clusters) > 0 {
		fmt.Printf("  Clusters: %s\n", strings.Join(qr.Clusters, ", "))
	}

	// Severity summary
	var sevParts []string
	for _, sev := range []store.Severity{store.SeverityCritical, store.SeverityWarn, store.SeverityInfo} {
		if count, ok := qr.BySeverity[sev]; ok && count > 0 {
			sevParts = append(sevParts, fmt.Sprintf("%s=%d", sev, count))
		}
	}
	if len(sevParts) > 0 {
		fmt.Printf("  Severity: %s\n", strings.Join(sevParts, ", "))
	}
	fmt.Println()

	// Reuse PlainText-style table for affected findings
	impactSnap := store.Snapshot{At: snap.At, Findings: qr.Findings}
	fmt.Print(monitor.PlainText(impactSnap))
}
