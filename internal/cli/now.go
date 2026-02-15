package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"github.com/ppiankov/trustwatch/internal/config"
	"github.com/ppiankov/trustwatch/internal/discovery"
	"github.com/ppiankov/trustwatch/internal/monitor"
	"github.com/ppiankov/trustwatch/internal/policy"
	"github.com/ppiankov/trustwatch/internal/probe"
	"github.com/ppiankov/trustwatch/internal/tunnel"
)

var nowCmd = &cobra.Command{
	Use:   "now",
	Short: "Show trust surface problems right now",
	Long: `Discover and probe all trust surfaces, display problems in a TUI.

Discovers webhooks, APIServices, TLS secrets, ingresses, mesh issuers,
annotated services, and external targets. Probes each via TLS handshake
and reports expiring or expired certificates.

Exit codes:
  0  No problems found
  1  Warnings exist (certs expiring within warn threshold)
  2  Critical problems (certs expiring within crit threshold or expired)
  3  Discovery or probe errors`,
	Example: `  # Scan current cluster
  trustwatch now

  # Scan a specific context with custom thresholds
  trustwatch now --context prod --warn-before 360h --crit-before 168h

  # JSON output for automation
  trustwatch now --output json

  # Table output even in a terminal
  trustwatch now -o table

  # CI gate: exit code only, no output
  trustwatch now --quiet && echo "All certs OK"

  # JSON piped to jq
  trustwatch now -o json | jq '.snapshot.findings[] | select(.severity == "critical")'

  # Scan through an in-cluster SOCKS5 relay (resolves cluster DNS)
  trustwatch now --tunnel

  # Air-gapped cluster using trustwatch as its own relay
  trustwatch now --tunnel --tunnel-image my-registry.io/trustwatch:v0.1.1 --tunnel-command /trustwatch,socks5`,
	RunE: runNow,
}

func init() {
	rootCmd.AddCommand(nowCmd)
	nowCmd.Flags().String("config", "", "Path to config file")
	nowCmd.Flags().String("kubeconfig", "", "Path to kubeconfig")
	nowCmd.Flags().String("context", "", "Kubernetes context to use")
	nowCmd.Flags().StringSlice("namespace", nil, "Namespaces to scan (empty = all)")
	nowCmd.Flags().Duration("warn-before", 0, "Warn threshold (default from config)")
	nowCmd.Flags().Duration("crit-before", 0, "Critical threshold (default from config)")
	nowCmd.Flags().Bool("tunnel", false, "Deploy a SOCKS5 relay pod to route probes through in-cluster DNS")
	nowCmd.Flags().String("tunnel-ns", "default", "Namespace for the tunnel relay pod")
	nowCmd.Flags().String("tunnel-image", tunnel.DefaultImage, "SOCKS5 proxy image for --tunnel")
	nowCmd.Flags().StringSlice("tunnel-command", nil, "Override container command (e.g. 'microsocks,-p,1080')")
	nowCmd.Flags().String("tunnel-pull-secret", "", "imagePullSecret name for the tunnel relay pod")
	nowCmd.Flags().StringP("output", "o", "", "Output format: json, table (default: auto-detect TTY)")
	nowCmd.Flags().BoolP("quiet", "q", false, "Suppress output, exit code only (for CI gates)")
}

func runNow(cmd *cobra.Command, _ []string) error {
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

	// Load TrustPolicy CRs if CRD is installed
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

	// Resolve context name for display
	if kubeCtx == "" {
		raw, rawErr := clientConfig.RawConfig()
		if rawErr == nil {
			kubeCtx = raw.CurrentContext
		}
	}

	// Optionally start a SOCKS5 tunnel for in-cluster DNS resolution
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

	// Derive API server host from kubeconfig for local probing
	apiServerTarget := apiServerFromHost(restCfg.Host)

	// Resolve namespaces for namespace-scoped discoverers
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
	slog.Info("namespace access resolved", "total", len(allNS),
		"secrets", len(secretNS), "ingresses", len(ingressNS),
		"services", len(svcNS), "gateways", len(gwNS),
		"certificates", len(certNS))

	// Build discoverers — probing discoverers get the tunnel probe function when --tunnel is set
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

	discoverers := []discovery.Discoverer{
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

	// Run discovery
	slog.Info("scanning discovery sources", "count", len(discoverers))
	orch := discovery.NewOrchestrator(discoverers, cfg.WarnBefore, cfg.CritBefore)
	snap := orch.Run()
	slog.Info("scan complete", "findings", len(snap.Findings))

	// Display results
	exitCode := monitor.ExitCode(snap)

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
		case "table":
			fmt.Print(monitor.PlainText(snap))
		default:
			if isInteractive() {
				m := monitor.NewModel(snap, kubeCtx)
				p := tea.NewProgram(m, tea.WithAltScreen())
				if _, err := p.Run(); err != nil {
					return fmt.Errorf("TUI error: %w", err)
				}
			} else {
				fmt.Print(monitor.PlainText(snap))
			}
		}
	}

	if exitCode != 0 {
		closeRelay()      // explicit cleanup because os.Exit bypasses defers
		os.Exit(exitCode) //nolint:gocritic // exitAfterDefer — defer is for the normal-return path; this is the nonzero-exit path
	}
	return nil
}

// isInteractive returns true if stdout is a terminal.
func isInteractive() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// apiServerFromHost extracts host:port from a REST config Host URL
// for use as an API server probe target.
func apiServerFromHost(host string) string {
	if host == "" {
		return ""
	}
	u, err := url.Parse(host)
	if err != nil {
		return ""
	}
	return u.Host
}

// restProbe returns a probe function that uses the REST config's transport
// (proxy, exec auth, tunnels) to reach the API server and extract its TLS cert.
func restProbe(cfg *rest.Config) func(string) probe.Result {
	return func(_ string) probe.Result {
		probeCfg := rest.CopyConfig(cfg)
		probeCfg.Insecure = true
		probeCfg.CAData = nil
		probeCfg.CAFile = ""

		transport, err := rest.TransportFor(probeCfg)
		if err != nil {
			return probe.Result{ProbeErr: fmt.Sprintf("building transport: %v", err)}
		}

		req, err := http.NewRequest(http.MethodGet, cfg.Host+"/version", http.NoBody)
		if err != nil {
			return probe.Result{ProbeErr: fmt.Sprintf("building request: %v", err)}
		}

		resp, err := (&http.Client{Transport: transport}).Do(req)
		if err != nil {
			return probe.Result{ProbeErr: fmt.Sprintf("connecting to apiserver: %v", err)}
		}
		defer resp.Body.Close() //nolint:errcheck // read-only probe, close error is unactionable

		if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
			return probe.Result{ProbeErr: "no TLS certificates from apiserver"}
		}

		return probe.Result{
			Cert:    resp.TLS.PeerCertificates[0],
			Chain:   resp.TLS.PeerCertificates,
			ProbeOK: true,
		}
	}
}
