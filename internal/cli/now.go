package cli

import (
	"fmt"
	"net/http"
	"net/url"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	"github.com/ppiankov/trustwatch/internal/config"
	"github.com/ppiankov/trustwatch/internal/discovery"
	"github.com/ppiankov/trustwatch/internal/monitor"
	"github.com/ppiankov/trustwatch/internal/probe"
)

var nowCmd = &cobra.Command{
	Use:   "now",
	Short: "Show trust surface problems right now",
	Long: `Discover and probe all trust surfaces, display problems in a TUI.

Exit codes:
  0  No problems found
  1  Warnings exist (certs expiring within warn threshold)
  2  Critical problems (certs expiring within crit threshold or expired)
  3  Discovery or probe errors`,
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

	// Resolve context name for display
	if kubeCtx == "" {
		raw, rawErr := clientConfig.RawConfig()
		if rawErr == nil {
			kubeCtx = raw.CurrentContext
		}
	}

	// Derive API server host from kubeconfig for local probing
	apiServerTarget := apiServerFromHost(restCfg.Host)

	// Build discoverers
	discoverers := []discovery.Discoverer{
		discovery.NewWebhookDiscoverer(clientset),
		discovery.NewAPIServiceDiscoverer(aggClient),
		discovery.NewAPIServerDiscoverer(apiServerTarget, discovery.WithProbeFn(restProbe(restCfg))),
		discovery.NewSecretDiscoverer(clientset),
		discovery.NewIngressDiscoverer(clientset),
		discovery.NewLinkerdDiscoverer(clientset),
		discovery.NewIstioDiscoverer(clientset),
		discovery.NewAnnotationDiscoverer(clientset),
	}
	if len(cfg.External) > 0 {
		discoverers = append(discoverers, discovery.NewExternalDiscoverer(cfg.External))
	}

	// Run discovery
	orch := discovery.NewOrchestrator(discoverers, cfg.WarnBefore, cfg.CritBefore)
	snap := orch.Run()

	// Display results
	exitCode := monitor.ExitCode(snap)

	if isInteractive() {
		m := monitor.NewModel(snap, kubeCtx)
		p := tea.NewProgram(m, tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			return fmt.Errorf("TUI error: %w", err)
		}
	} else {
		fmt.Print(monitor.PlainText(snap))
	}

	if exitCode != 0 {
		os.Exit(exitCode)
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
		probeCfg.TLSClientConfig.Insecure = true
		probeCfg.TLSClientConfig.CAData = nil
		probeCfg.TLSClientConfig.CAFile = ""

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
		defer resp.Body.Close()

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
