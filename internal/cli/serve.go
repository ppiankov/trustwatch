package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"github.com/ppiankov/trustwatch/internal/config"
	"github.com/ppiankov/trustwatch/internal/discovery"
	"github.com/ppiankov/trustwatch/internal/history"
	"github.com/ppiankov/trustwatch/internal/metrics"
	"github.com/ppiankov/trustwatch/internal/notify"
	"github.com/ppiankov/trustwatch/internal/policy"
	"github.com/ppiankov/trustwatch/internal/store"
	"github.com/ppiankov/trustwatch/internal/telemetry"
	"github.com/ppiankov/trustwatch/internal/web"
)

const (
	shutdownTimeout   = 5 * time.Second
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
	defaultConfigPath = "/etc/trustwatch/config.yaml"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run as in-cluster service with web UI and /metrics",
	Long: `Start trustwatch as a long-running service inside a Kubernetes cluster.

Runs a background scan loop and serves results over HTTP.

Endpoints:
  /               Problems web UI (only expiring/failed trust surfaces)
  /metrics        Prometheus scrape endpoint
  /healthz        Liveness probe (returns 503 if scan is stale)
  /api/v1/snapshot  JSON snapshot of all findings`,
	Example: `  # Run with default config
  trustwatch serve

  # Run with custom config file
  trustwatch serve --config /etc/trustwatch/config.yaml

  # Override listen address
  trustwatch serve --listen :9090

  # Run with JSON logging for log aggregation
  trustwatch serve --log-format json --log-level debug`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().String("config", defaultConfigPath, "Path to config file")
	serveCmd.Flags().String("listen", "", "Listen address (overrides config)")
	serveCmd.Flags().String("kubeconfig", "", "Path to kubeconfig")
	serveCmd.Flags().String("context", "", "Kubernetes context to use")
	serveCmd.Flags().String("history-db", "", "Path to SQLite history database (enables /api/v1/history and /api/v1/trend)")
	serveCmd.Flags().String("spiffe-socket", "", "Path to SPIFFE workload API socket")
}

func runServe(cmd *cobra.Command, _ []string) error {
	// Load config
	cfgPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return err
	}

	cfg := config.Defaults()
	if cfgPath != "" {
		if _, statErr := os.Stat(cfgPath); statErr == nil {
			cfg, err = config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
		} else if cfgPath != defaultConfigPath {
			// Non-default path that doesn't exist is an error
			return fmt.Errorf("config file not found: %s", cfgPath)
		}
	}

	// Override listen addr from flag
	listenFlag, _ := cmd.Flags().GetString("listen") //nolint:errcheck // flag registered above
	if listenFlag != "" {
		cfg.ListenAddr = listenFlag
	}

	// Override history DB from flag
	historyDB, _ := cmd.Flags().GetString("history-db") //nolint:errcheck // flag registered above
	if historyDB != "" {
		cfg.HistoryDB = historyDB
	}

	// Open history store if configured
	var histStore *history.Store
	if cfg.HistoryDB != "" {
		var histErr error
		histStore, histErr = history.Open(cfg.HistoryDB)
		if histErr != nil {
			return fmt.Errorf("opening history database: %w", histErr)
		}
		defer histStore.Close() //nolint:errcheck // best-effort cleanup on shutdown
		slog.Info("history storage enabled", "path", cfg.HistoryDB)
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

	restCfg, err := buildRESTConfig(kubeconfig, kubeCtx)
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

	// Build discoverers
	discoverers := []discovery.Discoverer{
		discovery.NewWebhookDiscoverer(clientset),
		discovery.NewAPIServiceDiscoverer(aggClient),
		discovery.NewAPIServerDiscoverer(apiServerTarget, discovery.WithProbeFn(restProbe(restCfg))),
		discovery.NewSecretDiscoverer(clientset, discovery.WithSecretNamespaces(secretNS)),
		discovery.NewIngressDiscoverer(clientset, discovery.WithIngressNamespaces(ingressNS)),
		discovery.NewLinkerdDiscoverer(clientset),
		discovery.NewIstioDiscoverer(clientset),
		discovery.NewAnnotationDiscoverer(clientset, discovery.WithAnnotationNamespaces(svcNS)),
		discovery.NewGatewayDiscoverer(gwClient, clientset, discovery.WithGatewayNamespaces(gwNS)),
		discovery.NewCertManagerDiscoverer(dynClient, clientset, discovery.WithCertManagerNamespaces(certNS)),
		discovery.NewCertManagerRenewalDiscoverer(dynClient, clientset, discovery.WithRenewalNamespaces(certNS)),
	}
	if len(cfg.External) > 0 {
		discoverers = append(discoverers, discovery.NewExternalDiscoverer(cfg.External))
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

	var orchOpts []discovery.OrchestratorOption
	if len(loadedPolicies) > 0 {
		orchOpts = append(orchOpts, discovery.WithPolicies(loadedPolicies))
	}
	if tracer != nil {
		orchOpts = append(orchOpts, discovery.WithTracer(tracer))
	}
	orch := discovery.NewOrchestrator(discoverers, cfg.WarnBefore, cfg.CritBefore, orchOpts...)

	// Notifications (nil if not configured)
	notifier := notify.New(cfg.Notifications)

	// Shared state: mutex-protected snapshot
	var mu sync.RWMutex
	var currentSnap store.Snapshot
	var previousSnap store.Snapshot

	getSnapshot := func() store.Snapshot {
		mu.RLock()
		defer mu.RUnlock()
		return currentSnap
	}

	// Prometheus metrics
	registry := prometheus.NewRegistry()
	collector := metrics.NewCollector(registry)

	// HTTP server
	mux := http.NewServeMux()
	var uiOpts []func(*web.UIConfig)
	if histStore != nil {
		uiOpts = append(uiOpts, web.WithHistoryEnabled())
	}
	mux.HandleFunc("/", web.UIHandler(getSnapshot, uiOpts...))
	mux.HandleFunc("/healthz", web.HealthzHandler(getSnapshot, 2*cfg.RefreshEvery))
	mux.HandleFunc("/api/v1/snapshot", web.SnapshotHandler(getSnapshot))
	if histStore != nil {
		mux.HandleFunc("/api/v1/history", web.HistoryHandler(histStore))
		mux.HandleFunc("/api/v1/trend", web.TrendHandler(histStore))
	}
	mux.Handle(cfg.MetricsPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Background scan loop
	scan := func() {
		start := time.Now()
		snap := orch.Run()
		duration := time.Since(start)

		mu.Lock()
		previousSnap = currentSnap
		currentSnap = snap
		prev := previousSnap
		mu.Unlock()

		collector.Update(snap, duration)

		if histStore != nil {
			if saveErr := histStore.Save(snap); saveErr != nil {
				slog.Error("saving history snapshot", "err", saveErr)
			}
		}

		if notifier != nil {
			notifier.Notify(prev, snap)
		}

		var critCount, warnCount, errCount int
		for i := range snap.Findings {
			switch snap.Findings[i].Severity {
			case store.SeverityCritical:
				critCount++
			case store.SeverityWarn:
				warnCount++
			}
			if !snap.Findings[i].ProbeOK {
				errCount++
			}
		}
		slog.Info("scan complete", "findings", len(snap.Findings),
			"critical", critCount, "warn", warnCount, "errors", errCount,
			"duration", duration.Round(time.Millisecond))
	}

	// Run initial scan
	scan()

	// Start periodic scan loop
	go func() {
		ticker := time.NewTicker(cfg.RefreshEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				func() {
					defer func() {
						if r := recover(); r != nil {
							slog.Error("scan panic recovered", "panic", r)
						}
					}()
					scan()
				}()
			}
		}
	}()

	// Start HTTP server
	srvErr := make(chan error, 1)
	go func() {
		slog.Info("trustwatch serve listening", "version", version, "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Wait for shutdown signal or server error
	select {
	case <-ctx.Done():
	case err := <-srvErr:
		return err
	}
	slog.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	slog.Info("shutdown complete")
	return nil
}

// buildRESTConfig tries in-cluster config first, falls back to kubeconfig.
func buildRESTConfig(kubeconfig, kubeCtx string) (*rest.Config, error) {
	// Try in-cluster first when no explicit flags are given
	if kubeconfig == "" && kubeCtx == "" {
		cfg, err := rest.InClusterConfig()
		if err == nil {
			return cfg, nil
		}
	}

	// Fall back to kubeconfig (respects KUBECONFIG env var)
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		loadingRules.ExplicitPath = kubeconfig
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{CurrentContext: kubeCtx},
	).ClientConfig()
}
