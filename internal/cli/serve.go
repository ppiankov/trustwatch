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
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"github.com/ppiankov/trustwatch/internal/config"
	"github.com/ppiankov/trustwatch/internal/discovery"
	"github.com/ppiankov/trustwatch/internal/metrics"
	"github.com/ppiankov/trustwatch/internal/store"
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
		discovery.NewGatewayDiscoverer(gwClient, clientset),
	}
	if len(cfg.External) > 0 {
		discoverers = append(discoverers, discovery.NewExternalDiscoverer(cfg.External))
	}

	orch := discovery.NewOrchestrator(discoverers, cfg.WarnBefore, cfg.CritBefore)

	// Shared state: mutex-protected snapshot
	var mu sync.RWMutex
	var currentSnap store.Snapshot

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
	mux.HandleFunc("/", web.UIHandler(getSnapshot))
	mux.HandleFunc("/healthz", web.HealthzHandler(getSnapshot, 2*cfg.RefreshEvery))
	mux.HandleFunc("/api/v1/snapshot", web.SnapshotHandler(getSnapshot))
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
		currentSnap = snap
		mu.Unlock()

		collector.Update(snap, duration)

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
