package cli

import (
	"context"
	"errors"
	"fmt"
	"log"
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

	"github.com/ppiankov/trustwatch/internal/config"
	"github.com/ppiankov/trustwatch/internal/discovery"
	"github.com/ppiankov/trustwatch/internal/metrics"
	"github.com/ppiankov/trustwatch/internal/store"
	"github.com/ppiankov/trustwatch/internal/web"
)

const (
	shutdownTimeout   = 5 * time.Second
	readHeaderTimeout = 10 * time.Second
	defaultConfigPath = "/etc/trustwatch/config.yaml"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run as in-cluster service with web UI and /metrics",
	Long: `Start trustwatch as a long-running service inside a Kubernetes cluster.

Exposes:
  /         Problems web UI (only expiring/failed trust surfaces)
  /metrics  Prometheus scrape endpoint
  /healthz  Liveness probe
  /api/v1/snapshot  JSON snapshot of all findings`,
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

	// Derive API server host from kubeconfig for local probing
	apiServerTarget := apiServerFromHost(restCfg.Host)

	// Build discoverers
	discoverers := []discovery.Discoverer{
		discovery.NewWebhookDiscoverer(clientset),
		discovery.NewAPIServiceDiscoverer(aggClient),
		discovery.NewAPIServerDiscoverer(apiServerTarget),
		discovery.NewSecretDiscoverer(clientset),
		discovery.NewIngressDiscoverer(clientset),
		discovery.NewLinkerdDiscoverer(clientset),
		discovery.NewIstioDiscoverer(clientset),
		discovery.NewAnnotationDiscoverer(clientset),
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
	mux.HandleFunc("/healthz", web.HealthzHandler())
	mux.HandleFunc("/api/v1/snapshot", web.SnapshotHandler(getSnapshot))
	mux.Handle(cfg.MetricsPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
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
		log.Printf("scan complete: %d findings (critical=%d warn=%d errors=%d) in %s",
			len(snap.Findings), critCount, warnCount, errCount, duration.Round(time.Millisecond))
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
							log.Printf("scan panic recovered: %v", r)
						}
					}()
					scan()
				}()
			}
		}
	}()

	// Start HTTP server
	go func() {
		log.Printf("trustwatch serve %s listening on %s", version, cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	log.Println("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	log.Println("shutdown complete")
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
