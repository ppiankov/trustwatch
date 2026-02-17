// Package metrics provides Prometheus instrumentation for trustwatch.
package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/ppiankov/trustwatch/internal/store"
)

// Collector translates a snapshot into Prometheus gauge values.
type Collector struct {
	certNotAfter       *prometheus.GaugeVec
	certExpiresIn      *prometheus.GaugeVec
	probeSuccess       *prometheus.GaugeVec
	findingsTotal      *prometheus.GaugeVec
	discoveryErrors    *prometheus.GaugeVec
	chainErrors        *prometheus.GaugeVec
	discovererDuration *prometheus.HistogramVec
	scanDuration       prometheus.Gauge
	lastScanTimestamp  prometheus.Gauge
	mu                 sync.Mutex
}

// NewCollector creates and registers metrics on the given registerer.
func NewCollector(reg prometheus.Registerer) *Collector {
	c := &Collector{
		certNotAfter: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "trustwatch",
			Name:      "cert_not_after_timestamp",
			Help:      "Unix timestamp of certificate notAfter.",
		}, []string{"source", "namespace", "name", "severity", "cluster"}),

		certExpiresIn: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "trustwatch",
			Name:      "cert_expires_in_seconds",
			Help:      "Seconds until certificate expires (negative if expired).",
		}, []string{"source", "namespace", "name", "severity", "cluster"}),

		probeSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "trustwatch",
			Name:      "probe_success",
			Help:      "Whether the TLS probe succeeded (1=ok, 0=failed).",
		}, []string{"source", "namespace", "name", "cluster"}),

		scanDuration: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "trustwatch",
			Name:      "scan_duration_seconds",
			Help:      "Duration of the last discovery scan in seconds.",
		}),

		lastScanTimestamp: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "trustwatch",
			Name:      "last_scan_timestamp_seconds",
			Help:      "Unix timestamp of the last completed scan.",
		}),

		findingsTotal: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "trustwatch",
			Name:      "findings_total",
			Help:      "Total number of findings by severity.",
		}, []string{"severity"}),

		discoveryErrors: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "trustwatch",
			Name:      "discovery_errors_total",
			Help:      "Number of discoverer failures by source.",
		}, []string{"source"}),

		chainErrors: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "trustwatch",
			Name:      "chain_errors_total",
			Help:      "Number of findings with chain validation errors by source.",
		}, []string{"source"}),

		discovererDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "trustwatch",
			Name:      "discoverer_duration_seconds",
			Help:      "Duration of each discoverer's Discover() call in seconds.",
			Buckets:   []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"source"}),
	}

	reg.MustRegister(c.certNotAfter)
	reg.MustRegister(c.certExpiresIn)
	reg.MustRegister(c.probeSuccess)
	reg.MustRegister(c.scanDuration)
	reg.MustRegister(c.lastScanTimestamp)
	reg.MustRegister(c.findingsTotal)
	reg.MustRegister(c.discoveryErrors)
	reg.MustRegister(c.chainErrors)
	reg.MustRegister(c.discovererDuration)

	return c
}

// ObserveDiscovererDuration records the wall-clock time for a single discoverer run.
func (c *Collector) ObserveDiscovererDuration(source string, d time.Duration) {
	c.discovererDuration.WithLabelValues(source).Observe(d.Seconds())
}

// Update replaces all metric values from the given snapshot.
func (c *Collector) Update(snap store.Snapshot, scanDuration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.certNotAfter.Reset()
	c.certExpiresIn.Reset()
	c.probeSuccess.Reset()
	c.findingsTotal.Reset()
	c.discoveryErrors.Reset()
	c.chainErrors.Reset()

	c.scanDuration.Set(scanDuration.Seconds())
	if !snap.At.IsZero() {
		c.lastScanTimestamp.Set(float64(snap.At.Unix()))
	}

	counts := map[store.Severity]int{
		store.SeverityInfo:     0,
		store.SeverityWarn:     0,
		store.SeverityCritical: 0,
	}

	chainErrorCounts := make(map[store.SourceKind]int)

	for i := range snap.Findings {
		f := &snap.Findings[i]
		counts[f.Severity]++
		if len(f.ChainErrors) > 0 {
			chainErrorCounts[f.Source]++
		}

		labels := prometheus.Labels{
			"source":    string(f.Source),
			"namespace": f.Namespace,
			"name":      f.Name,
			"severity":  string(f.Severity),
			"cluster":   f.Cluster,
		}

		if !f.NotAfter.IsZero() {
			c.certNotAfter.With(labels).Set(float64(f.NotAfter.Unix()))
			c.certExpiresIn.With(labels).Set(f.NotAfter.Sub(snap.At).Seconds())
		}

		probeLabels := prometheus.Labels{
			"source":    string(f.Source),
			"namespace": f.Namespace,
			"name":      f.Name,
			"cluster":   f.Cluster,
		}
		if f.ProbeOK {
			c.probeSuccess.With(probeLabels).Set(1)
		} else {
			c.probeSuccess.With(probeLabels).Set(0)
		}
	}

	for sev, count := range counts {
		c.findingsTotal.With(prometheus.Labels{"severity": string(sev)}).Set(float64(count))
	}

	for source := range snap.Errors {
		c.discoveryErrors.With(prometheus.Labels{"source": source}).Set(1)
	}

	for source, count := range chainErrorCounts {
		c.chainErrors.With(prometheus.Labels{"source": string(source)}).Set(float64(count))
	}
}
