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
	certNotAfter    *prometheus.GaugeVec
	certExpiresIn   *prometheus.GaugeVec
	probeSuccess    *prometheus.GaugeVec
	findingsTotal   *prometheus.GaugeVec
	discoveryErrors *prometheus.GaugeVec
	scanDuration    prometheus.Gauge
	mu              sync.Mutex
}

// NewCollector creates and registers metrics on the given registerer.
func NewCollector(reg prometheus.Registerer) *Collector {
	c := &Collector{
		certNotAfter: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "trustwatch",
			Name:      "cert_not_after_timestamp",
			Help:      "Unix timestamp of certificate notAfter.",
		}, []string{"source", "namespace", "name", "severity"}),

		certExpiresIn: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "trustwatch",
			Name:      "cert_expires_in_seconds",
			Help:      "Seconds until certificate expires (negative if expired).",
		}, []string{"source", "namespace", "name", "severity"}),

		probeSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "trustwatch",
			Name:      "probe_success",
			Help:      "Whether the TLS probe succeeded (1=ok, 0=failed).",
		}, []string{"source", "namespace", "name"}),

		scanDuration: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "trustwatch",
			Name:      "scan_duration_seconds",
			Help:      "Duration of the last discovery scan in seconds.",
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
	}

	reg.MustRegister(c.certNotAfter)
	reg.MustRegister(c.certExpiresIn)
	reg.MustRegister(c.probeSuccess)
	reg.MustRegister(c.scanDuration)
	reg.MustRegister(c.findingsTotal)
	reg.MustRegister(c.discoveryErrors)

	return c
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

	c.scanDuration.Set(scanDuration.Seconds())

	counts := map[store.Severity]int{
		store.SeverityInfo:     0,
		store.SeverityWarn:     0,
		store.SeverityCritical: 0,
	}

	for i := range snap.Findings {
		f := &snap.Findings[i]
		counts[f.Severity]++

		labels := prometheus.Labels{
			"source":    string(f.Source),
			"namespace": f.Namespace,
			"name":      f.Name,
			"severity":  string(f.Severity),
		}

		if !f.NotAfter.IsZero() {
			c.certNotAfter.With(labels).Set(float64(f.NotAfter.Unix()))
			c.certExpiresIn.With(labels).Set(f.NotAfter.Sub(snap.At).Seconds())
		}

		probeLabels := prometheus.Labels{
			"source":    string(f.Source),
			"namespace": f.Namespace,
			"name":      f.Name,
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
}
