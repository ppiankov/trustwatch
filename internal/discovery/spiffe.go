package discovery

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/ppiankov/trustwatch/internal/store"
)

// SPIFFEDiscoverer probes SPIRE trust bundles for expiring root CAs.
type SPIFFEDiscoverer struct {
	socketPath string
}

// NewSPIFFEDiscoverer creates a discoverer that connects to the SPIFFE
// workload API via the given Unix socket path.
func NewSPIFFEDiscoverer(socketPath string, opts ...func(*SPIFFEDiscoverer)) *SPIFFEDiscoverer {
	d := &SPIFFEDiscoverer{
		socketPath: socketPath,
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Name returns the discoverer label.
func (d *SPIFFEDiscoverer) Name() string { return "spiffe" }

// Discover connects to the SPIFFE workload API and returns findings for each root CA.
func (d *SPIFFEDiscoverer) Discover() ([]store.CertFinding, error) {
	// Check socket exists before attempting gRPC dial
	if _, err := os.Stat(d.socketPath); err != nil {
		slog.Debug("SPIFFE socket not found, skipping", "path", d.socketPath)
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+d.socketPath))
	if err != nil {
		return nil, fmt.Errorf("connecting to SPIFFE workload API: %w", err)
	}
	defer client.Close() //nolint:errcheck // best-effort cleanup

	bundleSet, err := client.FetchX509Bundles(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching X.509 bundles: %w", err)
	}

	bundles := make(map[string][]*x509.Certificate)
	for _, b := range bundleSet.Bundles() {
		td := b.TrustDomain().Name()
		bundles[td] = b.X509Authorities()
	}

	return findingsFromBundles(bundles), nil
}

// findingsFromBundles converts SPIFFE trust domain bundles into CertFindings.
// Each root CA cert in each trust domain becomes a finding.
func findingsFromBundles(bundles map[string][]*x509.Certificate) []store.CertFinding {
	var findings []store.CertFinding
	for td, certs := range bundles {
		for _, cert := range certs {
			f := store.CertFinding{
				NotAfter:  cert.NotAfter,
				Name:      cert.Subject.CommonName,
				Namespace: td,
				Source:    store.SourceSPIFFE,
				Subject:   cert.Subject.String(),
				Issuer:    cert.Issuer.String(),
				Serial:    cert.SerialNumber.String(),
				ProbeOK:   true,
				Notes:     fmt.Sprintf("SPIFFE trust domain %q root CA", td),
			}
			if f.Name == "" {
				f.Name = fmt.Sprintf("root-ca-%s", cert.SerialNumber.Text(16))
			}
			findings = append(findings, f)
		}
	}
	return findings
}
