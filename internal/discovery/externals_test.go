package discovery

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/config"
	"github.com/ppiankov/trustwatch/internal/probe"
	"github.com/ppiankov/trustwatch/internal/store"
)

func TestExternalDiscoverer_ImplementsDiscoverer(_ *testing.T) {
	var _ Discoverer = (*ExternalDiscoverer)(nil)
}

func TestExternalDiscoverer_Name(t *testing.T) {
	d := NewExternalDiscoverer(nil)
	if d.Name() != "externals" {
		t.Errorf("expected name %q, got %q", "externals", d.Name())
	}
}

func TestExternalDiscoverer_NoTargets(t *testing.T) {
	d := NewExternalDiscoverer(nil)
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestExternalDiscoverer_SingleTarget(t *testing.T) {
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)

	targets := []config.ExternalTarget{
		{URL: "tcp://api.stripe.com:443"},
	}

	d := NewExternalDiscoverer(targets)
	d.probeFn = func(raw string) probe.Result {
		if raw != "tcp://api.stripe.com:443" {
			t.Errorf("unexpected probe URL: %s", raw)
		}
		return probe.Result{
			ProbeOK: true,
			Cert: &x509.Certificate{
				NotAfter:     notAfter,
				DNSNames:     []string{"api.stripe.com"},
				Issuer:       pkix.Name{CommonName: "DigiCert"},
				Subject:      pkix.Name{CommonName: "api.stripe.com"},
				SerialNumber: big.NewInt(123),
			},
		}
	}

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Source != store.SourceExternal {
		t.Errorf("expected source %q, got %q", store.SourceExternal, f.Source)
	}
	if f.Severity != store.SeverityInfo {
		t.Errorf("expected severity %q, got %q", store.SeverityInfo, f.Severity)
	}
	if f.Target != "tcp://api.stripe.com:443" {
		t.Errorf("expected target %q, got %q", "tcp://api.stripe.com:443", f.Target)
	}
	if !f.ProbeOK {
		t.Errorf("expected ProbeOK=true, got error: %s", f.ProbeErr)
	}
	if !f.NotAfter.Equal(notAfter) {
		t.Errorf("expected NotAfter %v, got %v", notAfter, f.NotAfter)
	}
	if f.Subject == "" {
		t.Error("expected non-empty Subject")
	}
	if f.Issuer == "" {
		t.Error("expected non-empty Issuer")
	}
}

func TestExternalDiscoverer_MultipleTargets(t *testing.T) {
	targets := []config.ExternalTarget{
		{URL: "tcp://a.example.com:443"},
		{URL: "tcp://b.example.com:443"},
		{URL: "tcp://c.example.com:8443"},
	}

	d := NewExternalDiscoverer(targets)
	d.probeFn = mockProbeResult(successProbeResult())

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	for i, f := range findings {
		if f.Target != targets[i].URL {
			t.Errorf("finding[%d]: expected target %q, got %q", i, targets[i].URL, f.Target)
		}
		if f.Source != store.SourceExternal {
			t.Errorf("finding[%d]: expected source %q, got %q", i, store.SourceExternal, f.Source)
		}
	}
}

func TestExternalDiscoverer_ProbeFailure(t *testing.T) {
	targets := []config.ExternalTarget{
		{URL: "tcp://unreachable.example.com:443"},
	}

	d := NewExternalDiscoverer(targets)
	d.probeFn = mockProbeResult(failProbeResult())

	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ProbeOK {
		t.Error("expected ProbeOK=false")
	}
	if f.ProbeErr != "connection refused" {
		t.Errorf("expected ProbeErr %q, got %q", "connection refused", f.ProbeErr)
	}
	if f.Target != "tcp://unreachable.example.com:443" {
		t.Errorf("expected target preserved, got %q", f.Target)
	}
}

func TestExternalDiscoverer_EmptySlice(t *testing.T) {
	d := NewExternalDiscoverer([]config.ExternalTarget{})
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestExternalDiscoverer_URLPassedDirectly(t *testing.T) {
	// Verify the URL from config is passed directly to probeFn (no transformation)
	targets := []config.ExternalTarget{
		{URL: "tcp://custom.host:9999?sni=override.local"},
	}

	var receivedURL string
	d := NewExternalDiscoverer(targets)
	d.probeFn = func(raw string) probe.Result {
		receivedURL = raw
		return successProbeResult()
	}

	_, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedURL != "tcp://custom.host:9999?sni=override.local" {
		t.Errorf("expected URL passed directly, got %q", receivedURL)
	}
}
