package discovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

func selfSignedCA(cn string, notBefore, notAfter time.Time) *x509.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func TestFindingsFromBundles_SingleDomain(t *testing.T) {
	now := time.Now()
	ca := selfSignedCA("SPIRE Root CA", now.Add(-365*24*time.Hour), now.Add(365*24*time.Hour))

	bundles := map[string][]*x509.Certificate{
		"example.org": {ca},
	}

	findings := findingsFromBundles(bundles)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Source != store.SourceSPIFFE {
		t.Errorf("source = %q, want %q", f.Source, store.SourceSPIFFE)
	}
	if f.Namespace != "example.org" {
		t.Errorf("namespace = %q, want %q", f.Namespace, "example.org")
	}
	if f.Name != "SPIRE Root CA" {
		t.Errorf("name = %q, want %q", f.Name, "SPIRE Root CA")
	}
	if !f.ProbeOK {
		t.Error("expected probeOK=true")
	}
}

func TestFindingsFromBundles_MultipleDomains(t *testing.T) {
	now := time.Now()
	ca1 := selfSignedCA("Root A", now.Add(-24*time.Hour), now.Add(24*time.Hour))
	ca2 := selfSignedCA("Root B", now.Add(-24*time.Hour), now.Add(24*time.Hour))

	bundles := map[string][]*x509.Certificate{
		"domain-a.org": {ca1},
		"domain-b.org": {ca2},
	}

	findings := findingsFromBundles(bundles)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

func TestFindingsFromBundles_MultipleCertsPerDomain(t *testing.T) {
	now := time.Now()
	ca1 := selfSignedCA("Root 1", now.Add(-24*time.Hour), now.Add(24*time.Hour))
	ca2 := selfSignedCA("Root 2", now.Add(-24*time.Hour), now.Add(24*time.Hour))

	bundles := map[string][]*x509.Certificate{
		"example.org": {ca1, ca2},
	}

	findings := findingsFromBundles(bundles)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

func TestFindingsFromBundles_EmptyCN(t *testing.T) {
	now := time.Now()
	ca := selfSignedCA("", now.Add(-24*time.Hour), now.Add(24*time.Hour))

	bundles := map[string][]*x509.Certificate{
		"example.org": {ca},
	}

	findings := findingsFromBundles(bundles)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Name == "" {
		t.Error("expected non-empty name when CN is empty (should use serial)")
	}
}

func TestFindingsFromBundles_Empty(t *testing.T) {
	findings := findingsFromBundles(nil)
	if findings != nil {
		t.Errorf("expected nil findings for empty bundles, got %d", len(findings))
	}
}

func TestSPIFFEDiscoverer_Name(t *testing.T) {
	d := NewSPIFFEDiscoverer("/nonexistent/socket.sock")
	if d.Name() != "spiffe" {
		t.Errorf("name = %q, want %q", d.Name(), "spiffe")
	}
}

func TestSPIFFEDiscoverer_SocketNotFound(t *testing.T) {
	d := NewSPIFFEDiscoverer("/nonexistent/spire-agent.sock")
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings when socket missing, got %d", len(findings))
	}
}
