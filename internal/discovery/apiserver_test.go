package discovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/store"
)

func TestAPIServerDiscoverer_Name(t *testing.T) {
	d := NewAPIServerDiscoverer("")
	if d.Name() != "apiserver" {
		t.Errorf("expected name %q, got %q", "apiserver", d.Name())
	}
}

func TestAPIServerDiscoverer_DefaultTarget(t *testing.T) {
	d := NewAPIServerDiscoverer("")
	if d.target != defaultAPIServerTarget {
		t.Errorf("expected target %q, got %q", defaultAPIServerTarget, d.target)
	}
}

func TestAPIServerDiscoverer_CustomTarget(t *testing.T) {
	d := NewAPIServerDiscoverer("my-apiserver:6443")
	if d.target != "my-apiserver:6443" {
		t.Errorf("expected target %q, got %q", "my-apiserver:6443", d.target)
	}
}

func TestAPIServerDiscoverer_Discover(t *testing.T) {
	cert, x509Cert := generateTestCert(t)
	listener := startTestTLSServer(t, &cert)
	defer listener.Close()

	d := NewAPIServerDiscoverer(listener.Addr().String())
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Source != store.SourceAPIServer {
		t.Errorf("expected source %q, got %q", store.SourceAPIServer, f.Source)
	}
	if f.Severity != store.SeverityInfo {
		t.Errorf("expected severity %q, got %q", store.SeverityInfo, f.Severity)
	}
	if f.Name != "kubernetes-apiserver" {
		t.Errorf("expected name %q, got %q", "kubernetes-apiserver", f.Name)
	}
	if !f.ProbeOK {
		t.Errorf("expected probe OK, got error: %s", f.ProbeErr)
	}
	if f.NotAfter.IsZero() {
		t.Error("expected non-zero NotAfter")
	}
	if !f.NotAfter.Equal(x509Cert.NotAfter) {
		t.Errorf("expected NotAfter %v, got %v", x509Cert.NotAfter, f.NotAfter)
	}
	if f.Serial != x509Cert.SerialNumber.String() {
		t.Errorf("expected serial %q, got %q", x509Cert.SerialNumber.String(), f.Serial)
	}
	if len(f.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d", len(f.DNSNames))
	}
}

func TestAPIServerDiscoverer_ProbeFailure(t *testing.T) {
	// Use a listener that immediately closes to get a free port, then close it
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	d := NewAPIServerDiscoverer(addr)
	findings, err := d.Discover()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ProbeOK {
		t.Error("expected probe failure")
	}
	if f.ProbeErr == "" {
		t.Error("expected non-empty probe error")
	}
	if f.Source != store.SourceAPIServer {
		t.Errorf("expected source %q, got %q", store.SourceAPIServer, f.Source)
	}
}

func TestAPIServerDiscoverer_ImplementsDiscoverer(_ *testing.T) {
	var _ Discoverer = (*APIServerDiscoverer)(nil)
}

func startTestTLSServer(t *testing.T, cert *tls.Certificate) net.Listener {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Complete TLS handshake before closing
			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
			conn.Close()
		}
	}()

	return listener
}

func generateTestCert(t *testing.T) (tlsCert tls.Certificate, parsed *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"kubernetes.default.svc", "localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err = x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, parsed
}
