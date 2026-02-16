package revocation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// helper: generate a self-signed CA + leaf pair for testing
func testCACertPair(t *testing.T) (ca *x509.Certificate, caKey *ecdsa.PrivateKey, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return ca, caKey, leaf, leafKey
}

func TestCheckOCSP_GoodStaple(t *testing.T) {
	ca, caKey, leaf, _ := testCACertPair(t)

	staple, err := ocsp.CreateResponse(ca, ca, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-1 * time.Hour),
		NextUpdate:   time.Now().Add(1 * time.Hour),
	}, caKey)
	if err != nil {
		t.Fatal(err)
	}

	result := CheckOCSP(leaf, ca, staple)
	if result != nil {
		t.Errorf("expected nil for good staple, got %+v", result)
	}
}

func TestCheckOCSP_RevokedStaple(t *testing.T) {
	ca, caKey, leaf, _ := testCACertPair(t)

	staple, err := ocsp.CreateResponse(ca, ca, ocsp.Response{
		Status:       ocsp.Revoked,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-1 * time.Hour),
		NextUpdate:   time.Now().Add(1 * time.Hour),
		RevokedAt:    time.Now().Add(-30 * time.Minute),
	}, caKey)
	if err != nil {
		t.Fatal(err)
	}

	result := CheckOCSP(leaf, ca, staple)
	if result == nil {
		t.Fatal("expected revocation result, got nil")
	}
	if result.Status != StatusRevoked {
		t.Errorf("expected status %q, got %q", StatusRevoked, result.Status)
	}
}

func TestCheckOCSP_ExpiredStaple(t *testing.T) {
	ca, caKey, leaf, _ := testCACertPair(t)

	staple, err := ocsp.CreateResponse(ca, ca, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-2 * time.Hour),
		NextUpdate:   time.Now().Add(-1 * time.Hour), // expired
	}, caKey)
	if err != nil {
		t.Fatal(err)
	}

	result := CheckOCSP(leaf, ca, staple)
	if result == nil {
		t.Fatal("expected result for expired staple, got nil")
	}
	if result.Status != StatusStapleInvalid {
		t.Errorf("expected status %q, got %q", StatusStapleInvalid, result.Status)
	}
}

func TestCheckOCSP_MalformedStaple(t *testing.T) {
	_, _, leaf, _ := testCACertPair(t)
	ca := leaf // wrong issuer for parse

	result := CheckOCSP(leaf, ca, []byte("not-valid-ocsp"))
	if result == nil {
		t.Fatal("expected result for malformed staple, got nil")
	}
	if result.Status != StatusStapleInvalid {
		t.Errorf("expected status %q, got %q", StatusStapleInvalid, result.Status)
	}
}

func TestCheckOCSP_ResponderGood(t *testing.T) {
	ca, caKey, leaf, _ := testCACertPair(t)

	// Mock OCSP responder
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp, err := ocsp.CreateResponse(ca, ca, ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: leaf.SerialNumber,
			ThisUpdate:   time.Now().Add(-1 * time.Hour),
			NextUpdate:   time.Now().Add(1 * time.Hour),
		}, caKey)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(resp) //nolint:errcheck // test handler response write
	}))
	defer srv.Close()

	// Inject OCSP server URL into cert
	leaf.OCSPServer = []string{srv.URL}

	result := CheckOCSP(leaf, ca, nil) // no staple
	if result != nil {
		t.Errorf("expected nil for good OCSP response, got %+v", result)
	}
}

func TestCheckOCSP_ResponderRevoked(t *testing.T) {
	ca, caKey, leaf, _ := testCACertPair(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp, err := ocsp.CreateResponse(ca, ca, ocsp.Response{
			Status:       ocsp.Revoked,
			SerialNumber: leaf.SerialNumber,
			ThisUpdate:   time.Now().Add(-1 * time.Hour),
			NextUpdate:   time.Now().Add(1 * time.Hour),
			RevokedAt:    time.Now().Add(-30 * time.Minute),
		}, caKey)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(resp) //nolint:errcheck // test handler response write
	}))
	defer srv.Close()

	leaf.OCSPServer = []string{srv.URL}

	result := CheckOCSP(leaf, ca, nil)
	if result == nil {
		t.Fatal("expected revocation result, got nil")
	}
	if result.Status != StatusRevoked {
		t.Errorf("expected status %q, got %q", StatusRevoked, result.Status)
	}
}

func TestCheckOCSP_ResponderUnreachable(t *testing.T) {
	_, _, leaf, _ := testCACertPair(t)
	leaf.OCSPServer = []string{"http://127.0.0.1:1/ocsp"} // unreachable

	ca := leaf // doesn't matter since we won't get a response
	result := CheckOCSP(leaf, ca, nil)
	if result == nil {
		t.Fatal("expected unreachable result, got nil")
	}
	if result.Status != StatusUnreachable {
		t.Errorf("expected status %q, got %q", StatusUnreachable, result.Status)
	}
}

func TestCheckOCSP_NoServers(t *testing.T) {
	ca, _, leaf, _ := testCACertPair(t)
	leaf.OCSPServer = nil

	result := CheckOCSP(leaf, ca, nil)
	if result != nil {
		t.Errorf("expected nil when no OCSP servers, got %+v", result)
	}
}

func TestCheckCRL_NotRevoked(t *testing.T) {
	ca, caKey, leaf, _ := testCACertPair(t)

	// Create empty CRL
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-1 * time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(crlBytes) //nolint:errcheck // test handler response write
	}))
	defer srv.Close()

	leaf.CRLDistributionPoints = []string{srv.URL}
	cache := NewCRLCache()

	result := CheckCRL(leaf, cache)
	if result != nil {
		t.Errorf("expected nil for non-revoked cert, got %+v", result)
	}
}

func TestCheckCRL_Revoked(t *testing.T) {
	ca, caKey, leaf, _ := testCACertPair(t)

	// CRL with leaf serial revoked
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-1 * time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: leaf.SerialNumber, RevocationTime: time.Now().Add(-30 * time.Minute)},
		},
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(crlBytes) //nolint:errcheck // test handler response write
	}))
	defer srv.Close()

	leaf.CRLDistributionPoints = []string{srv.URL}
	cache := NewCRLCache()

	result := CheckCRL(leaf, cache)
	if result == nil {
		t.Fatal("expected revocation result, got nil")
	}
	if result.Status != StatusRevoked {
		t.Errorf("expected status %q, got %q", StatusRevoked, result.Status)
	}
}

func TestCheckCRL_Stale(t *testing.T) {
	ca, caKey, leaf, _ := testCACertPair(t)

	// CRL with NextUpdate in the past
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-48 * time.Hour),
		NextUpdate: time.Now().Add(-1 * time.Hour), // stale
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(crlBytes) //nolint:errcheck // test handler response write
	}))
	defer srv.Close()

	leaf.CRLDistributionPoints = []string{srv.URL}
	cache := NewCRLCache()

	result := CheckCRL(leaf, cache)
	if result == nil {
		t.Fatal("expected stale CRL result, got nil")
	}
	if result.Status != StatusCRLStale {
		t.Errorf("expected status %q, got %q", StatusCRLStale, result.Status)
	}
}

func TestCheckCRL_NoDPs(t *testing.T) {
	_, _, leaf, _ := testCACertPair(t)
	leaf.CRLDistributionPoints = nil

	result := CheckCRL(leaf, NewCRLCache())
	if result != nil {
		t.Errorf("expected nil when no CRL DPs, got %+v", result)
	}
}

func TestCRLCache_HitMissExpiry(t *testing.T) {
	cache := NewCRLCache()

	// Miss
	if got := cache.Get("http://example.com/crl"); got != nil {
		t.Errorf("expected nil for cache miss, got %v", got)
	}

	// Set with future expiry
	crl := &x509.RevocationList{NextUpdate: time.Now().Add(1 * time.Hour)}
	cache.Set("http://example.com/crl", crl)

	// Hit
	if got := cache.Get("http://example.com/crl"); got == nil {
		t.Error("expected cache hit, got nil")
	}

	// Set with past expiry (expired)
	expiredCRL := &x509.RevocationList{NextUpdate: time.Now().Add(-1 * time.Hour)}
	cache.Set("http://example.com/expired", expiredCRL)

	if got := cache.Get("http://example.com/expired"); got != nil {
		t.Errorf("expected nil for expired cache entry, got %v", got)
	}
}

func TestCheck_NoCert(t *testing.T) {
	issues := Check(nil, nil, nil, NewCRLCache())
	if len(issues) != 0 {
		t.Errorf("expected no issues for nil cert, got %v", issues)
	}
}

func TestCheck_NoIssuer(t *testing.T) {
	_, _, leaf, _ := testCACertPair(t)
	leaf.OCSPServer = nil
	leaf.CRLDistributionPoints = nil

	issues := Check(leaf, nil, nil, NewCRLCache())
	if len(issues) != 0 {
		t.Errorf("expected no issues without issuer and no endpoints, got %v", issues)
	}
}

func TestCheck_Integration(t *testing.T) {
	ca, caKey, leaf, _ := testCACertPair(t)

	// Revoked via OCSP responder
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp, _ := ocsp.CreateResponse(ca, ca, ocsp.Response{
			Status:       ocsp.Revoked,
			SerialNumber: leaf.SerialNumber,
			ThisUpdate:   time.Now().Add(-1 * time.Hour),
			NextUpdate:   time.Now().Add(1 * time.Hour),
			RevokedAt:    time.Now().Add(-30 * time.Minute),
		}, caKey)
		w.Write(resp) //nolint:errcheck // test handler response write
	}))
	defer srv.Close()

	leaf.OCSPServer = []string{srv.URL}
	leaf.CRLDistributionPoints = nil

	issues := Check(leaf, ca, nil, NewCRLCache())
	if len(issues) == 0 {
		t.Fatal("expected revocation issues, got none")
	}
	if !strings.Contains(issues[0], "CERT_REVOKED") {
		t.Errorf("expected CERT_REVOKED in issue, got %q", issues[0])
	}
}
