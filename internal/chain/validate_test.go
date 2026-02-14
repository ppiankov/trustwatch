package chain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCA generates a self-signed CA certificate and key.
func testCA(t *testing.T, cn string, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// testIntermediate generates an intermediate CA signed by parent.
func testIntermediate(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// testLeaf generates a leaf certificate signed by parent.
func testLeaf(t *testing.T, cn string, dnsNames []string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// testSelfSignedLeaf generates a self-signed non-CA leaf certificate.
func testSelfSignedLeaf(t *testing.T, cn string, dnsNames []string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// certToPEM encodes a certificate as PEM bytes.
func certToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func validChain(t *testing.T) (root, inter, leaf *x509.Certificate) {
	t.Helper()
	now := time.Now()
	var rootKey, interKey *ecdsa.PrivateKey
	root, rootKey = testCA(t, "Root CA", now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	inter, interKey = testIntermediate(t, "Intermediate CA", root, rootKey, now.Add(-time.Hour), now.Add(5*365*24*time.Hour))
	leaf = testLeaf(t, "leaf.example.com", []string{"leaf.example.com", "*.example.com"}, inter, interKey, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	return root, inter, leaf
}

func TestValidateChain_ValidChain(t *testing.T) {
	root, inter, leaf := validChain(t)
	result := ValidateChain([]*x509.Certificate{leaf, inter, root}, "", time.Now())
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}
}

func TestValidateChain_ValidChainWithHostname(t *testing.T) {
	root, inter, leaf := validChain(t)
	result := ValidateChain([]*x509.Certificate{leaf, inter, root}, "leaf.example.com", time.Now())
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %v", result.Errors)
	}
}

func TestValidateChain_SelfSignedLeaf(t *testing.T) {
	leaf := testSelfSignedLeaf(t, "self-signed.example.com", []string{"self-signed.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	result := ValidateChain([]*x509.Certificate{leaf}, "", time.Now())

	found := false
	for _, e := range result.Errors {
		if e == "leaf certificate is self-signed" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected self-signed error, got %v", result.Errors)
	}
}

func TestValidateChain_SelfSignedCA(t *testing.T) {
	// A self-signed CA should NOT trigger the self-signed leaf error
	ca, _ := testCA(t, "Root CA", time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	result := ValidateChain([]*x509.Certificate{ca}, "", time.Now())

	for _, e := range result.Errors {
		if e == "leaf certificate is self-signed" {
			t.Errorf("self-signed CA should not trigger leaf self-signed error, got %v", result.Errors)
		}
	}
}

func TestValidateChain_ExpiredIntermediate(t *testing.T) {
	now := time.Now()
	root, rootKey := testCA(t, "Root CA", now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	// Intermediate expired yesterday
	inter, interKey := testIntermediate(t, "Expired Intermediate", root, rootKey, now.Add(-2*365*24*time.Hour), now.Add(-24*time.Hour))
	leaf := testLeaf(t, "leaf.example.com", []string{"leaf.example.com"}, inter, interKey, now.Add(-time.Hour), now.Add(90*24*time.Hour))

	result := ValidateChain([]*x509.Certificate{leaf, inter, root}, "", now)

	found := false
	for _, e := range result.Errors {
		if e == "intermediate expired: Expired Intermediate" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected expired intermediate error, got %v", result.Errors)
	}
}

func TestValidateChain_MisorderedBundle(t *testing.T) {
	root, inter, leaf := validChain(t)
	// Put intermediate before leaf (wrong order)
	result := ValidateChain([]*x509.Certificate{inter, leaf, root}, "", time.Now())

	found := false
	for _, e := range result.Errors {
		if e == "chain misordered at position 0" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected misordered error, got %v", result.Errors)
	}
}

func TestValidateChain_BrokenChain(t *testing.T) {
	now := time.Now()
	// Create two unrelated CAs
	root, rootKey := testCA(t, "Root CA", now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	unrelatedCA, unrelatedKey := testCA(t, "Unrelated CA", now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	inter, _ := testIntermediate(t, "Intermediate CA", root, rootKey, now.Add(-time.Hour), now.Add(5*365*24*time.Hour))
	// Leaf signed by unrelated CA — chain is broken
	leaf := testLeaf(t, "leaf.example.com", []string{"leaf.example.com"}, unrelatedCA, unrelatedKey, now.Add(-time.Hour), now.Add(90*24*time.Hour))

	result := ValidateChain([]*x509.Certificate{leaf, inter, root}, "", now)

	found := false
	for _, e := range result.Errors {
		if strings.HasPrefix(e, "chain verification failed:") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected chain verification error, got %v", result.Errors)
	}
}

func TestValidateChain_WrongSANs(t *testing.T) {
	root, inter, leaf := validChain(t)
	// Leaf has SANs for *.example.com but we check wrong.example.org
	result := ValidateChain([]*x509.Certificate{leaf, inter, root}, "wrong.example.org", time.Now())

	found := false
	for _, e := range result.Errors {
		if e == `certificate does not cover hostname "wrong.example.org"` {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected SAN mismatch error, got %v", result.Errors)
	}
}

func TestValidateChain_WildcardSAN(t *testing.T) {
	root, inter, leaf := validChain(t)
	// *.example.com should match sub.example.com
	result := ValidateChain([]*x509.Certificate{leaf, inter, root}, "sub.example.com", time.Now())
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors for wildcard match, got %v", result.Errors)
	}
}

func TestValidateChain_EmptyChain(t *testing.T) {
	result := ValidateChain(nil, "", time.Now())
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors for empty chain, got %v", result.Errors)
	}
}

func TestParsePEMBundle_MultipleCerts(t *testing.T) {
	root, inter, leaf := validChain(t)
	bundle := append(certToPEM(leaf), certToPEM(inter)...)
	bundle = append(bundle, certToPEM(root)...)

	certs, err := ParsePEMBundle(bundle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 3 {
		t.Errorf("expected 3 certs, got %d", len(certs))
	}
}

func TestParsePEMBundle_SingleCert(t *testing.T) {
	root, _, _ := validChain(t)
	certs, err := ParsePEMBundle(certToPEM(root))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert, got %d", len(certs))
	}
}

func TestParsePEMBundle_NoPEM(t *testing.T) {
	_, err := ParsePEMBundle([]byte("not a pem"))
	if err == nil {
		t.Error("expected error for non-PEM data")
	}
}

func TestParsePEMBundle_MixedBlocks(t *testing.T) {
	root, _, _ := validChain(t)
	// Add a non-CERTIFICATE block
	privBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("fake")})
	bundle := make([]byte, 0, len(privBlock)+256)
	bundle = append(bundle, privBlock...)
	bundle = append(bundle, certToPEM(root)...)

	certs, err := ParsePEMBundle(bundle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert (skipping non-CERTIFICATE block), got %d", len(certs))
	}
}
