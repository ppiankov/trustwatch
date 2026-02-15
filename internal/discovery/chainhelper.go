package discovery

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"net"
	"net/url"
	"time"

	"github.com/ppiankov/trustwatch/internal/chain"
	"github.com/ppiankov/trustwatch/internal/store"
)

// applyProbeChainValidation runs chain validation on a probe result and populates finding fields.
func applyProbeChainValidation(finding *store.CertFinding, certs []*x509.Certificate, hostname string) {
	finding.ChainLen = len(certs)
	if len(certs) > 0 {
		applyCertMetadata(finding, certs[0], certs)
	}
	result := chain.ValidateChain(certs, hostname, time.Now())
	if len(result.Errors) > 0 {
		finding.ChainErrors = result.Errors
	}
}

// applyPEMChainValidation parses a PEM bundle, runs chain validation, and populates finding fields.
// Returns the leaf certificate for metadata extraction, or nil on error.
func applyPEMChainValidation(finding *store.CertFinding, pemData []byte, hostname string) *x509.Certificate {
	certs, err := chain.ParsePEMBundle(pemData)
	if err != nil {
		finding.ProbeOK = false
		finding.ProbeErr = err.Error()
		return nil
	}
	finding.ChainLen = len(certs)
	applyCertMetadata(finding, certs[0], certs)
	result := chain.ValidateChain(certs, hostname, time.Now())
	if len(result.Errors) > 0 {
		finding.ChainErrors = result.Errors
	}
	return certs[0]
}

// applyCertMetadata populates key algorithm, key size, signature algorithm, and self-signed
// status from a leaf certificate.
func applyCertMetadata(finding *store.CertFinding, leaf *x509.Certificate, certs []*x509.Certificate) {
	finding.SignatureAlgorithm = leaf.SignatureAlgorithm.String()

	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		finding.KeyAlgorithm = "RSA"
		finding.KeySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		finding.KeyAlgorithm = "ECDSA"
		finding.KeySize = pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		finding.KeyAlgorithm = "Ed25519"
		finding.KeySize = 256
	}

	// Self-signed: single cert in chain with issuer == subject
	if len(certs) == 1 {
		finding.SelfSigned = bytes.Equal(leaf.RawIssuer, leaf.RawSubject)
	}
}

// extractHostFromTarget extracts the hostname from a host:port target string or URL.
func extractHostFromTarget(target string) string {
	// Try URL parsing first (for https://host:port or tcp://host:port?sni=x)
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host, _, err := net.SplitHostPort(u.Host)
		if err != nil {
			return u.Host
		}
		// Prefer SNI query param if present
		if sni := u.Query().Get("sni"); sni != "" {
			return sni
		}
		return host
	}
	// Bare host:port
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	return host
}
