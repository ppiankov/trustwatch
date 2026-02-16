package discovery

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"time"

	"github.com/ppiankov/trustwatch/internal/chain"
	"github.com/ppiankov/trustwatch/internal/probe"
	"github.com/ppiankov/trustwatch/internal/store"
)

// applyProbeChainValidation runs chain and posture validation on a probe result and populates finding fields.
func applyProbeChainValidation(finding *store.CertFinding, pr probe.Result, hostname string) {
	finding.ChainLen = len(pr.Chain)
	if len(pr.Chain) > 0 {
		applyCertMetadata(finding, pr.Chain[0], pr.Chain)
	}
	result := chain.ValidateChain(pr.Chain, hostname, time.Now())
	if len(result.Errors) > 0 {
		finding.ChainErrors = result.Errors
	}

	// TLS posture from handshake metadata
	if pr.TLSVersion != 0 {
		finding.TLSVersion = tls.VersionName(pr.TLSVersion)
	}
	if pr.CipherSuite != 0 {
		finding.CipherSuite = tls.CipherSuiteName(pr.CipherSuite)
	}
	if issues := probe.EvaluatePosture(pr.TLSVersion, pr.CipherSuite); len(issues) > 0 {
		finding.PostureIssues = issues
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
