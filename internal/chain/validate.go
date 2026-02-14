// Package chain validates X.509 certificate chains for trust issues.
package chain

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// ValidationResult holds the outcome of chain validation.
type ValidationResult struct {
	Errors []string
	Chain  []*x509.Certificate
}

// ValidateChain checks a certificate chain for common trust issues.
// chain[0] is the leaf. hostname is optional; if non-empty, SAN matching is checked.
func ValidateChain(chain []*x509.Certificate, hostname string, now time.Time) ValidationResult {
	result := ValidationResult{Chain: chain}
	if len(chain) == 0 {
		return result
	}

	leaf := chain[0]

	// 1. Self-signed leaf detection
	if isSelfSigned(leaf) && !leaf.IsCA {
		result.Errors = append(result.Errors, "leaf certificate is self-signed")
	}

	// 2. Expired intermediates
	for i := 1; i < len(chain); i++ {
		c := chain[i]
		if c.NotAfter.Before(now) {
			result.Errors = append(result.Errors, fmt.Sprintf("intermediate expired: %s", subjectName(c)))
		} else if c.NotBefore.After(now) {
			result.Errors = append(result.Errors, fmt.Sprintf("intermediate not yet valid: %s", subjectName(c)))
		}
	}

	// 3. Misordered bundle detection
	if len(chain) > 1 {
		for i := 0; i < len(chain)-1; i++ {
			if chain[i].Issuer.String() != chain[i+1].Subject.String() {
				result.Errors = append(result.Errors, fmt.Sprintf("chain misordered at position %d", i))
				break // report first mismatch only
			}
		}
	}

	// 4. Broken chain (verify leaf against intermediates + roots)
	if err := verifyChainTrust(leaf, chain[1:], now); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("chain verification failed: %v", err))
	}

	// 5. Wrong SANs
	if hostname != "" {
		if err := leaf.VerifyHostname(hostname); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("certificate does not cover hostname %q", hostname))
		}
	}

	return result
}

// verifyChainTrust uses x509.Verify to check the leaf against the rest of the chain.
// Returns nil if the chain has fewer than 1 cert or verification succeeds.
func verifyChainTrust(leaf *x509.Certificate, rest []*x509.Certificate, now time.Time) error {
	if len(rest) == 0 {
		return nil
	}
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	for _, c := range rest {
		if c.IsCA && c.Issuer.String() == c.Subject.String() {
			roots.AddCert(c)
		} else {
			intermediates.AddCert(c)
		}
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

// ParsePEMBundle decodes all CERTIFICATE PEM blocks from data.
func ParsePEMBundle(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return certs, fmt.Errorf("parsing certificate at position %d: %w", len(certs), err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no PEM certificate blocks found")
	}
	return certs, nil
}

// isSelfSigned checks whether a certificate is self-signed.
func isSelfSigned(c *x509.Certificate) bool {
	if c.Issuer.String() != c.Subject.String() {
		return false
	}
	// If AuthorityKeyId is present, it must match SubjectKeyId
	if len(c.AuthorityKeyId) > 0 && len(c.SubjectKeyId) > 0 {
		return bytes.Equal(c.AuthorityKeyId, c.SubjectKeyId)
	}
	// No AKI means likely self-signed (common in self-signed certs)
	return true
}

// subjectName returns a human-readable name for a certificate.
func subjectName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}
