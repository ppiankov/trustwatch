package revocation

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"
)

const crlTimeout = 10 * time.Second

// CheckCRL checks if a certificate's serial appears in any CRL distribution point.
func CheckCRL(cert *x509.Certificate, cache *CRLCache) *Result {
	if len(cert.CRLDistributionPoints) == 0 {
		return nil
	}

	for _, dp := range cert.CRLDistributionPoints {
		crl := cache.Get(dp)
		if crl == nil {
			var err error
			crl, err = fetchCRL(dp)
			if err != nil {
				return &Result{
					Status: StatusUnreachable,
					Detail: fmt.Sprintf("CRL fetch from %s: %v", dp, err),
				}
			}
			cache.Set(dp, crl)
		}

		// Check if CRL is stale
		if !crl.NextUpdate.IsZero() && crl.NextUpdate.Before(time.Now()) {
			return &Result{
				Status: StatusCRLStale,
				Detail: fmt.Sprintf("CRL from %s expired %s", dp, crl.NextUpdate.UTC().Format(time.RFC3339)),
			}
		}

		// Check if cert serial is in the revoked list
		for _, revoked := range crl.RevokedCertificateEntries {
			if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
				return &Result{
					Status: StatusRevoked,
					Detail: fmt.Sprintf("CRL from %s: certificate serial %s revoked", dp, cert.SerialNumber.Text(16)),
				}
			}
		}
	}

	return nil
}

func fetchCRL(url string) (*x509.RevocationList, error) {
	client := &http.Client{Timeout: crlTimeout}
	resp, err := client.Get(url) //nolint:gosec // CRL distribution points are from the certificate's X.509 extension
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only fetch

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
	if err != nil {
		return nil, fmt.Errorf("reading CRL: %w", err)
	}

	return x509.ParseRevocationList(data)
}
