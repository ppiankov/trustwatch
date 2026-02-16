// Package revocation checks certificate revocation status via OCSP and CRL.
package revocation

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

const ocspTimeout = 5 * time.Second

// CheckOCSP checks revocation status via OCSP.
// Tries the stapled response first, then queries AIA OCSP responders.
func CheckOCSP(cert, issuer *x509.Certificate, staple []byte) *Result {
	if len(staple) > 0 {
		if r := checkStaple(staple, issuer); r != nil {
			return r
		}
		// Staple was good — cert is not revoked
		return nil
	}

	// No staple — query OCSP responder if available
	if len(cert.OCSPServer) == 0 {
		return nil
	}

	return queryOCSP(cert, issuer)
}

func checkStaple(staple []byte, issuer *x509.Certificate) *Result {
	resp, err := ocsp.ParseResponse(staple, issuer)
	if err != nil {
		return &Result{
			Status: StatusStapleInvalid,
			Detail: fmt.Sprintf("OCSP staple parse error: %v", err),
		}
	}

	if !resp.NextUpdate.IsZero() && resp.NextUpdate.Before(time.Now()) {
		return &Result{
			Status: StatusStapleInvalid,
			Detail: fmt.Sprintf("OCSP staple expired at %s", resp.NextUpdate.UTC().Format(time.RFC3339)),
		}
	}

	if resp.Status == ocsp.Revoked {
		return &Result{
			Status: StatusRevoked,
			Detail: "OCSP staple: certificate revoked",
		}
	}

	if resp.Status == ocsp.Good {
		return nil
	}

	// Unknown or other status
	return &Result{
		Status: StatusUnreachable,
		Detail: fmt.Sprintf("OCSP staple status: %d", resp.Status),
	}
}

func queryOCSP(cert, issuer *x509.Certificate) *Result {
	reqBytes, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return &Result{
			Status: StatusUnreachable,
			Detail: fmt.Sprintf("OCSP request creation failed: %v", err),
		}
	}

	client := &http.Client{Timeout: ocspTimeout}
	httpResp, err := client.Post(cert.OCSPServer[0], "application/ocsp-request", bytes.NewReader(reqBytes))
	if err != nil {
		return &Result{
			Status: StatusUnreachable,
			Detail: fmt.Sprintf("OCSP responder at %s: %v", cert.OCSPServer[0], err),
		}
	}
	defer httpResp.Body.Close() //nolint:errcheck // read-only check

	respBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return &Result{
			Status: StatusUnreachable,
			Detail: fmt.Sprintf("OCSP response read error: %v", err),
		}
	}

	resp, err := ocsp.ParseResponse(respBytes, issuer)
	if err != nil {
		return &Result{
			Status: StatusUnreachable,
			Detail: fmt.Sprintf("OCSP response parse error: %v", err),
		}
	}

	if resp.Status == ocsp.Revoked {
		return &Result{
			Status: StatusRevoked,
			Detail: fmt.Sprintf("OCSP confirms revocation (responder: %s)", cert.OCSPServer[0]),
		}
	}

	return nil
}
