// Package probe provides TLS handshake probing for certificate inspection.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// DialContextFunc is the signature used by ProbeWithDialer to establish TCP connections.
type DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

const defaultTimeout = 5 * time.Second

// Retry defaults for transient connection errors.
var (
	retryMax   = 2
	retryDelay = time.Second
)

// Result holds the outcome of a TLS probe.
type Result struct {
	Cert         *x509.Certificate
	ProbeErr     string
	Chain        []*x509.Certificate
	OCSPResponse []byte
	RetryCount   int
	TLSVersion   uint16
	CipherSuite  uint16
	ProbeOK      bool
}

// Probe connects to a TLS endpoint and returns the presented certificate.
// Accepts urls like https://host:port or tcp://host:port?sni=name.
func Probe(raw string) Result {
	return ProbeWithDialer(raw, (&net.Dialer{Timeout: defaultTimeout}).DialContext)
}

// ProbeWithDialer is like Probe but uses the provided dial function for the
// underlying TCP connection. This allows routing through a SOCKS5 proxy or
// ProbeWithDialer performs a TLS handshake using a custom dial function.
// This enables routing probes through a SOCKS5 tunnel or any other custom transport.
//
//nolint:revive // "ProbeWithDialer" is clearer than "WithDialer" despite stutter
func ProbeWithDialer(raw string, dialFn DialContextFunc) Result {
	u, err := url.Parse(raw)
	if err != nil {
		return Result{ProbeOK: false, ProbeErr: err.Error()}
	}

	hostport := u.Host
	sni := u.Query().Get("sni")
	if sni == "" {
		sni = strings.Split(u.Host, ":")[0]
	}

	switch u.Scheme {
	case "https", "tcp":
		// supported
	default:
		return Result{ProbeOK: false, ProbeErr: fmt.Sprintf("unsupported scheme: %s (use https or tcp)", u.Scheme)}
	}

	// Retry loop: only connection (dial) errors are retried.
	// TLS handshake failures are definitive and returned immediately.
	var lastDialErr error
	for attempt := 0; attempt <= retryMax; attempt++ {
		if attempt > 0 {
			time.Sleep(retryDelay * time.Duration(1<<uint(attempt-1)))
		}

		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)

		rawConn, dialErr := dialFn(ctx, "tcp", hostport)
		if dialErr != nil {
			cancel()
			lastDialErr = dialErr
			continue
		}

		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true, // we check expiry, not trust chain
		})

		if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
			rawConn.Close() //nolint:errcheck // best-effort cleanup on handshake failure
			cancel()
			return Result{ProbeOK: false, ProbeErr: hsErr.Error(), RetryCount: attempt}
		}

		state := tlsConn.ConnectionState()
		tlsConn.Close() //nolint:errcheck // read-only probe, close error is unactionable
		cancel()

		if len(state.PeerCertificates) == 0 {
			return Result{ProbeOK: false, ProbeErr: "no peer certificates presented", RetryCount: attempt}
		}

		return Result{
			Cert:         state.PeerCertificates[0],
			Chain:        state.PeerCertificates,
			OCSPResponse: state.OCSPResponse,
			TLSVersion:   state.Version,
			CipherSuite:  state.CipherSuite,
			ProbeOK:      true,
			RetryCount:   attempt,
		}
	}

	return Result{ProbeOK: false, ProbeErr: lastDialErr.Error(), RetryCount: retryMax}
}

// FormatTarget builds a probe URL from host:port and optional SNI.
func FormatTarget(hostport, sni string) string {
	if sni == "" {
		return "tcp://" + hostport
	}
	return fmt.Sprintf("tcp://%s?sni=%s", hostport, url.QueryEscape(sni))
}
