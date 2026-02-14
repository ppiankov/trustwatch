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

// Result holds the outcome of a TLS probe.
type Result struct {
	Cert     *x509.Certificate
	Chain    []*x509.Certificate
	ProbeOK  bool
	ProbeErr string
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

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	rawConn, err := dialFn(ctx, "tcp", hostport)
	if err != nil {
		return Result{ProbeOK: false, ProbeErr: err.Error()}
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // we check expiry, not trust chain
	})

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close() //nolint:errcheck // best-effort cleanup on handshake failure
		return Result{ProbeOK: false, ProbeErr: err.Error()}
	}
	defer tlsConn.Close() //nolint:errcheck // read-only probe, close error is unactionable

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return Result{ProbeOK: false, ProbeErr: "no peer certificates presented"}
	}

	return Result{
		Cert:    state.PeerCertificates[0],
		Chain:   state.PeerCertificates,
		ProbeOK: true,
	}
}

// FormatTarget builds a probe URL from host:port and optional SNI.
func FormatTarget(hostport, sni string) string {
	if sni == "" {
		return "tcp://" + hostport
	}
	return fmt.Sprintf("tcp://%s?sni=%s", hostport, url.QueryEscape(sni))
}
