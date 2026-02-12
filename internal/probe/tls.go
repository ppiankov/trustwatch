package probe

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

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

	dialer := &net.Dialer{Timeout: defaultTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", hostport, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // we check expiry, not trust chain
	})
	if err != nil {
		return Result{ProbeOK: false, ProbeErr: err.Error()}
	}
	defer conn.Close()

	state := conn.ConnectionState()
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
