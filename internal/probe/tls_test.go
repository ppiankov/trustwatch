package probe

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestFormatTarget(t *testing.T) {
	tests := []struct {
		name     string
		hostport string
		sni      string
		want     string
	}{
		{
			name:     "without SNI",
			hostport: "my-svc.ns.svc:443",
			sni:      "",
			want:     "tcp://my-svc.ns.svc:443",
		},
		{
			name:     "with SNI",
			hostport: "10.0.0.1:8443",
			sni:      "api.internal",
			want:     "tcp://10.0.0.1:8443?sni=api.internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatTarget(tt.hostport, tt.sni)
			if got != tt.want {
				t.Errorf("FormatTarget(%q, %q) = %q, want %q", tt.hostport, tt.sni, got, tt.want)
			}
		})
	}
}

func TestProbeUnsupportedScheme(t *testing.T) {
	result := Probe("ftp://example.com:21")
	if result.ProbeOK {
		t.Error("expected probe to fail for unsupported scheme")
	}
	if result.ProbeErr == "" {
		t.Error("expected error message for unsupported scheme")
	}
}

func TestProbeInvalidURL(t *testing.T) {
	result := Probe("://invalid")
	if result.ProbeOK {
		t.Error("expected probe to fail for invalid URL")
	}
}

func TestProbeUnreachable(t *testing.T) {
	// Use an address that should fail quickly (localhost, unlikely port)
	result := Probe("tcp://127.0.0.1:19999")
	if result.ProbeOK {
		t.Error("expected probe to fail for unreachable endpoint")
	}
	if result.ProbeErr == "" {
		t.Error("expected error message for unreachable endpoint")
	}
}

func TestProbeWithDialer_DialError(t *testing.T) {
	dialFn := func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, errors.New("socks5: connection refused")
	}

	result := ProbeWithDialer("tcp://example.com:443", dialFn)
	if result.ProbeOK {
		t.Error("expected probe to fail when dial returns error")
	}
	if result.ProbeErr != "socks5: connection refused" {
		t.Errorf("expected dial error message, got %q", result.ProbeErr)
	}
}

func TestProbeWithDialer_InvalidURL(t *testing.T) {
	dialFn := func(_ context.Context, _, _ string) (net.Conn, error) {
		t.Fatal("dial should not be called for invalid URL")
		return nil, nil
	}

	result := ProbeWithDialer("://invalid", dialFn)
	if result.ProbeOK {
		t.Error("expected probe to fail for invalid URL")
	}
}

func TestProbeWithDialer_UnsupportedScheme(t *testing.T) {
	dialFn := func(_ context.Context, _, _ string) (net.Conn, error) {
		t.Fatal("dial should not be called for unsupported scheme")
		return nil, nil
	}

	result := ProbeWithDialer("ftp://example.com:21", dialFn)
	if result.ProbeOK {
		t.Error("expected probe to fail for unsupported scheme")
	}
}

func TestProbeWithDialer_DialerReceivesCorrectAddr(t *testing.T) {
	var gotNetwork, gotAddr string
	dialFn := func(_ context.Context, network, addr string) (net.Conn, error) {
		gotNetwork = network
		gotAddr = addr
		return nil, errors.New("test: expected error")
	}

	ProbeWithDialer("tcp://my-svc.ns.svc:8443", dialFn)

	if gotNetwork != "tcp" {
		t.Errorf("expected network %q, got %q", "tcp", gotNetwork)
	}
	if gotAddr != "my-svc.ns.svc:8443" {
		t.Errorf("expected addr %q, got %q", "my-svc.ns.svc:8443", gotAddr)
	}
}
