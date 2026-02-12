package probe

import (
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
