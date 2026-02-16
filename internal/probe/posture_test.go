package probe

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestEvaluatePosture_WeakTLSVersion(t *testing.T) {
	tests := []struct {
		wantSubstr string
		name       string
		version    uint16
	}{
		{name: "TLS 1.0", version: tls.VersionTLS10, wantSubstr: "weak TLS version: TLS 1.0"},
		{name: "TLS 1.1", version: tls.VersionTLS11, wantSubstr: "weak TLS version: TLS 1.1"},
		{name: "SSL 3.0", version: tls.VersionSSL30, wantSubstr: "weak TLS version: SSL 3.0"}, //nolint:staticcheck // testing deprecated version
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := EvaluatePosture(tt.version, 0)
			found := false
			for _, issue := range issues {
				if strings.Contains(issue, tt.wantSubstr) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected issue containing %q, got %v", tt.wantSubstr, issues)
			}
		})
	}
}

func TestEvaluatePosture_AcceptableTLSVersion(t *testing.T) {
	tests := []struct {
		name    string
		version uint16
	}{
		{"TLS 1.2", tls.VersionTLS12},
		{"TLS 1.3", tls.VersionTLS13},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := EvaluatePosture(tt.version, 0)
			for _, issue := range issues {
				if strings.Contains(issue, "weak TLS version") {
					t.Errorf("unexpected TLS version issue: %s", issue)
				}
			}
		})
	}
}

func TestEvaluatePosture_InsecureCipher(t *testing.T) {
	// Use actual insecure cipher IDs from Go's tls package
	for _, cs := range tls.InsecureCipherSuites() {
		t.Run(cs.Name, func(t *testing.T) {
			issues := EvaluatePosture(tls.VersionTLS12, cs.ID)
			found := false
			for _, issue := range issues {
				if strings.Contains(issue, "weak cipher:") {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected weak cipher issue for %s (0x%04x), got %v", cs.Name, cs.ID, issues)
			}
		})
	}
}

func TestEvaluatePosture_SecureCipher(t *testing.T) {
	// TLS_AES_128_GCM_SHA256 is a TLS 1.3 cipher — always secure
	issues := EvaluatePosture(tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256)
	if len(issues) != 0 {
		t.Errorf("expected no issues for TLS 1.3 + AES-128-GCM, got %v", issues)
	}
}

func TestEvaluatePosture_CBCCipher(t *testing.T) {
	// TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA is in CipherSuites() (not insecure list)
	// but uses CBC mode — vulnerable to padding oracle attacks
	id := tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	issues := EvaluatePosture(tls.VersionTLS12, id)
	found := false
	for _, issue := range issues {
		if strings.Contains(issue, "CBC-mode cipher") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected CBC-mode cipher issue for 0x%04x, got %v", id, issues)
	}
}

func TestEvaluatePosture_ZeroValues(t *testing.T) {
	issues := EvaluatePosture(0, 0)
	if len(issues) != 0 {
		t.Errorf("expected no issues for zero values, got %v", issues)
	}
}

func TestEvaluatePosture_CleanHandshake(t *testing.T) {
	// TLS 1.2 + ECDHE-RSA-AES128-GCM-SHA256 = no issues
	issues := EvaluatePosture(tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	if len(issues) != 0 {
		t.Errorf("expected no issues for TLS 1.2 + AES-GCM, got %v", issues)
	}
}
