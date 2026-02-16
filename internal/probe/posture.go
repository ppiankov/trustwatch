package probe

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// EvaluatePosture checks TLS handshake parameters for weak configurations.
// Returns a list of human-readable issues found, or nil if posture is acceptable.
func EvaluatePosture(tlsVersion, cipherSuite uint16) []string {
	var issues []string

	if issue := checkTLSVersion(tlsVersion); issue != "" {
		issues = append(issues, issue)
	}
	if issue := checkCipherSuite(cipherSuite); issue != "" {
		issues = append(issues, issue)
	}

	return issues
}

// checkTLSVersion flags TLS versions older than 1.2.
func checkTLSVersion(v uint16) string {
	switch v {
	case tls.VersionSSL30: //nolint:staticcheck // deliberately checking deprecated version
		return "weak TLS version: SSL 3.0"
	case tls.VersionTLS10:
		return "weak TLS version: TLS 1.0"
	case tls.VersionTLS11:
		return "weak TLS version: TLS 1.1"
	default:
		return ""
	}
}

// checkCipherSuite flags insecure or weak cipher suites.
func checkCipherSuite(id uint16) string {
	if id == 0 {
		return ""
	}

	name := tls.CipherSuiteName(id)

	// Check against Go's insecure cipher suite list (RC4, 3DES, NULL, etc.)
	for _, cs := range tls.InsecureCipherSuites() {
		if cs.ID == id {
			reason := classifyInsecureCipher(name)
			return fmt.Sprintf("weak cipher: %s (%s)", name, reason)
		}
	}

	// CBC-mode ciphers are not in InsecureCipherSuites but are vulnerable
	// to padding oracle attacks (BEAST, Lucky13)
	if strings.Contains(name, "CBC") {
		return fmt.Sprintf("CBC-mode cipher: %s", name)
	}

	return ""
}

// classifyInsecureCipher returns a short reason why the cipher is insecure.
func classifyInsecureCipher(name string) string {
	switch {
	case strings.Contains(name, "RC4"):
		return "RC4"
	case strings.Contains(name, "3DES"):
		return "3DES"
	case strings.Contains(name, "NULL"):
		return "NULL"
	default:
		return "insecure"
	}
}
