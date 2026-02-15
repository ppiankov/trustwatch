package policy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ppiankov/trustwatch/internal/store"
)

// evalMinKeySize checks that a finding's key size meets the minimum threshold.
func evalMinKeySize(f *store.CertFinding, params map[string]string) (violated bool, reason string) {
	minStr := params["minBits"]
	if minStr == "" {
		return false, ""
	}
	minBits, err := strconv.Atoi(minStr)
	if err != nil {
		return false, ""
	}
	if f.KeySize > 0 && f.KeySize < minBits {
		return true, fmt.Sprintf("key size %d < minimum %d", f.KeySize, minBits)
	}
	return false, ""
}

// evalNoSHA1 checks that a finding doesn't use SHA-1 signatures.
func evalNoSHA1(f *store.CertFinding) (violated bool, reason string) {
	if strings.Contains(strings.ToUpper(f.SignatureAlgorithm), "SHA1") ||
		strings.Contains(strings.ToUpper(f.SignatureAlgorithm), "SHA-1") {
		return true, fmt.Sprintf("uses deprecated signature algorithm %s", f.SignatureAlgorithm)
	}
	return false, ""
}

// evalRequiredIssuer checks that a finding's issuer matches the required pattern.
func evalRequiredIssuer(f *store.CertFinding, params map[string]string) (violated bool, reason string) {
	required := params["issuer"]
	if required == "" {
		return false, ""
	}
	if !strings.Contains(f.Issuer, required) {
		return true, fmt.Sprintf("issuer %q does not match required %q", f.Issuer, required)
	}
	return false, ""
}

// evalNoSelfSigned checks that a finding is not self-signed (leaf only).
func evalNoSelfSigned(f *store.CertFinding) (violated bool, reason string) {
	if f.SelfSigned {
		return true, "certificate is self-signed"
	}
	return false, ""
}
