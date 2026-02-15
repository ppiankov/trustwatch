package policy

import (
	"testing"

	"github.com/ppiankov/trustwatch/internal/store"
)

func TestEvalMinKeySize_TooSmall(t *testing.T) {
	f := &store.CertFinding{KeyAlgorithm: "RSA", KeySize: 1024}
	violated, reason := evalMinKeySize(f, map[string]string{"minBits": "2048"})
	if !violated {
		t.Error("expected violation for RSA-1024 < 2048")
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestEvalMinKeySize_OK(t *testing.T) {
	f := &store.CertFinding{KeyAlgorithm: "RSA", KeySize: 2048}
	violated, _ := evalMinKeySize(f, map[string]string{"minBits": "2048"})
	if violated {
		t.Error("did not expect violation for RSA-2048 >= 2048")
	}
}

func TestEvalMinKeySize_NoKeySize(t *testing.T) {
	f := &store.CertFinding{KeyAlgorithm: "RSA", KeySize: 0}
	violated, _ := evalMinKeySize(f, map[string]string{"minBits": "2048"})
	if violated {
		t.Error("did not expect violation when key size is 0")
	}
}

func TestEvalNoSHA1_Violated(t *testing.T) {
	f := &store.CertFinding{SignatureAlgorithm: "SHA1-RSA"}
	violated, _ := evalNoSHA1(f)
	if !violated {
		t.Error("expected violation for SHA1-RSA")
	}
}

func TestEvalNoSHA1_OK(t *testing.T) {
	f := &store.CertFinding{SignatureAlgorithm: "SHA256-RSA"}
	violated, _ := evalNoSHA1(f)
	if violated {
		t.Error("did not expect violation for SHA256-RSA")
	}
}

func TestEvalRequiredIssuer_Wrong(t *testing.T) {
	f := &store.CertFinding{Issuer: "CN=Bad CA"}
	violated, _ := evalRequiredIssuer(f, map[string]string{"issuer": "Good CA"})
	if !violated {
		t.Error("expected violation for wrong issuer")
	}
}

func TestEvalRequiredIssuer_OK(t *testing.T) {
	f := &store.CertFinding{Issuer: "CN=Good CA,O=Corp"}
	violated, _ := evalRequiredIssuer(f, map[string]string{"issuer": "Good CA"})
	if violated {
		t.Error("did not expect violation for matching issuer")
	}
}

func TestEvalNoSelfSigned_Violated(t *testing.T) {
	f := &store.CertFinding{SelfSigned: true}
	violated, _ := evalNoSelfSigned(f)
	if !violated {
		t.Error("expected violation for self-signed cert")
	}
}

func TestEvalNoSelfSigned_OK(t *testing.T) {
	f := &store.CertFinding{SelfSigned: false}
	violated, _ := evalNoSelfSigned(f)
	if violated {
		t.Error("did not expect violation for CA-signed cert")
	}
}
