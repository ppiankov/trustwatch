package ct

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ppiankov/trustwatch/internal/store"
)

func mockServer(entries []Entry, status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(entries) //nolint:errcheck // test handler
	}))
}

func TestFetchCerts_ValidResponse(t *testing.T) {
	entries := []Entry{
		{ID: 1, SerialNumber: "AAA", CommonName: "www.example.com", IssuerName: "CN=R3"},
		{ID: 2, SerialNumber: "BBB", CommonName: "api.example.com", IssuerName: "CN=R3"},
	}
	srv := mockServer(entries, http.StatusOK)
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	got, err := c.FetchCerts(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].SerialNumber != "AAA" {
		t.Errorf("expected serial AAA, got %s", got[0].SerialNumber)
	}
}

func TestFetchCerts_EmptyResponse(t *testing.T) {
	srv := mockServer([]Entry{}, http.StatusOK)
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	got, err := c.FetchCerts(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 entries, got %d", len(got))
	}
}

func TestFetchCerts_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	_, err := c.FetchCerts(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error for 500 status")
	}
}

func TestFetchCerts_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json")) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	_, err := c.FetchCerts(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestFetchCerts_Deduplication(t *testing.T) {
	entries := []Entry{
		{ID: 1, SerialNumber: "AAA", CommonName: "www.example.com"},
		{ID: 2, SerialNumber: "AAA", CommonName: "www.example.com"}, // duplicate serial
		{ID: 3, SerialNumber: "BBB", CommonName: "api.example.com"},
	}
	srv := mockServer(entries, http.StatusOK)
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	got, err := c.FetchCerts(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 deduplicated entries, got %d", len(got))
	}
}

func TestCheck_UnknownCert(t *testing.T) {
	entries := []Entry{
		{SerialNumber: "UNKNOWN1", CommonName: "rogue.example.com", IssuerName: "CN=R3"},
	}
	knownSerials := map[string]bool{"KNOWN1": true}
	findings := Check(entries, knownSerials, nil)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].FindingType != FindingCTUnknown {
		t.Errorf("expected finding type %s, got %s", FindingCTUnknown, findings[0].FindingType)
	}
	if findings[0].Severity != store.SeverityWarn {
		t.Errorf("expected warn severity, got %s", findings[0].Severity)
	}
	if findings[0].Source != store.SourceCT {
		t.Errorf("expected source ct, got %s", findings[0].Source)
	}
}

func TestCheck_KnownCert(t *testing.T) {
	entries := []Entry{
		{SerialNumber: "KNOWN1", CommonName: "www.example.com", IssuerName: "CN=R3"},
	}
	knownSerials := map[string]bool{"KNOWN1": true}
	findings := Check(entries, knownSerials, nil)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for known cert, got %d", len(findings))
	}
}

func TestCheck_RogueIssuer(t *testing.T) {
	entries := []Entry{
		{SerialNumber: "KNOWN1", CommonName: "www.example.com", IssuerName: "CN=Evil CA, O=BadCorp"},
	}
	knownSerials := map[string]bool{"KNOWN1": true}
	allowedIssuers := []string{"Let's Encrypt", "DigiCert"}
	findings := Check(entries, knownSerials, allowedIssuers)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].FindingType != FindingCTRogue {
		t.Errorf("expected finding type %s, got %s", FindingCTRogue, findings[0].FindingType)
	}
	if findings[0].Severity != store.SeverityCritical {
		t.Errorf("expected critical severity, got %s", findings[0].Severity)
	}
}

func TestCheck_AllowedIssuer(t *testing.T) {
	entries := []Entry{
		{SerialNumber: "KNOWN1", CommonName: "www.example.com", IssuerName: "C=US, O=Let's Encrypt, CN=R3"},
	}
	knownSerials := map[string]bool{"KNOWN1": true}
	allowedIssuers := []string{"Let's Encrypt"}
	findings := Check(entries, knownSerials, allowedIssuers)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for allowed issuer, got %d", len(findings))
	}
}

func TestCheck_BothUnknownAndRogue(t *testing.T) {
	entries := []Entry{
		{SerialNumber: "UNKNOWN1", CommonName: "shadow.example.com", IssuerName: "CN=Evil CA"},
	}
	knownSerials := map[string]bool{"KNOWN1": true}
	allowedIssuers := []string{"Let's Encrypt"}
	findings := Check(entries, knownSerials, allowedIssuers)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (unknown + rogue), got %d", len(findings))
	}
	types := map[string]bool{}
	for _, f := range findings {
		types[f.FindingType] = true
	}
	if !types[FindingCTUnknown] {
		t.Error("expected CT_UNKNOWN_CERT finding")
	}
	if !types[FindingCTRogue] {
		t.Error("expected CT_ROGUE_ISSUER finding")
	}
}

func TestCheck_NoAllowedIssuers_SkipsRogueCheck(t *testing.T) {
	entries := []Entry{
		{SerialNumber: "KNOWN1", CommonName: "www.example.com", IssuerName: "CN=Any CA"},
	}
	knownSerials := map[string]bool{"KNOWN1": true}
	// Empty allowedIssuers means skip rogue issuer check
	findings := Check(entries, knownSerials, nil)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no allowed issuers configured, got %d", len(findings))
	}
}

func TestCheck_DNSNamesSplit(t *testing.T) {
	entries := []Entry{
		{SerialNumber: "UNKNOWN1", CommonName: "www.example.com",
			NameValue:  "www.example.com\nexample.com\napi.example.com",
			IssuerName: "CN=R3"},
	}
	findings := Check(entries, map[string]bool{}, nil)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if len(findings[0].DNSNames) != 3 {
		t.Errorf("expected 3 DNS names, got %d: %v", len(findings[0].DNSNames), findings[0].DNSNames)
	}
}

func TestCheck_EmptyEntries(t *testing.T) {
	findings := Check(nil, map[string]bool{"KNOWN1": true}, []string{"Let's Encrypt"})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty entries, got %d", len(findings))
	}
}

func TestDedup(t *testing.T) {
	entries := []Entry{
		{SerialNumber: "A"}, {SerialNumber: "B"}, {SerialNumber: "A"}, {SerialNumber: "C"}, {SerialNumber: "B"},
	}
	got := dedup(entries)
	if len(got) != 3 {
		t.Errorf("expected 3 unique entries, got %d", len(got))
	}
}
