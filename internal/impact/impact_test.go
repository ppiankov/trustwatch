package impact

import (
	"testing"

	"github.com/ppiankov/trustwatch/internal/store"
)

func testFindings() []store.CertFinding {
	return []store.CertFinding{
		{
			Name:        "leaf-1",
			Subject:     "CN=leaf-1.example.com",
			Issuer:      "CN=Intermediate CA",
			IssuerChain: []string{"CN=Intermediate CA", "CN=Root CA"},
			Serial:      "AAA111",
			Namespace:   "default",
			Cluster:     "prod",
			Source:      store.SourceWebhook,
			Severity:    store.SeverityCritical,
			ProbeOK:     true,
		},
		{
			Name:        "leaf-2",
			Subject:     "CN=leaf-2.example.com",
			Issuer:      "CN=Intermediate CA",
			IssuerChain: []string{"CN=Intermediate CA", "CN=Root CA"},
			Serial:      "BBB222",
			Namespace:   "kube-system",
			Cluster:     "prod",
			Source:      store.SourceAPIService,
			Severity:    store.SeverityWarn,
			ProbeOK:     true,
		},
		{
			Name:        "leaf-3",
			Subject:     "CN=leaf-3.internal",
			Issuer:      "CN=Other Intermediate",
			IssuerChain: []string{"CN=Other Intermediate", "CN=Root CA"},
			Serial:      "CCC333",
			Namespace:   "cert-manager",
			Cluster:     "staging",
			Source:      store.SourceExternal,
			Severity:    store.SeverityInfo,
			ProbeOK:     true,
		},
		{
			Name:      "no-chain",
			Subject:   "CN=standalone.test",
			Issuer:    "CN=standalone.test",
			Serial:    "DDD444",
			Namespace: "default",
			Source:    store.SourceAnnotation,
			Severity:  store.SeverityInfo,
			ProbeOK:   true,
		},
	}
}

func TestBuild_IndexesCreated(t *testing.T) {
	g := Build(testFindings())
	if len(g.issuerIndex) == 0 {
		t.Error("expected issuer index to be populated")
	}
	if len(g.subjectIndex) == 0 {
		t.Error("expected subject index to be populated")
	}
	if len(g.serialIndex) == 0 {
		t.Error("expected serial index to be populated")
	}
}

func TestQueryIssuer_IntermediateCA(t *testing.T) {
	g := Build(testFindings())
	qr := g.QueryIssuer("Intermediate CA")

	// leaf-1 and leaf-2 have "CN=Intermediate CA" as direct issuer and in chain
	if len(qr.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(qr.Findings))
	}
}

func TestQueryIssuer_RootCA(t *testing.T) {
	g := Build(testFindings())
	qr := g.QueryIssuer("Root CA")

	// All 3 chained certs have "CN=Root CA" in their issuer chain
	if len(qr.Findings) != 3 {
		t.Fatalf("expected 3 findings for root CA, got %d", len(qr.Findings))
	}
	if len(qr.Namespaces) != 3 {
		t.Errorf("expected 3 namespaces, got %v", qr.Namespaces)
	}
	if len(qr.Clusters) != 2 {
		t.Errorf("expected 2 clusters, got %v", qr.Clusters)
	}
}

func TestQueryIssuer_CaseInsensitive(t *testing.T) {
	g := Build(testFindings())
	qr := g.QueryIssuer("root ca")
	if len(qr.Findings) != 3 {
		t.Fatalf("expected 3 findings (case-insensitive), got %d", len(qr.Findings))
	}
}

func TestQueryIssuer_NoMatch(t *testing.T) {
	g := Build(testFindings())
	qr := g.QueryIssuer("NonExistent CA")
	if len(qr.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(qr.Findings))
	}
	if qr.MatchedPattern != "NonExistent CA" {
		t.Errorf("expected pattern preserved, got %q", qr.MatchedPattern)
	}
}

func TestQuerySerial_ExactMatch(t *testing.T) {
	g := Build(testFindings())
	qr := g.QuerySerial("BBB222")
	if len(qr.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(qr.Findings))
	}
	if qr.Findings[0].Name != "leaf-2" {
		t.Errorf("expected leaf-2, got %s", qr.Findings[0].Name)
	}
}

func TestQuerySerial_NoMatch(t *testing.T) {
	g := Build(testFindings())
	qr := g.QuerySerial("ZZZ999")
	if len(qr.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(qr.Findings))
	}
}

func TestQuerySubject_SubstringMatch(t *testing.T) {
	g := Build(testFindings())
	qr := g.QuerySubject("example.com")
	if len(qr.Findings) != 2 {
		t.Fatalf("expected 2 findings matching example.com, got %d", len(qr.Findings))
	}
}

func TestQuerySubject_CaseInsensitive(t *testing.T) {
	g := Build(testFindings())
	qr := g.QuerySubject("STANDALONE")
	if len(qr.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(qr.Findings))
	}
	if qr.Findings[0].Serial != "DDD444" {
		t.Errorf("expected DDD444, got %s", qr.Findings[0].Serial)
	}
}

func TestQueryResult_BySeverity(t *testing.T) {
	g := Build(testFindings())
	qr := g.QueryIssuer("Root CA")
	if qr.BySeverity[store.SeverityCritical] != 1 {
		t.Errorf("expected 1 critical, got %d", qr.BySeverity[store.SeverityCritical])
	}
	if qr.BySeverity[store.SeverityWarn] != 1 {
		t.Errorf("expected 1 warn, got %d", qr.BySeverity[store.SeverityWarn])
	}
	if qr.BySeverity[store.SeverityInfo] != 1 {
		t.Errorf("expected 1 info, got %d", qr.BySeverity[store.SeverityInfo])
	}
}

func TestQueryResult_BySource(t *testing.T) {
	g := Build(testFindings())
	qr := g.QueryIssuer("Root CA")
	if qr.BySource[store.SourceWebhook] != 1 {
		t.Errorf("expected 1 webhook, got %d", qr.BySource[store.SourceWebhook])
	}
	if qr.BySource[store.SourceAPIService] != 1 {
		t.Errorf("expected 1 apiservice, got %d", qr.BySource[store.SourceAPIService])
	}
}

func TestBuild_EmptyFindings(t *testing.T) {
	g := Build(nil)
	qr := g.QueryIssuer("anything")
	if len(qr.Findings) != 0 {
		t.Errorf("expected 0 findings from empty graph, got %d", len(qr.Findings))
	}
}

func TestQueryIssuer_NoDuplicates(t *testing.T) {
	// A finding with the same issuer in both Issuer and IssuerChain
	// should only appear once in results
	g := Build(testFindings())
	qr := g.QueryIssuer("Intermediate CA")
	names := make(map[string]int)
	for _, f := range qr.Findings {
		names[f.Name]++
	}
	for name, count := range names {
		if count > 1 {
			t.Errorf("finding %q appeared %d times (expected 1)", name, count)
		}
	}
}
