package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/config"
	"github.com/ppiankov/trustwatch/internal/store"
)

func TestGrafana_SendsAnnotation(t *testing.T) {
	var gotReq *http.Request
	var gotBody grafanaAnnotation

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReq = r
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &gotBody) //nolint:errcheck // test helper
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.NotificationConfig{
		Enabled: true,
		Webhooks: []config.WebhookConfig{
			{Type: "grafana", URL: srv.URL, APIKey: "test-key-123"},
		},
		Severities: []string{"critical", "warn"},
		Cooldown:   time.Hour,
	}
	n := New(cfg)

	prev := store.Snapshot{}
	curr := store.Snapshot{
		Findings: []store.CertFinding{
			{
				Name:      "my-cert",
				Namespace: "default",
				Source:    store.SourceTLSSecret,
				Severity:  store.SeverityCritical,
				NotAfter:  time.Now().Add(24 * time.Hour),
				ProbeOK:   true,
			},
		},
	}

	n.Notify(prev, curr)

	if gotReq == nil {
		t.Fatal("expected Grafana annotation request")
	}
	if gotReq.URL.Path != "/api/annotations" {
		t.Errorf("expected path /api/annotations, got %q", gotReq.URL.Path)
	}
	if gotReq.Header.Get("Authorization") != "Bearer test-key-123" {
		t.Errorf("expected Bearer auth, got %q", gotReq.Header.Get("Authorization"))
	}
	if gotReq.Header.Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json, got %q", gotReq.Header.Get("Content-Type"))
	}
	if gotBody.Time == 0 {
		t.Error("expected non-zero timestamp")
	}
}

func TestGrafana_TagsIncludeSeverity(t *testing.T) {
	var gotBody grafanaAnnotation

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &gotBody) //nolint:errcheck // test helper
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.NotificationConfig{
		Enabled: true,
		Webhooks: []config.WebhookConfig{
			{Type: "grafana", URL: srv.URL, APIKey: "key"},
		},
		Severities: []string{"critical", "warn"},
		Cooldown:   time.Hour,
	}
	n := New(cfg)

	curr := store.Snapshot{
		Findings: []store.CertFinding{
			{Name: "a", Namespace: "ns", Source: store.SourceTLSSecret, Severity: store.SeverityCritical, ProbeOK: true},
			{Name: "b", Namespace: "ns", Source: store.SourceTLSSecret, Severity: store.SeverityWarn, ProbeOK: true},
		},
	}
	n.Notify(store.Snapshot{}, curr)

	hasTrustwatch := false
	hasCrit := false
	hasWarn := false
	for _, tag := range gotBody.Tags {
		switch tag {
		case "trustwatch":
			hasTrustwatch = true
		case "critical":
			hasCrit = true
		case "warn":
			hasWarn = true
		}
	}
	if !hasTrustwatch {
		t.Error("expected 'trustwatch' tag")
	}
	if !hasCrit {
		t.Error("expected 'critical' tag")
	}
	if !hasWarn {
		t.Error("expected 'warn' tag")
	}
}

func TestGrafana_DashboardUID(t *testing.T) {
	var gotBody grafanaAnnotation

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &gotBody) //nolint:errcheck // test helper
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.NotificationConfig{
		Enabled: true,
		Webhooks: []config.WebhookConfig{
			{Type: "grafana", URL: srv.URL, APIKey: "key", DashboardUID: "abc-123"},
		},
		Severities: []string{"critical"},
		Cooldown:   time.Hour,
	}
	n := New(cfg)

	curr := store.Snapshot{
		Findings: []store.CertFinding{
			{Name: "cert", Namespace: "ns", Source: store.SourceTLSSecret, Severity: store.SeverityCritical, ProbeOK: true},
		},
	}
	n.Notify(store.Snapshot{}, curr)

	if gotBody.DashboardUID != "abc-123" {
		t.Errorf("expected dashboardUID 'abc-123', got %q", gotBody.DashboardUID)
	}
}

func TestGrafana_TextContainsFindings(t *testing.T) {
	var gotBody grafanaAnnotation

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &gotBody) //nolint:errcheck // test helper
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.NotificationConfig{
		Enabled: true,
		Webhooks: []config.WebhookConfig{
			{Type: "grafana", URL: srv.URL, APIKey: "key"},
		},
		Severities: []string{"critical"},
		Cooldown:   time.Hour,
	}
	n := New(cfg)

	curr := store.Snapshot{
		Findings: []store.CertFinding{
			{Name: "my-cert", Namespace: "kube-system", Source: store.SourceWebhook, Severity: store.SeverityCritical, ProbeOK: true},
		},
	}
	n.Notify(store.Snapshot{}, curr)

	if gotBody.Text == "" {
		t.Fatal("expected non-empty text")
	}
	if !contains(gotBody.Text, "kube-system/my-cert") {
		t.Errorf("expected text to contain finding details, got %q", gotBody.Text)
	}
	if !contains(gotBody.Text, "CRITICAL") {
		t.Errorf("expected text to contain severity, got %q", gotBody.Text)
	}
}

func TestGrafana_NoAnnotationWhenNoNewFindings(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.NotificationConfig{
		Enabled: true,
		Webhooks: []config.WebhookConfig{
			{Type: "grafana", URL: srv.URL, APIKey: "key"},
		},
		Severities: []string{"critical"},
		Cooldown:   time.Hour,
	}
	n := New(cfg)

	finding := store.CertFinding{
		Name: "cert", Namespace: "ns", Source: store.SourceTLSSecret,
		Severity: store.SeverityCritical, ProbeOK: true,
	}
	snap := store.Snapshot{Findings: []store.CertFinding{finding}}

	// Same finding in both prev and curr — no change, no notification
	n.Notify(snap, snap)

	if called {
		t.Error("expected no Grafana annotation when findings unchanged")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
