package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ppiankov/trustwatch/internal/config"
	"github.com/ppiankov/trustwatch/internal/store"
)

func testConfig(url string) config.NotificationConfig {
	return config.NotificationConfig{
		Enabled: true,
		Webhooks: []config.WebhookConfig{
			{URL: url, Type: "generic"},
		},
		Severities: []string{"critical", "warn"},
		Cooldown:   time.Hour,
	}
}

func criticalFinding(name, ns string) store.CertFinding {
	return store.CertFinding{
		Name:      name,
		Namespace: ns,
		Source:    store.SourceTLSSecret,
		Severity:  store.SeverityCritical,
		NotAfter:  time.Now().Add(24 * time.Hour),
		ProbeOK:   true,
	}
}

func warnFinding(name, ns string) store.CertFinding {
	return store.CertFinding{
		Name:      name,
		Namespace: ns,
		Source:    store.SourceTLSSecret,
		Severity:  store.SeverityWarn,
		NotAfter:  time.Now().Add(20 * 24 * time.Hour),
		ProbeOK:   true,
	}
}

func TestNew_DisabledReturnsNil(t *testing.T) {
	n := New(config.NotificationConfig{Enabled: false})
	if n != nil {
		t.Error("expected nil notifier when disabled")
	}
}

func TestNew_NoWebhooksReturnsNil(t *testing.T) {
	n := New(config.NotificationConfig{Enabled: true})
	if n != nil {
		t.Error("expected nil notifier when no webhooks")
	}
}

func TestNotifier_NewCriticalFinding(t *testing.T) {
	var mu sync.Mutex
	var received []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test helper
		received = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(testConfig(srv.URL))

	prev := store.Snapshot{At: time.Now()}
	curr := store.Snapshot{
		At:       time.Now(),
		Findings: []store.CertFinding{criticalFinding("my-cert", "default")},
	}

	n.Notify(prev, curr)

	mu.Lock()
	defer mu.Unlock()
	if received == nil {
		t.Fatal("expected webhook to be called")
	}

	var payload GenericPayload
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("invalid JSON payload: %v", err)
	}
	if len(payload.Findings) != 1 {
		t.Errorf("expected 1 finding in payload, got %d", len(payload.Findings))
	}
	if payload.Findings[0].Name != "my-cert" {
		t.Errorf("expected finding name 'my-cert', got %q", payload.Findings[0].Name)
	}
}

func TestNotifier_CooldownSuppresses(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(testConfig(srv.URL))

	prev := store.Snapshot{At: time.Now()}
	curr := store.Snapshot{
		At:       time.Now(),
		Findings: []store.CertFinding{criticalFinding("my-cert", "default")},
	}

	// First notification
	n.Notify(prev, curr)

	// Second notification with same finding — should be suppressed by cooldown
	n.Notify(curr, curr)

	mu.Lock()
	defer mu.Unlock()
	if callCount != 1 {
		t.Errorf("expected 1 webhook call (cooldown should suppress second), got %d", callCount)
	}
}

func TestNotifier_SeverityFilter(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.Severities = []string{"critical"} // only critical
	n := New(cfg)

	prev := store.Snapshot{At: time.Now()}
	curr := store.Snapshot{
		At:       time.Now(),
		Findings: []store.CertFinding{warnFinding("my-cert", "default")},
	}

	n.Notify(prev, curr)

	mu.Lock()
	defer mu.Unlock()
	if callCount != 0 {
		t.Errorf("expected 0 webhook calls (warn filtered out), got %d", callCount)
	}
}

func TestNotifier_EscalationNotifies(t *testing.T) {
	var mu sync.Mutex
	var received []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test helper
		received = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(testConfig(srv.URL))

	prev := store.Snapshot{
		At:       time.Now(),
		Findings: []store.CertFinding{warnFinding("my-cert", "default")},
	}

	// Consume the initial notification
	empty := store.Snapshot{At: time.Now()}
	n.Notify(empty, prev)

	// Reset cooldown for escalation test
	n.mu.Lock()
	n.sent = make(map[string]time.Time)
	n.mu.Unlock()

	// Escalate to critical
	curr := store.Snapshot{
		At:       time.Now(),
		Findings: []store.CertFinding{criticalFinding("my-cert", "default")},
	}

	mu.Lock()
	received = nil
	mu.Unlock()

	n.Notify(prev, curr)

	mu.Lock()
	defer mu.Unlock()
	if received == nil {
		t.Fatal("expected webhook to be called on escalation")
	}

	var payload GenericPayload
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("invalid JSON payload: %v", err)
	}
	if payload.Findings[0].Severity != store.SeverityCritical {
		t.Errorf("expected severity critical, got %q", payload.Findings[0].Severity)
	}
}

func TestNotifier_GenericWebhookPayload(t *testing.T) {
	var received []byte
	var mu sync.Mutex
	var gotContentType string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test helper
		received = body
		gotContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(testConfig(srv.URL))

	curr := store.Snapshot{
		At: time.Now(),
		Findings: []store.CertFinding{
			criticalFinding("cert-a", "ns1"),
			warnFinding("cert-b", "ns2"),
		},
	}

	n.Notify(store.Snapshot{}, curr)

	mu.Lock()
	defer mu.Unlock()

	if gotContentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", gotContentType)
	}

	var payload GenericPayload
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if payload.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
	if payload.Summary == "" {
		t.Error("expected non-empty summary")
	}
	if len(payload.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(payload.Findings))
	}
}

func TestNotifier_SlackPayload(t *testing.T) {
	var received []byte
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test helper
		received = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.Webhooks[0].Type = "slack"
	n := New(cfg)

	curr := store.Snapshot{
		At:       time.Now(),
		Findings: []store.CertFinding{criticalFinding("my-cert", "default")},
	}

	n.Notify(store.Snapshot{}, curr)

	mu.Lock()
	defer mu.Unlock()

	var payload SlackPayload
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("invalid Slack JSON: %v", err)
	}
	if len(payload.Blocks) < 3 {
		t.Fatalf("expected at least 3 blocks (header + finding + context), got %d", len(payload.Blocks))
	}
	if payload.Blocks[0].Type != "header" {
		t.Errorf("expected first block type 'header', got %q", payload.Blocks[0].Type)
	}
	if payload.Blocks[1].Type != "section" {
		t.Errorf("expected second block type 'section', got %q", payload.Blocks[1].Type)
	}
}

func TestNotifier_WebhookFailureLogsWarning(_ *testing.T) {
	// Use an unreachable URL — the notification should not block or panic
	cfg := config.NotificationConfig{
		Enabled: true,
		Webhooks: []config.WebhookConfig{
			{URL: "http://127.0.0.1:1", Type: "generic"}, // connection refused
		},
		Severities: []string{"critical"},
		Cooldown:   time.Hour,
	}
	n := New(cfg)

	curr := store.Snapshot{
		At:       time.Now(),
		Findings: []store.CertFinding{criticalFinding("my-cert", "default")},
	}

	// Should not panic or block
	n.Notify(store.Snapshot{}, curr)
}

func TestBuildSummary(t *testing.T) {
	tests := []struct {
		name     string
		want     string
		findings []store.CertFinding
	}{
		{
			name:     "critical only",
			findings: []store.CertFinding{criticalFinding("a", "ns")},
			want:     "1 critical finding(s)",
		},
		{
			name:     "warn only",
			findings: []store.CertFinding{warnFinding("a", "ns")},
			want:     "1 warn finding(s)",
		},
		{
			name: "mixed",
			findings: []store.CertFinding{
				criticalFinding("a", "ns"),
				criticalFinding("b", "ns"),
				warnFinding("c", "ns"),
			},
			want: "2 critical, 1 warn finding(s)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSummary(tt.findings)
			if got != tt.want {
				t.Errorf("buildSummary() = %q, want %q", got, tt.want)
			}
		})
	}
}
