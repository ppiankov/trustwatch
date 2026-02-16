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

func pagerDutyConfig(routingKey string) config.NotificationConfig {
	return config.NotificationConfig{
		Enabled: true,
		Webhooks: []config.WebhookConfig{
			{Type: "pagerduty", RoutingKey: routingKey},
		},
		Severities: []string{"critical", "warn"},
		Cooldown:   time.Hour,
	}
}

func TestPagerDuty_TriggerOnNewFinding(t *testing.T) {
	var mu sync.Mutex
	var events []pdEvent

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test helper
		var ev pdEvent
		if err := json.Unmarshal(body, &ev); err != nil {
			t.Errorf("invalid JSON: %v", err)
		}
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	// Override the PagerDuty URL to point to our test server
	origURL := pagerDutyEventsURL
	defer func() { pagerDutyEventsURL = origURL }()
	pagerDutyEventsURL = srv.URL

	cfg := pagerDutyConfig("test-routing-key")
	n := New(cfg)

	prev := store.Snapshot{At: time.Now()}
	curr := store.Snapshot{
		At:       time.Now(),
		Findings: []store.CertFinding{criticalFinding("my-cert", "default")},
	}

	n.Notify(prev, curr)

	mu.Lock()
	defer mu.Unlock()

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.RoutingKey != "test-routing-key" {
		t.Errorf("expected routing key 'test-routing-key', got %q", ev.RoutingKey)
	}
	if ev.EventAction != "trigger" {
		t.Errorf("expected event_action 'trigger', got %q", ev.EventAction)
	}
	if ev.DedupKey == "" {
		t.Error("expected non-empty dedup_key")
	}
	if ev.Payload == nil {
		t.Fatal("expected payload")
	}
	if ev.Payload.Source != "trustwatch" {
		t.Errorf("expected source 'trustwatch', got %q", ev.Payload.Source)
	}
	if ev.Payload.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %q", ev.Payload.Severity)
	}
}

func TestPagerDuty_ResolveOnClearedFinding(t *testing.T) {
	var mu sync.Mutex
	var events []pdEvent

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test helper
		var ev pdEvent
		if err := json.Unmarshal(body, &ev); err != nil {
			t.Errorf("invalid JSON: %v", err)
		}
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	origURL := pagerDutyEventsURL
	defer func() { pagerDutyEventsURL = origURL }()
	pagerDutyEventsURL = srv.URL

	cfg := pagerDutyConfig("test-routing-key")
	n := New(cfg)

	prev := store.Snapshot{
		At:       time.Now(),
		Findings: []store.CertFinding{criticalFinding("my-cert", "default")},
	}
	curr := store.Snapshot{
		At:       time.Now(),
		Findings: nil, // finding cleared
	}

	n.Notify(prev, curr)

	mu.Lock()
	defer mu.Unlock()

	if len(events) != 1 {
		t.Fatalf("expected 1 resolve event, got %d", len(events))
	}
	if events[0].EventAction != "resolve" {
		t.Errorf("expected event_action 'resolve', got %q", events[0].EventAction)
	}
	if events[0].Payload != nil {
		t.Error("resolve events should not have a payload")
	}
}

func TestPagerDuty_NoResolveForPresentFinding(t *testing.T) {
	var mu sync.Mutex
	var events []pdEvent

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test helper
		var ev pdEvent
		if err := json.Unmarshal(body, &ev); err != nil {
			t.Errorf("invalid JSON: %v", err)
		}
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	origURL := pagerDutyEventsURL
	defer func() { pagerDutyEventsURL = origURL }()
	pagerDutyEventsURL = srv.URL

	cfg := pagerDutyConfig("test-routing-key")
	n := New(cfg)

	finding := criticalFinding("my-cert", "default")
	prev := store.Snapshot{
		At:       time.Now(),
		Findings: []store.CertFinding{finding},
	}
	curr := store.Snapshot{
		At:       time.Now(),
		Findings: []store.CertFinding{finding}, // still present
	}

	n.Notify(prev, curr)

	mu.Lock()
	defer mu.Unlock()

	// No trigger (same finding, cooldown) and no resolve (still present)
	for _, ev := range events {
		if ev.EventAction == "resolve" {
			t.Error("should not resolve a finding that is still present")
		}
	}
}

func TestPagerDuty_WarnSeverityMapsToWarning(t *testing.T) {
	var mu sync.Mutex
	var events []pdEvent

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test helper
		var ev pdEvent
		if err := json.Unmarshal(body, &ev); err != nil {
			t.Errorf("invalid JSON: %v", err)
		}
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	origURL := pagerDutyEventsURL
	defer func() { pagerDutyEventsURL = origURL }()
	pagerDutyEventsURL = srv.URL

	cfg := pagerDutyConfig("test-routing-key")
	n := New(cfg)

	prev := store.Snapshot{At: time.Now()}
	curr := store.Snapshot{
		At:       time.Now(),
		Findings: []store.CertFinding{warnFinding("my-cert", "default")},
	}

	n.Notify(prev, curr)

	mu.Lock()
	defer mu.Unlock()

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Payload.Severity != "warning" {
		t.Errorf("expected PD severity 'warning' for warn finding, got %q", events[0].Payload.Severity)
	}
}

func TestPdSummary(t *testing.T) {
	f := &store.CertFinding{
		Name:      "my-cert",
		Namespace: "kube-system",
		Source:    store.SourceWebhook,
		Severity:  store.SeverityCritical,
	}
	got := pdSummary(f)
	if got != "[CRITICAL] kube-system/my-cert — k8s.webhook" {
		t.Errorf("unexpected summary: %q", got)
	}
}

func TestPdSeverity(t *testing.T) {
	tests := []struct {
		input store.Severity
		want  string
	}{
		{store.SeverityCritical, "critical"},
		{store.SeverityWarn, "warning"},
		{store.SeverityInfo, "info"},
	}
	for _, tt := range tests {
		got := pdSeverity(tt.input)
		if got != tt.want {
			t.Errorf("pdSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
