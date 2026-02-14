package config

import (
	"os"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	c := Defaults()
	if c.ListenAddr != ":8080" {
		t.Errorf("expected :8080, got %s", c.ListenAddr)
	}
	if c.MetricsPath != "/metrics" {
		t.Errorf("expected /metrics, got %s", c.MetricsPath)
	}
	if c.WarnBefore != 720*time.Hour {
		t.Errorf("expected 720h, got %v", c.WarnBefore)
	}
	if c.CritBefore != 336*time.Hour {
		t.Errorf("expected 336h, got %v", c.CritBefore)
	}
	if c.RefreshEvery != 2*time.Minute {
		t.Errorf("expected 2m, got %v", c.RefreshEvery)
	}
}

func TestLoad(t *testing.T) {
	content := `
listenAddr: ":9090"
metricsPath: "/prom"
external:
  - url: "https://vault.internal:8200"
`
	f, err := os.CreateTemp("", "trustwatch-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	if _, writeErr := f.WriteString(content); writeErr != nil {
		t.Fatal(writeErr)
	}
	f.Close()

	c, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":9090" {
		t.Errorf("expected :9090, got %s", c.ListenAddr)
	}
	if c.MetricsPath != "/prom" {
		t.Errorf("expected /prom, got %s", c.MetricsPath)
	}
	if len(c.External) != 1 {
		t.Fatalf("expected 1 external target, got %d", len(c.External))
	}
	if c.External[0].URL != "https://vault.internal:8200" {
		t.Errorf("expected vault URL, got %s", c.External[0].URL)
	}
	// defaults should still apply for unset fields
	if c.WarnBefore != 720*time.Hour {
		t.Errorf("expected 720h default, got %v", c.WarnBefore)
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestValidate_DefaultsPass(t *testing.T) {
	c := Defaults()
	if err := c.Validate(); err != nil {
		t.Errorf("defaults should be valid: %v", err)
	}
}

func TestValidate_NegativeWarnBefore(t *testing.T) {
	c := Defaults()
	c.WarnBefore = -1 * time.Hour
	if err := c.Validate(); err == nil {
		t.Error("expected error for negative warnBefore")
	}
}

func TestValidate_CritBeforeExceedsWarnBefore(t *testing.T) {
	c := Defaults()
	c.CritBefore = 800 * time.Hour
	if err := c.Validate(); err == nil {
		t.Error("expected error when critBefore >= warnBefore")
	}
}

func TestValidate_RefreshTooFast(t *testing.T) {
	c := Defaults()
	c.RefreshEvery = 10 * time.Second
	if err := c.Validate(); err == nil {
		t.Error("expected error for refreshEvery < 30s")
	}
}

func TestValidate_EmptyListenAddr(t *testing.T) {
	c := Defaults()
	c.ListenAddr = ""
	if err := c.Validate(); err == nil {
		t.Error("expected error for empty listenAddr")
	}
}

func TestLoadNotificationConfig(t *testing.T) {
	content := `
listenAddr: ":8080"
notifications:
  enabled: true
  webhooks:
    - url: "https://hooks.slack.com/services/T/B/x"
      type: slack
    - url: "https://alerts.example.com/trustwatch"
      type: generic
  severities: ["critical", "warn"]
  cooldown: "30m"
`
	f, err := os.CreateTemp("", "trustwatch-notify-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	if _, writeErr := f.WriteString(content); writeErr != nil {
		t.Fatal(writeErr)
	}
	f.Close()

	c, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !c.Notifications.Enabled {
		t.Error("expected notifications.enabled to be true")
	}
	if len(c.Notifications.Webhooks) != 2 {
		t.Fatalf("expected 2 webhooks, got %d", len(c.Notifications.Webhooks))
	}
	if c.Notifications.Webhooks[0].Type != "slack" {
		t.Errorf("expected first webhook type 'slack', got %q", c.Notifications.Webhooks[0].Type)
	}
	if c.Notifications.Webhooks[1].Type != "generic" {
		t.Errorf("expected second webhook type 'generic', got %q", c.Notifications.Webhooks[1].Type)
	}
	if len(c.Notifications.Severities) != 2 {
		t.Errorf("expected 2 severities, got %d", len(c.Notifications.Severities))
	}
	if c.Notifications.Cooldown != 30*time.Minute {
		t.Errorf("expected cooldown 30m, got %v", c.Notifications.Cooldown)
	}
}

func TestLoadInvalidConfig(t *testing.T) {
	content := `
listenAddr: ":9090"
critBefore: "800h"
warnBefore: "720h"
`
	f, err := os.CreateTemp("", "trustwatch-invalid-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	if _, writeErr := f.WriteString(content); writeErr != nil {
		t.Fatal(writeErr)
	}
	f.Close()

	_, err = Load(f.Name())
	if err == nil {
		t.Error("expected validation error when critBefore > warnBefore")
	}
}
