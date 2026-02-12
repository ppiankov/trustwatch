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

	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
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
