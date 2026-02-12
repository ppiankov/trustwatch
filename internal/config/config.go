package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ExternalTarget is an explicit TLS endpoint to probe.
type ExternalTarget struct {
	URL string `yaml:"url"` // https://host:port or tcp://host:port?sni=name
}

// Config holds trustwatch runtime configuration.
type Config struct {
	ListenAddr   string           `yaml:"listenAddr"`   // default ":8080"
	MetricsPath  string           `yaml:"metricsPath"`  // default "/metrics"
	RefreshEvery time.Duration    `yaml:"refreshEvery"` // default 2m
	WarnBefore   time.Duration    `yaml:"warnBefore"`   // default 720h (30d)
	CritBefore   time.Duration    `yaml:"critBefore"`   // default 336h (14d)
	Namespaces   []string         `yaml:"namespaces"`   // empty = all
	External     []ExternalTarget `yaml:"external"`
}

// Defaults returns a Config with sane defaults.
func Defaults() *Config {
	return &Config{
		ListenAddr:   ":8080",
		MetricsPath:  "/metrics",
		RefreshEvery: 2 * time.Minute,
		WarnBefore:   720 * time.Hour, // 30 days
		CritBefore:   336 * time.Hour, // 14 days
		Namespaces:   nil,
	}
}

// Load reads a YAML config file and merges with defaults.
func Load(path string) (*Config, error) {
	c := Defaults()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, nil
}
