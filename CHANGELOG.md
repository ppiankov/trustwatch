# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-02-13

### Added
- `--tunnel` flag for `now` mode: deploys a temporary SOCKS5 relay pod inside the cluster so probes can resolve in-cluster DNS from a laptop
- `--tunnel-ns` flag to control which namespace the relay pod is created in (default: `default`)
- `ProbeWithDialer` function for pluggable TLS probe transport
- Functional options (`WithProbeFn`) on all probing discoverers (webhooks, apiservices, annotations, externals)

## [0.1.0] - 2026-02-12

First functional release. Both `now` and `serve` modes are operational.

### Added
- `now` command: ad-hoc TUI scan with BubbleTea, exit codes 0/1/2/3
- `serve` command: long-running HTTP server with background scan loop
- Web UI at `/` showing critical and warn findings
- JSON API at `/api/v1/snapshot`
- Health endpoint at `/healthz`
- Prometheus metrics: `certwatch_cert_not_after_timestamp`, `certwatch_cert_expires_in_seconds`, `certwatch_probe_success`, `certwatch_scan_duration_seconds`, `certwatch_findings_total`
- Discovery: admission webhooks, APIService aggregation, API server, TLS secrets, Ingress TLS, Linkerd identity, Istio CA, annotation-based targets, external targets
- Concurrent discovery orchestrator with severity classification
- TLS probe module with SNI support
- YAML configuration with sane defaults
- Graceful shutdown with SIGINT/SIGTERM handling
- CI pipeline (test, lint, build, security scan)
