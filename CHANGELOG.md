# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-02-13

### Added
- TUI search: press `/` to filter findings by name, namespace, source, or target
- TUI navigation: `g`/`G` for top/bottom, `1`-`9` for row jump, `j`/`k` for vim-style movement
- TUI header shows `Showing: N/M` when search filter is active
- `--tunnel` flag for `now` mode: deploys a temporary SOCKS5 relay pod inside the cluster so probes can resolve in-cluster DNS from a laptop
- `--tunnel-ns` flag to control which namespace the relay pod is created in (default: `default`)
- `--tunnel-image` flag to override the SOCKS5 proxy image (default: `serjs/go-socks5-proxy:latest`)
- `--tunnel-pull-secret` flag to set an imagePullSecret on the relay pod for private registries
- `--tunnel-command` flag to override the relay container entrypoint for custom SOCKS5 images
- `trustwatch socks5` embedded SOCKS5 server for air-gapped self-relay (no extra image needed)
- Dockerfile and `make docker-build` for container image builds
- Multi-arch container images (`linux/amd64`, `linux/arm64`) published to `ghcr.io/ppiankov/trustwatch` on release
- Progress logging during discovery phase (per-discoverer completion + summary)
- Helm chart (`charts/trustwatch/`) with RBAC, ConfigMap, health probes, and optional ServiceMonitor
- `ProbeWithDialer` function for pluggable TLS probe transport
- Functional options (`WithProbeFn`) on all probing discoverers (webhooks, apiservices, annotations, externals)

### Fixed
- APIService with `insecureSkipTLSVerify: true` no longer reported as critical — downgraded to info with note
- TUI now shows a separator line between the findings table and the detail panel
- TUI color bleeding: removed ANSI from table cells that caused truncated escape sequences to bleed red across rows
- Relay pod now reports container-level failure reasons (ErrImagePull, ImagePullBackOff, OOMKilled) instead of generic timeout
- Early bail on permanent image pull failures instead of waiting for full timeout

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
