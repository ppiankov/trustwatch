# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.5] - 2026-02-15

### Added
- Certificate chain validation: detects broken chains, wrong SANs, self-signed leaves, misordered PEM bundles, expired intermediates
- `ChainErrors` and `ChainLen` fields on findings (JSON API, TUI detail panel, web UI table)
- `trustwatch_chain_errors_total{source}` Prometheus metric
- Cosign keyless signing of container images and binary checksums (Sigstore OIDC)
- SBOM generation (SPDX-JSON) and attestation on container images

## [0.1.4] - 2026-02-14

### Added
- `trustwatch rules` command: generates static PrometheusRule YAML for Prometheus Operator (no cluster connection needed)
- Flags: `--warn-before`, `--crit-before`, `--name`, `--namespace`, `--labels` for customizing generated rules
- Alert rules: `TrustwatchCertExpiringSoon`, `TrustwatchCertExpiryCritical`, `TrustwatchCertExpired`, `TrustwatchProbeFailed`, `TrustwatchDiscoveryErrors`
- cert-manager Certificate CR discovery via dynamic client (graceful skip if CRDs absent)
- cert-manager `status.notAfter` extraction with fallback to Secret PEM parsing
- Webhook notifications in serve mode: generic JSON POST and Slack incoming webhooks
- Notification config: severity filtering, cooldown-based deduplication, escalation detection (warn→critical)
- Helm: PrometheusRule template (`prometheusRule.enabled`)
- Helm: notification config in values and ConfigMap
- Helm RBAC: `cert-manager.io` certificates list/watch

## [0.1.3] - 2026-02-14

### Added
- `--output json` / `-o json` flag on `now` command for CI-friendly JSON output
- `--output table` / `-o table` flag on `now` command for forced table output even in TTY
- `--quiet` / `-q` flag on `now` command to suppress output (exit code only, for CI gates)
- Gateway API TLS discovery: extracts certificates from `gateway.networking.k8s.io/v1` Gateway listener `certificateRefs`
- Graceful skip when Gateway API CRDs are not installed
- Cross-namespace Gateway certificate reference support
- Namespace-scoped RBAC: discoverers respect `--namespace` flag and probe permissions via `SelfSubjectAccessReview`
- Inaccessible namespaces are skipped gracefully with a warning instead of returning 403 errors
- Grafana dashboard shipped as optional ConfigMap in Helm chart (`grafanaDashboard.enabled`)
- Helm RBAC: `gateway.networking.k8s.io` gateways list/watch, `authorization.k8s.io` selfsubjectaccessreviews create

## [0.1.2] - 2026-02-14

### Added
- Structured logging via `slog` with `--log-level` (debug/info/warn/error) and `--log-format` (text/json) flags
- Config validation: `Load()` now rejects invalid values (negative durations, critBefore >= warnBefore, refreshEvery < 30s)
- Discovery error propagation: `Snapshot.Errors` tracks which discoverers failed, surfaced in metrics, JSON API, and exit code 3
- Prometheus metric `trustwatch_discovery_errors_total{source}` for discoverer failure visibility
- Helm: `securityContext` (runAsNonRoot, readOnlyRootFilesystem, drop ALL capabilities)
- Helm: PodDisruptionBudget template (`podDisruptionBudget.enabled`)
- Helm: NetworkPolicy template (`networkPolicy.enabled`)
- Helm: NOTES.txt with post-install instructions
- CLI integration tests
- CLI help text with usage examples on `now` and `serve` commands

### Fixed
- HTTP server now sets read/write/idle timeouts to prevent resource exhaustion
- Replaced `log.Fatalf` in serve goroutine with error channel for graceful shutdown
- `/healthz` returns 503 when no scan has completed or scan is stale (was always 200)
- Resolved all 33 golangci-lint issues (fieldalignment, package comments, errcheck, goconst, misspell)

## [0.1.1] - 2026-02-13

### Added
- TUI search: press `/` to filter findings by name, namespace, source, or target
- TUI navigation: `g`/`G` for top/bottom, `1`-`9` for row jump, `j`/`k` for vim-style movement
- TUI header shows `Showing: N/M` when search filter is active
- TUI detail panel shows exact `notAfter` timestamp alongside relative time
- Security model section in README (RBAC scope, secret access, data retention)
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
- **BREAKING**: Prometheus metric prefix renamed from `certwatch_*` to `trustwatch_*` — update dashboards and alerts
- Webhook `failurePolicy=Ignore` severity capped at warn — expired certs on Ignore webhooks no longer spam critical
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
- Prometheus metrics: `trustwatch_cert_not_after_timestamp`, `trustwatch_cert_expires_in_seconds`, `trustwatch_probe_success`, `trustwatch_scan_duration_seconds`, `trustwatch_findings_total`
- Discovery: admission webhooks, APIService aggregation, API server, TLS secrets, Ingress TLS, Linkerd identity, Istio CA, annotation-based targets, external targets
- Concurrent discovery orchestrator with severity classification
- TLS probe module with SNI support
- YAML configuration with sane defaults
- Graceful shutdown with SIGINT/SIGTERM handling
- CI pipeline (test, lint, build, security scan)
