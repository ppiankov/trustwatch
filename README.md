[![CI](https://github.com/ppiankov/trustwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/trustwatch/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ppiankov/trustwatch)](https://goreportcard.com/report/github.com/ppiankov/trustwatch)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![ANCC](https://img.shields.io/badge/ANCC-compliant-brightgreen)](https://ancc.dev)

# trustwatch

**Kubernetes trust surface monitoring.** Discovers expiring certificates on admission webhooks, API aggregation endpoints, service mesh issuers, cert-manager renewals, SPIFFE trust bundles, cloud provider certs, and external dependencies — then reports only the ones that matter. Supports policy-driven rules, multi-cluster federation, and historical trend tracking.

## Quick Start

```bash
# Homebrew
brew install ppiankov/tap/trustwatch

# Or install from source
go install github.com/ppiankov/trustwatch/cmd/trustwatch@latest

# kubectl plugin (also installed by Homebrew)
kubectl trustwatch now --context prod

# Scan current cluster
trustwatch now --context prod

# Run as in-cluster service
trustwatch serve --config /etc/trustwatch/config.yaml
```

### Agent Integration

trustwatch is designed to be used by autonomous agents without plugins or SDKs. Single binary, deterministic output, structured JSON, bounded jobs.

Agents: read [`SKILL.md`](SKILL.md) for commands, flags, JSON output structure, and parsing examples.

Key pattern for agents: `trustwatch now --context prod --output json` then parse `.snapshot.findings[]` for certificate issues.

### Container Image

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/ppiankov/trustwatch:latest

# Or build locally
make docker-build IMAGE=my-registry.io/trustwatch
docker push my-registry.io/trustwatch:v0.2.0
```

Multi-arch images (`linux/amd64`, `linux/arm64`) are published automatically on each release. The image is built `FROM scratch` with only the static binary and CA certificates (~15 MB). It doubles as its own tunnel relay in air-gapped clusters via `trustwatch socks5` (see [tunnel docs](#--tunnel-in-cluster-dns-resolution)).

### Verification

Container images and binary checksums are signed with [Sigstore](https://sigstore.dev) keyless signing.

```bash
# Verify container image
cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "https://github.com/ppiankov/trustwatch/" \
  ghcr.io/ppiankov/trustwatch:latest

# Verify SBOM attestation
cosign verify-attestation --type spdxjson \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "https://github.com/ppiankov/trustwatch/" \
  ghcr.io/ppiankov/trustwatch:latest

# Verify binary checksums
cosign verify-blob --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "https://github.com/ppiankov/trustwatch/" checksums.txt
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No problems |
| 1 | Warnings (certs expiring within warn threshold) |
| 2 | Critical (certs expiring within crit threshold or expired) |
| 3 | Discovery or probe errors |

## What is trustwatch?

- Discovers trust surfaces that Kubernetes depends on (webhooks, apiservices, mesh issuers)
- Probes TLS endpoints and reads TLS Secrets for certificate expiry
- Annotation-driven: teams declare what matters with `trustwatch.dev/*` annotations
- Accepts external targets via ConfigMap (vault, IdP, databases, anything with TLS)
- TrustPolicy CRD for declarative policy rules (min key size, no SHA-1, required issuer, no self-signed)
- Multi-cluster federation: aggregate findings from remote trustwatch instances
- Historical snapshots via SQLite with trend API for UI sparklines
- cert-manager renewal health: detects stuck renewals, failed challenges, pending certificates
- SPIFFE/SPIRE trust bundle monitoring via workload API
- Cloud provider certs: AWS ACM, GCP Certificate Manager, Azure Key Vault (build-tagged)
- OpenTelemetry tracing with OTLP export
- Two modes: `now` (ad-hoc TUI) and `serve` (always-on web UI + Prometheus metrics)
- Deterministic, rule-based severity (no ML, no anomaly detection)
- Reports only problems — healthy surfaces stay quiet

## What trustwatch is NOT

- Not a port scanner — discovery is API-driven and annotation-driven
- Not a cert-manager replacement — it monitors, not manages
- Not a mesh leaf-cert alarm — ignores short-lived workload certs by design
- Not a compliance auditor — it reports operational risk, not regulatory posture
- Not a trust graph visualizer — it shows problems, not topology

## Project Status

**Status: Beta** · **v0.3.1** · Pre-1.0

| Milestone | Status |
|-----------|--------|
| Core functionality | Complete |
| Test coverage >85% | Complete |
| Security audit | Complete |
| golangci-lint config | Complete |
| CI pipeline (test/lint/scan) | Complete |
| Homebrew distribution | Complete |
| Safety model documented | Complete |
| API stability guarantees | Partial |
| v1.0 release | Planned |

Pre-1.0: annotation keys (`trustwatch.dev/*`) are stable from v0.2+. Exit codes stable from v0.1+. Prometheus metric names may change before v1.0.

## Discovery Sources

### Auto-Critical (always discovered)

| Source | What | Why Critical |
|--------|------|-------------|
| API server | `kubernetes.default.svc:443` | Everything depends on it |
| Admission webhooks | `failurePolicy: Fail` webhooks | Expiry bricks deployments |
| API aggregation | `APIService` backends | Expiry breaks APIs |
| Linkerd | Trust roots + issuer Secret | Expiry breaks mesh identity |
| Istio | CA/root/intermediate materials | Expiry breaks mesh identity |
| Gateway API | `Gateway` listener TLS certificate refs | Expiry breaks gateway routing |
| cert-manager | `Certificate` CR expiry via dynamic client | Expiry breaks managed certs |
| cert-manager renewal | Stuck `CertificateRequest`, failed `Challenge`, not-ready `Certificate` | Stalled renewals lead to silent expiry |
| SPIFFE/SPIRE | Trust bundle root CAs via workload API | Expiry breaks SPIFFE identity |

### Opt-In (annotation-driven)

Annotate any Service or Deployment:

```yaml
metadata:
  annotations:
    trustwatch.dev/enabled: "true"
    trustwatch.dev/severity: "critical"
    trustwatch.dev/ports: "443,8443"
    trustwatch.dev/sni: "api.internal"
```

Declare external dependencies:

```yaml
metadata:
  annotations:
    trustwatch.dev/external-targets: |
      https://vault.internal:8200
      tcp://idp.company.com:443?sni=idp.company.com
```

### Cloud Provider Certs (build-tagged)

Cloud provider certificate discovery is available when built with the corresponding tags:

```bash
# Build with all cloud providers
make build-cloud   # or: go build -tags "aws,gcp,azure" ./cmd/trustwatch

# Build with specific providers
go build -tags aws ./cmd/trustwatch
```

| Provider | Build Tag | Source |
|----------|-----------|--------|
| AWS ACM | `aws` | Lists certificates via `acm:ListCertificates` |
| GCP Certificate Manager | `gcp` | Lists certificates via Certificate Manager API |
| Azure Key Vault | `azure` | Lists certificates via Key Vault API |

All providers use ambient authentication (IAM roles, workload identity, managed identity).

### ConfigMap Externals

```yaml
# trustwatch config
external:
  - url: "https://vault.company.internal:8200"
  - url: "tcp://10.0.8.10:9443?sni=api.internal"
```

## Modes

### `trustwatch now` — Ad-hoc TUI

Run from your laptop. Discovers trust surfaces, probes endpoints, displays problems in a terminal UI.

```bash
trustwatch now --context prod --warn-before 720h --crit-before 336h
```

#### Output formats

By default, `now` shows a TUI when stdout is a terminal and a plain table when piped. Use `--output` to force a specific format, or `--quiet` for CI gates that only need the exit code:

```bash
# JSON output for automation
trustwatch now -o json

# Force table output even in a terminal
trustwatch now -o table

# CI gate: exit code only, no output
trustwatch now --quiet && echo "All certs OK"

# JSON piped to jq
trustwatch now -o json | jq '.snapshot.findings[] | select(.severity == "critical")'
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | _(auto)_ | Output format: `json`, `table` (default: TUI if TTY, table if piped) |
| `--quiet` | `-q` | `false` | Suppress all output, exit code only |

#### `--tunnel`: In-cluster DNS resolution

By default, `now` runs from your laptop and can't resolve in-cluster DNS names (e.g. `webhook-svc.ns.svc:443`). The `--tunnel` flag deploys a temporary SOCKS5 proxy pod inside the cluster and routes all probe traffic through it via port-forwarding:

```bash
trustwatch now --tunnel
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--tunnel` | `false` | Enable the in-cluster SOCKS5 relay |
| `--tunnel-ns` | `default` | Namespace for the relay pod |
| `--tunnel-image` | `serjs/go-socks5-proxy:latest` | SOCKS5 proxy image |
| `--tunnel-pull-secret` | _(empty)_ | imagePullSecret name for private registries |
| `--tunnel-command` | _(empty)_ | Override container entrypoint (comma-separated) |

**Private registries / air-gapped clusters:**

If your cluster can't pull from Docker Hub, mirror the image and use `--tunnel-image`:

```bash
# Mirror with crane or skopeo
crane copy serjs/go-socks5-proxy:latest my-registry.io/socks5-proxy:latest
# or: skopeo copy docker://serjs/go-socks5-proxy:latest docker://my-registry.io/socks5-proxy:latest

trustwatch now --tunnel --tunnel-image my-registry.io/socks5-proxy:latest
```

If the registry requires authentication, create an imagePullSecret and pass it:

```bash
trustwatch now --tunnel \
  --tunnel-image my-registry.io/socks5-proxy:latest \
  --tunnel-pull-secret my-registry-creds
```

**Air-gapped clusters (self-relay):**

trustwatch includes a built-in SOCKS5 server. If the trustwatch image is already in your registry, use it as its own relay — no extra images needed:

```bash
trustwatch now --tunnel \
  --tunnel-image my-registry.io/trustwatch:v0.2.0 \
  --tunnel-command /trustwatch,socks5
```

**Custom SOCKS5 image:**

If you use a custom image that doesn't run a SOCKS5 server by default, use `--tunnel-command` to supply the entrypoint. The server must listen on port 1080:

```bash
trustwatch now --tunnel \
  --tunnel-image nicolaka/netshoot:latest \
  --tunnel-command microsocks,-p,1080
```

**Relay pod lifecycle:**

The relay pod is cleaned up automatically when trustwatch exits. A 5-minute `activeDeadlineSeconds` safety net ensures the pod is terminated even if trustwatch crashes or the connection drops.

### Multi-Cluster Federation

Aggregate findings from multiple trustwatch instances:

```bash
# Scan local cluster and two remote instances
trustwatch now --cluster-name prod \
  --remote staging=http://trustwatch.staging:8080 \
  --remote dev=http://trustwatch.dev:8080
```

In `serve` mode, configure remotes via config file:

```yaml
clusterName: prod
remotes:
  - name: staging
    url: http://trustwatch.staging.svc:8080
  - name: dev
    url: http://trustwatch.dev.svc:8080
```

All findings are labeled with their cluster name and the `cluster` label appears on Prometheus metrics.

### `trustwatch serve` — In-Cluster Service

```bash
helm install trustwatch charts/trustwatch \
  --namespace trustwatch --create-namespace \
  --set image.repository=harbor.example.com/trustwatch/trustwatch
```

Override config values:

```bash
helm install trustwatch charts/trustwatch \
  --namespace trustwatch --create-namespace \
  --set config.warnBefore=360h \
  --set config.critBefore=168h
```

Enable Prometheus ServiceMonitor:

```bash
helm install trustwatch charts/trustwatch \
  --namespace trustwatch --create-namespace \
  --set serviceMonitor.enabled=true
```

Enable PrometheusRule alerts:

```bash
helm install trustwatch charts/trustwatch \
  --namespace trustwatch --create-namespace \
  --set prometheusRule.enabled=true
```

Or generate PrometheusRule YAML without Helm:

```bash
trustwatch rules --namespace monitoring --name trustwatch-alerts
```

Enable Grafana dashboard (auto-imported via sidecar):

```bash
helm install trustwatch charts/trustwatch \
  --namespace trustwatch --create-namespace \
  --set grafanaDashboard.enabled=true
```

Exposes web UI, Prometheus metrics, and JSON API.

| Endpoint | Purpose |
|----------|---------|
| `/` | Problems web UI (filterable, with detail panels and trend sparklines) |
| `/metrics` | Prometheus scrape |
| `/healthz` | Liveness/readiness (503 if no scan or stale) |
| `/api/v1/snapshot` | JSON findings |
| `/api/v1/history` | Historical snapshot summaries (requires `--history-db`) |
| `/api/v1/trend` | Severity trend for a specific finding (requires `--history-db`) |

### Prometheus Metrics

```
trustwatch_cert_not_after_timestamp{source, namespace, name, severity, cluster}
trustwatch_cert_expires_in_seconds{source, namespace, name, severity, cluster}
trustwatch_probe_success{source, namespace, name, cluster}
trustwatch_scan_duration_seconds
trustwatch_findings_total{severity}
trustwatch_discovery_errors_total{source}
trustwatch_chain_errors_total{source}
```

### Prometheus Operator Integration

When using Prometheus Operator, the ServiceMonitor and PrometheusRule must carry the label your Prometheus instance selects on. Check with:

```bash
kubectl get prometheus -A -o jsonpath='{.items[*].spec.serviceMonitorSelector}'
```

A common setup requires `release: prometheus-operator`:

```yaml
serviceMonitor:
  enabled: true
  labels:
    release: prometheus-operator
prometheusRule:
  enabled: true
  labels:
    release: prometheus-operator
```

See `examples/values-prod.yaml` for a complete production values file.

### Alert Monitoring with infranow

[infranow](https://github.com/ppiankov/infranow) can monitor trustwatch alerts directly from Prometheus. Point it at your Prometheus service and it will surface firing alerts for expiring certificates, probe failures, and scan staleness:

```bash
infranow monitor --k8s-service prometheus-operated \
  --k8s-namespace monitoring --k8s-remote-port 9090
```

### Troubleshooting

**`TrustwatchProbeFailed` alerts on Ingress TLS secrets**

If trustwatch reports probe failures for Ingress-referenced TLS secrets, the service account likely lacks `get` permission on secrets. Verify:

```bash
kubectl auth can-i get secrets --as system:serviceaccount:trustwatch:trustwatch -n <namespace>
```

The Helm chart ClusterRole includes `get`, `list`, and `watch` for secrets. If namespace-level RBAC policies restrict access, create a RoleBinding in the affected namespace:

```bash
kubectl create rolebinding trustwatch-secrets -n <namespace> \
  --clusterrole=trustwatch --serviceaccount=trustwatch:trustwatch
```

**Chain validation warnings on external targets probed by IP**

When external targets are configured by IP address, chain validation reports "certificate does not cover hostname" because the cert's SANs don't include the IP. Add `sni` to match the certificate's hostname:

```yaml
external:
  - url: "https://10.0.0.1:443"
    sni: "api.example.com"
```

The "certificate signed by unknown authority" warning can appear when the server doesn't send the full intermediate chain. Fix the server's TLS config to include intermediates.

## TrustPolicy CRD

Declarative policy rules via `trustwatch.dev/v1alpha1` TrustPolicy resources:

```bash
# Install the CRD
trustwatch apply

# List active policies
trustwatch policy
```

Example TrustPolicy:

```yaml
apiVersion: trustwatch.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: production-standards
spec:
  targets:
    - kind: Namespace
      names: ["production", "kube-system"]
  thresholds:
    warnBefore: 720h
    critBefore: 336h
  rules:
    - type: minKeySize
      params:
        bits: "2048"
    - type: noSHA1
    - type: requiredIssuer
      params:
        issuer: "CN=My CA"
    - type: noSelfSigned
```

Policy violations appear as findings with source `policy` and finding type `POLICY_VIOLATION`.

## Configuration

```yaml
listenAddr: ":8080"
metricsPath: "/metrics"
refreshEvery: "2m"
warnBefore: "720h"    # 30 days
critBefore: "336h"    # 14 days
namespaces: []         # empty = all
historyDB: ""          # path to SQLite DB (enables /api/v1/history, /api/v1/trend)
spiffeSocket: ""       # path to SPIFFE workload API socket
otelEndpoint: ""       # OTLP gRPC endpoint (e.g. localhost:4317)
clusterName: ""        # label for this cluster in federated views
external:
  - url: "https://vault.internal:8200"
remotes:               # remote trustwatch instances for federation
  - name: staging
    url: http://trustwatch.staging.svc:8080
notifications:
  enabled: false
  webhooks:
    - url: "https://hooks.slack.com/services/T/B/x"
      type: slack
    - url: "https://alerts.example.com/trustwatch"
      type: generic
  severities: ["critical", "warn"]
  cooldown: "1h"
```

## Architecture

```
trustwatch
├── Discovery (Kubernetes API)
│   ├── Webhooks (Validating + Mutating)
│   ├── APIService aggregation
│   ├── TLS Secrets
│   ├── Ingress TLS refs
│   ├── Linkerd identity (trust roots + issuer)
│   ├── Istio CA materials
│   ├── Gateway API TLS refs
│   ├── cert-manager Certificates + renewal health
│   ├── SPIFFE/SPIRE trust bundles
│   ├── Cloud providers (AWS ACM, GCP, Azure KV)
│   └── Annotations (trustwatch.dev/*)
├── Probing (TLS handshake)
│   ├── In-cluster endpoints
│   ├── External targets (ConfigMap)
│   └── SOCKS5 tunnel (--tunnel)
├── Policy Engine
│   ├── TrustPolicy CRD (trustwatch.dev/v1alpha1)
│   └── Rules: min key size, no SHA-1, required issuer, no self-signed
├── Federation
│   ├── Remote snapshot aggregation (--remote name=url)
│   └── Cluster labels on metrics and UI
├── Storage
│   ├── SQLite history (--history-db)
│   └── Trend API (/api/v1/trend)
├── Output
│   ├── TUI (now mode)
│   ├── Web UI (serve mode, filterable with detail panels + sparklines)
│   ├── Prometheus metrics
│   ├── JSON API
│   ├── Notifications (Slack, generic webhook)
│   └── OpenTelemetry traces (--otel-endpoint)
└── Severity
    ├── Critical: expired, webhook Fail, within crit threshold
    ├── Warn: within warn threshold, webhook Ignore (capped¹), insecureSkipTLSVerify
    └── Info: inventory (metrics only)

¹ Webhooks with failurePolicy=Ignore are capped at Warn because they do not block admission.
```

## Security Model

### RBAC Requirements

trustwatch needs **read-only** cluster-wide access. The Helm chart creates a ClusterRole with these rules:

| API Group | Resources | Verbs |
|-----------|-----------|-------|
| `""` (core) | secrets, services, configmaps, namespaces | get, list, watch |
| `admissionregistration.k8s.io` | validatingwebhookconfigurations, mutatingwebhookconfigurations | list, watch |
| `apiregistration.k8s.io` | apiservices | list, watch |
| `apiextensions.k8s.io` | customresourcedefinitions | get, create, update |
| `apps` | deployments | list, watch |
| `networking.k8s.io` | ingresses | list, watch |
| `gateway.networking.k8s.io` | gateways | list, watch |
| `cert-manager.io` | certificates, certificaterequests, challenges | list, watch |
| `trustwatch.dev` | trustpolicies | list, watch |
| `authorization.k8s.io` | selfsubjectaccessreviews | create |

When `--namespace` is used, trustwatch probes its own permissions via `SelfSubjectAccessReview` and silently skips namespaces where it lacks access. This allows namespace-scoped RBAC without 403 errors in the output.

### Secret Access

trustwatch reads `kubernetes.io/tls` Secrets to extract certificate expiry dates. It reads the `tls.crt` PEM data only — private keys (`tls.key`) are never accessed, logged, or stored. If you want to avoid Secret access entirely, remove the `secrets` permission and trustwatch will fall back to probe-only mode (TLS handshake) for all endpoints.

### External Targets

External targets are configured via a ConfigMap (in `serve` mode) or CLI config file (in `now` mode). They contain hostnames and ports, never credentials. If your external targets require authentication context, use annotations on Services instead.

### Data Retention

- **`now` mode**: Snapshot exists only in memory for the duration of the TUI session. Nothing is written to disk unless `--history-db` is set.
- **`serve` mode**: The latest snapshot is held in memory and served via `/api/v1/snapshot`. When `--history-db` is configured, snapshots are persisted to a local SQLite database for trend analysis.
- **No PII**: trustwatch stores certificate metadata (subject, issuer, SANs, serial, expiry). It does not store certificate private keys, request bodies, or user data.

## Stability

- **Metric names** (`trustwatch_*`) may change before v1.0
- **Annotation keys** (`trustwatch.dev/*`) are stable from v0.2+
- **Exit codes** (0/1/2/3) are stable from v0.1+
- **JSON API** (`/api/v1/snapshot`) schema may gain fields but will not remove them before v1.0

## Known Limitations

- Does not detect certs served via Envoy SDS that aren't backed by Kubernetes Secrets
- Cannot probe endpoints blocked by NetworkPolicy from trustwatch's namespace
- Mesh leaf/workload certs (24h default) are intentionally ignored to avoid noise
- Cloud provider discovery requires build tags (`aws`, `gcp`, `azure`) — not included in the default binary
- SPIFFE discovery requires a reachable workload API socket
- Historical storage uses local SQLite — not suitable for HA deployments with multiple replicas
- Requires RBAC read access to secrets, webhooks, apiservices, ingresses, services, gateways, certificates, trustpolicies
- `--tunnel` mode may log `connection reset by peer` errors from the Kubernetes port-forward layer — these are cosmetic and caused by unreachable probe targets closing the SOCKS5 connection; probe results are unaffected

## Roadmap

- [x] `now` mode with BubbleTea TUI
- [x] `serve` mode with web UI + Prometheus metrics
- [x] Webhook + APIService auto-discovery
- [x] TLS Secret parsing
- [x] Ingress TLS discovery
- [x] Linkerd issuer/trust-roots discovery
- [x] Istio CA material discovery
- [x] Annotation-based target discovery
- [x] External targets from config
- [x] `--tunnel` SOCKS5 relay for laptop-to-cluster probing
- [x] Helm chart
- [x] Structured logging (`--log-level`, `--log-format`)
- [x] JSON/table output formats (`--output json|table`, `--quiet`)
- [x] Gateway API TLS discovery
- [x] Namespace-scoped RBAC with access probing
- [x] Grafana dashboard (Helm chart)
- [x] `rules` command (generate PrometheusRule YAML)
- [x] cert-manager Certificate CR discovery
- [x] Webhook and Slack notifications
- [x] Certificate chain validation (broken chains, wrong SANs, self-signed leaves)
- [x] Signed container images + SBOM attestation (Cosign/Sigstore)
- [x] TrustPolicy CRD with policy rules engine
- [x] cert-manager renewal health monitoring
- [x] Historical snapshot storage (SQLite) with trend API
- [x] SPIFFE/SPIRE trust bundle discovery
- [x] Cloud provider certs (AWS ACM, GCP, Azure Key Vault)
- [x] OpenTelemetry tracing
- [x] Multi-cluster federation
- [x] Web UI filtering, detail panels, and trend sparklines

## License

MIT — see [LICENSE](LICENSE) for details.
