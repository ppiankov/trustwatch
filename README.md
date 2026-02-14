[![CI](https://github.com/ppiankov/trustwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/trustwatch/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ppiankov/trustwatch)](https://goreportcard.com/report/github.com/ppiankov/trustwatch)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

# trustwatch

**Kubernetes trust surface monitoring.** Discovers expiring certificates on admission webhooks, API aggregation endpoints, service mesh issuers, annotated services, and external dependencies — then reports only the ones that matter.

## Quick Start

```bash
# Install
go install github.com/ppiankov/trustwatch/cmd/trustwatch@latest

# Scan current cluster
trustwatch now --context prod

# Run as in-cluster service
trustwatch serve --config /etc/trustwatch/config.yaml
```

### Container Image

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/ppiankov/trustwatch:latest

# Or build locally
make docker-build IMAGE=my-registry.io/trustwatch
docker push my-registry.io/trustwatch:v0.1.1
```

Multi-arch images (`linux/amd64`, `linux/arm64`) are published automatically on each release. The image is built `FROM scratch` with only the static binary and CA certificates (~15 MB). It doubles as its own tunnel relay in air-gapped clusters via `trustwatch socks5` (see [tunnel docs](#--tunnel-in-cluster-dns-resolution)).

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
- Two modes: `now` (ad-hoc TUI) and `serve` (always-on web UI + Prometheus metrics)
- Deterministic, rule-based severity (no ML, no anomaly detection)
- Reports only problems — healthy surfaces stay quiet

## What trustwatch is NOT

- Not a port scanner — discovery is API-driven and annotation-driven
- Not a cert-manager replacement — it monitors, not manages
- Not a mesh leaf-cert alarm — ignores short-lived workload certs by design
- Not a compliance auditor — it reports operational risk, not regulatory posture
- Not a trust graph visualizer — it shows problems, not topology

## Discovery Sources

### Auto-Critical (always discovered)

| Source | What | Why Critical |
|--------|------|-------------|
| API server | `kubernetes.default.svc:443` | Everything depends on it |
| Admission webhooks | `failurePolicy: Fail` webhooks | Expiry bricks deployments |
| API aggregation | `APIService` backends | Expiry breaks APIs |
| Linkerd | Trust roots + issuer Secret | Expiry breaks mesh identity |
| Istio | CA/root/intermediate materials | Expiry breaks mesh identity |

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
  --tunnel-image my-registry.io/trustwatch:v0.1.1 \
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

Exposes web UI, Prometheus metrics, and JSON API.

| Endpoint | Purpose |
|----------|---------|
| `/` | Problems web UI |
| `/metrics` | Prometheus scrape |
| `/healthz` | Liveness probe |
| `/api/v1/snapshot` | JSON findings |

### Prometheus Metrics

```
trustwatch_cert_not_after_timestamp{source, namespace, name, severity}
trustwatch_cert_expires_in_seconds{source, namespace, name, severity}
trustwatch_probe_success{source, namespace, name}
trustwatch_scan_duration_seconds
trustwatch_findings_total{severity}
```

## Configuration

```yaml
listenAddr: ":8080"
metricsPath: "/metrics"
refreshEvery: "2m"
warnBefore: "720h"    # 30 days
critBefore: "336h"    # 14 days
namespaces: []         # empty = all
external:
  - url: "https://vault.internal:8200"
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
│   └── Annotations (trustwatch.dev/*)
├── Probing (TLS handshake)
│   ├── In-cluster endpoints
│   ├── External targets (ConfigMap)
│   └── SOCKS5 tunnel (--tunnel)
├── Output
│   ├── TUI (now mode)
│   ├── Web UI (serve mode)
│   ├── Prometheus metrics
│   └── JSON API
└── Severity
    ├── Critical: expired, webhook Fail, within crit threshold
    ├── Warn: within warn threshold, webhook Ignore (capped), insecureSkipTLSVerify
    └── Info: inventory (metrics only)
```

## Security Model

### RBAC Requirements

trustwatch needs **read-only** cluster-wide access. The Helm chart creates a ClusterRole with these rules:

| API Group | Resources | Verbs |
|-----------|-----------|-------|
| `""` (core) | secrets, services, configmaps, namespaces | list, watch |
| `admissionregistration.k8s.io` | validatingwebhookconfigurations, mutatingwebhookconfigurations | list, watch |
| `apiregistration.k8s.io` | apiservices | list, watch |
| `apps` | deployments | list, watch |
| `networking.k8s.io` | ingresses | list, watch |

### Secret Access

trustwatch reads `kubernetes.io/tls` Secrets to extract certificate expiry dates. It reads the `tls.crt` PEM data only — private keys (`tls.key`) are never accessed, logged, or stored. If you want to avoid Secret access entirely, remove the `secrets` permission and trustwatch will fall back to probe-only mode (TLS handshake) for all endpoints.

### External Targets

External targets are configured via a ConfigMap (in `serve` mode) or CLI config file (in `now` mode). They contain hostnames and ports, never credentials. If your external targets require authentication context, use annotations on Services instead.

### Data Retention

- **`now` mode**: Snapshot exists only in memory for the duration of the TUI session. Nothing is written to disk.
- **`serve` mode**: The latest snapshot is held in memory and served via `/api/v1/snapshot`. No historical data is stored. Prometheus metrics are exported for external retention.
- **No PII**: trustwatch stores certificate metadata (subject, issuer, SANs, serial, expiry). It does not store certificate private keys, request bodies, or user data.

## Known Limitations

- Does not detect certs served via Envoy SDS that aren't backed by Kubernetes Secrets
- Cannot probe endpoints blocked by NetworkPolicy from trustwatch's namespace
- Mesh leaf/workload certs (24h default) are intentionally ignored to avoid noise
- No CRD support yet — annotations and ConfigMap only (CRD on roadmap)
- Requires RBAC read access to secrets, webhooks, apiservices, ingresses, services
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
- [ ] `--quiet` / `--verbose` log level control
- [ ] `rules` command (generate PrometheusRule YAML)
- [ ] cert-manager Certificate CR awareness
- [ ] TrustPolicy CRD (future)

## License

MIT — see [LICENSE](LICENSE) for details.
