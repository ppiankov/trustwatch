# Work Orders: trustwatch MVP

Goal: ship a working `trustwatch now` and `trustwatch serve` that discovers Kubernetes trust surfaces, probes TLS endpoints, and reports expiring certificates.

Prerequisites complete:
- Repo scaffolded with CLI skeleton (now, serve, version commands)
- TLS probe module with SNI support
- CertFinding data model and Discoverer interface
- CI pipeline (test, lint, build, security scan)
- CLAUDE.md, CONTRIBUTING.md, Makefile, .golangci.yml

---

## Phase 1: Core Discovery

### WO-T01: Kubernetes API server probe

Probe `kubernetes.default.svc:443` and report cert expiry. This is the simplest discoverer and validates the probe→finding pipeline end-to-end.

Files:
- `internal/discovery/apiserver.go` — APIServerDiscoverer
- `internal/discovery/apiserver_test.go` — unit tests with mock TLS server

Verification: `make test` passes, discoverer returns CertFinding with correct NotAfter.

### WO-T02: Admission webhook discovery

List ValidatingWebhookConfiguration and MutatingWebhookConfiguration. For each webhook with `clientConfig.service`, resolve to service DNS + port and probe via TLS handshake. Mark `failurePolicy: Fail` as critical severity.

Files:
- `internal/discovery/webhooks.go`
- `internal/discovery/webhooks_test.go`

RBAC: list/watch on `admissionregistration.k8s.io` webhookconfigurations.

Verification: `make test` passes, mock webhook configs produce correct findings.

### WO-T03: APIService discovery

List APIService objects with `.spec.service` set. Resolve to service DNS + port, probe TLS. Mark available services as critical.

Files:
- `internal/discovery/apiservices.go`
- `internal/discovery/apiservices_test.go`

RBAC: list/watch on `apiregistration.k8s.io` apiservices.

Verification: `make test` passes.

### WO-T04: TLS Secret inventory

List Secrets of type `kubernetes.io/tls`. Parse `tls.crt` for leaf cert NotAfter, SANs, issuer. Findings are info severity by default (inventory, not alerting).

Files:
- `internal/discovery/secrets.go`
- `internal/discovery/secrets_test.go`

RBAC: list/watch on secrets.

Verification: `make test` passes, PEM parsing handles multi-cert bundles.

### WO-T05: Ingress TLS discovery

List Ingresses, extract `spec.tls[].secretName`, dereference to TLS Secrets, parse certs. Link findings back to the Ingress object.

Files:
- `internal/discovery/ingress.go`
- `internal/discovery/ingress_test.go`

RBAC: list/watch on networking.k8s.io ingresses.

Verification: `make test` passes.

---

## Phase 2: Mesh + External Discovery

### WO-T06: Linkerd identity discovery

Check for Linkerd presence (namespace `linkerd` or `linkerd-viz`). Read:
- ConfigMap `linkerd-identity-trust-roots` in `linkerd` namespace (trust anchors)
- Secret `linkerd-identity-issuer` in `linkerd` namespace (issuer cert)

Parse PEM certs, report expiry. Critical severity for issuer.

Files:
- `internal/discovery/linkerd.go`
- `internal/discovery/linkerd_test.go`

Verification: `make test` passes, gracefully skips if Linkerd not installed.

### WO-T07: Istio CA discovery

Check for Istio presence (namespace `istio-system`). Read CA/root/intermediate materials from known Secrets/ConfigMaps. Do NOT monitor workload leaf certs (24h default lifetime = noise).

Files:
- `internal/discovery/istio.go`
- `internal/discovery/istio_test.go`

Verification: `make test` passes, gracefully skips if Istio not installed.

### WO-T08: Annotation-based target discovery

Scan Services and Deployments for `trustwatch.dev/*` annotations. Build probe targets from:
- `trustwatch.dev/enabled: "true"` — include this object
- `trustwatch.dev/ports` — ports to probe
- `trustwatch.dev/sni` — SNI override
- `trustwatch.dev/severity` — severity override
- `trustwatch.dev/tls-secret` — read from Secret instead of probing
- `trustwatch.dev/external-targets` — multiline URL list

Files:
- `internal/discovery/annotations.go`
- `internal/discovery/annotations_test.go`

RBAC: list/watch on services, deployments.

Verification: `make test` passes, annotation parsing handles all supported keys.

### WO-T09: External targets from ConfigMap

Read external target URLs from the config file (mounted ConfigMap in serve mode, file path in now mode). Probe each via TLS handshake.

Files:
- `internal/discovery/externals.go`
- `internal/discovery/externals_test.go`

Verification: `make test` passes.

---

## Phase 3: Aggregation + Output

### WO-T10: Discovery orchestrator

Run all discoverers concurrently, collect findings into a Snapshot. Apply severity classification:
- Expired → critical
- Within critBefore → critical
- Within warnBefore → warn
- Webhook failurePolicy=Fail within warnBefore → critical (escalate)
- Healthy → info (inventory only)

Graceful degradation: if a discoverer fails, log it, continue with others.

Files:
- `internal/discovery/orchestrator.go`
- `internal/discovery/orchestrator_test.go`

Verification: `make test` passes, partial failures don't abort.

### WO-T11: `now` mode TUI

Implement BubbleTea TUI for `trustwatch now`:
- Header: cluster context, snapshot time, problem counts
- Table: severity, source, namespace/name, target, expires in, status
- Detail panel for selected row (SANs, issuer, probe error, notes)
- Color coding: red for critical, yellow for warn
- Exit codes: 0 (ok), 1 (warn), 2 (critical), 3 (errors)

Files:
- `internal/cli/now.go` (update)
- `internal/monitor/tui.go`
- `internal/monitor/tui_test.go`

Verification: `make test` passes, TUI renders correctly.

### WO-T12: Prometheus metrics exporter

Implement metrics:
- `trustwatch_cert_not_after_timestamp` (gauge)
- `trustwatch_cert_expires_in_seconds` (gauge)
- `trustwatch_probe_ok` (gauge, 1/0)
- `trustwatch_discovery_ok` (gauge per source, for degradation visibility)

Labels: source, namespace, name, target, severity (bounded).

Files:
- `internal/metrics/exporter.go`
- `internal/metrics/exporter_test.go`

Verification: `make test` passes, metric names follow Prometheus conventions.

### WO-T13: Web UI (problems dashboard)

Built-in HTML served at `/`. Shows only findings with severity warn or critical. Table with: severity, source, where, target, expires in, status. Minimal CSS, no JS frameworks.

Also serve:
- `/api/v1/snapshot` — JSON
- `/healthz` — liveness

Files:
- `internal/web/server.go`
- `internal/web/server_test.go`

Verification: `make test` passes, HTTP handlers return correct content types.

### WO-T14: `serve` mode integration

Wire discovery orchestrator + metrics exporter + web UI into `trustwatch serve`:
- Background refresh loop (every refreshEvery)
- Serve /metrics, /, /healthz, /api/v1/snapshot on listenAddr
- Kubernetes client from in-cluster config or kubeconfig flag

Files:
- `internal/cli/serve.go` (update)
- `internal/app/app.go`

Verification: `make test` passes, `make build` succeeds.

---

## Phase 4: Packaging

### WO-T15: Helm chart

Create `charts/trustwatch/` with:
- Deployment (1 replica)
- Service (8080)
- ServiceAccount + ClusterRole + ClusterRoleBinding (read-only RBAC)
- ConfigMap (config.yaml)
- ServiceMonitor (optional, if Prometheus Operator detected)
- values.yaml with image, config overrides, RBAC toggle

Files:
- `charts/trustwatch/Chart.yaml`
- `charts/trustwatch/values.yaml`
- `charts/trustwatch/templates/deployment.yaml`
- `charts/trustwatch/templates/service.yaml`
- `charts/trustwatch/templates/rbac.yaml`
- `charts/trustwatch/templates/configmap.yaml`
- `charts/trustwatch/templates/servicemonitor.yaml`
- `charts/trustwatch/templates/_helpers.tpl`

Verification: `helm template trustwatch charts/trustwatch/` renders valid YAML.

### WO-T16: Dockerfile

Multi-stage build:
- Builder: `golang:1.25-alpine`
- Runtime: `gcr.io/distroless/static-debian12:nonroot`

Files:
- `Dockerfile`

Verification: `docker build -t trustwatch .` succeeds.

### WO-T17: `rules` command

Generate PrometheusRule YAML for GitOps workflows:
- `trustwatch rules --output rules.yaml`
- Produces PrometheusRule with alert rules for trustwatch_cert_expires_in_seconds thresholds

Files:
- `internal/cli/rules.go`
- `internal/cli/rules_test.go`

Verification: `make test` passes, output is valid PrometheusRule YAML.

---

## Phase 5: Polish

### WO-T18: Integration tests

Test against a real (or kind) cluster:
- Discoverers find expected objects
- Probes succeed against live endpoints
- End-to-end: now mode returns correct exit codes

Files:
- `test/integration/`

Verification: Tests pass against a kind cluster.

### WO-T19: Documentation finalization

- README with usage examples, screenshots of TUI and web UI
- Architecture diagram
- Annotation reference in docs/

Files:
- `README.md` (update)
- `docs/annotations.md`
- `docs/architecture.md`

### WO-T20: Release workflow

GitHub Actions workflow for tagged releases:
- Multi-platform binaries
- Checksums
- GitHub Release with install instructions
- Helm chart publish

Files:
- `.github/workflows/release.yml`

---

## Phase 6: CI/Automation and Extended Discovery

### WO-T21: JSON/table output for `now` mode

**Goal**: `trustwatch now --output json` enables piping results into CI pipelines, scripts, or jq.

Currently `now` always launches TUI. CI systems and scripts need structured output.

**CLI changes**:
```
trustwatch now --output json    # JSON array of findings to stdout
trustwatch now --output table   # ASCII table to stdout (no TUI)
trustwatch now                  # TUI (default when TTY)
```

**Behavior**:
- Auto-detect: if stdout is not a TTY, default to `table` instead of TUI
- `--output json`: JSON array of CertFinding objects, same schema as `/api/v1/snapshot`
- `--output table`: fixed-width ASCII table (severity, source, namespace/name, expires in, status)
- Exit codes preserved: 0 (ok), 1 (warn), 2 (critical)
- `--quiet` flag: suppress all output, only return exit code

**Use cases**:
- `trustwatch now --output json | jq '.[] | select(.severity == "critical")'`
- `trustwatch now --quiet && echo "all clear" || echo "problems found"`
- CI gate: `trustwatch now --output json --fail-on warn`

**Files**:
- `internal/cli/now.go` — add `--output` and `--quiet` flags, TTY detection
- `internal/monitor/table.go` — ASCII table renderer (new)
- `internal/monitor/json.go` — JSON output writer (new)
- `internal/monitor/table_test.go`
- `internal/monitor/json_test.go`

**Verification**: `make test` passes, `trustwatch now --output json | jq .` works.

---

### WO-T22: Gateway API TLS discovery

**Goal**: Discover TLS certificates from Gateway API resources (`gateway.networking.k8s.io`).

Gateway API is replacing Ingress. Its TLS config lives on Gateway and HTTPRoute objects with `certificateRefs`.

**Discovery targets**:
- `Gateway` objects with `spec.listeners[].tls.certificateRefs` → dereference to TLS Secrets
- `spec.listeners[].tls.mode: Terminate` → probe the gateway endpoint via TLS
- Optional: `ReferenceGrant` awareness (cross-namespace secret refs)

**Files**:
- `internal/discovery/gateway.go`
- `internal/discovery/gateway_test.go`

**RBAC**: list/watch on `gateway.networking.k8s.io` gateways (add to ClusterRole in Helm chart).

**Behavior**:
- Gracefully skip if Gateway API CRDs not installed (check API discovery first)
- Link findings back to Gateway object (namespace/name/listener)
- Probe gateway TLS endpoints like Ingress discovery does

**Verification**: `make test` passes, gracefully skips on clusters without Gateway API.

---

### WO-T23: Namespace-scoped RBAC degradation

**Goal**: Work with namespace-scoped permissions instead of requiring cluster-wide read access.

Not every team can get ClusterRole. trustwatch should degrade gracefully to whatever permissions are available.

**Behavior**:
- On startup, probe RBAC with SelfSubjectAccessReview for each resource type
- Skip discoverers for resources the ServiceAccount can't access
- Log which discoverers were skipped and why
- `trustwatch now` header shows "Scope: cluster" or "Scope: namespace/payments"
- `--namespace` flag to restrict discovery to specific namespace(s)

**Files**:
- `internal/discovery/rbac.go` — permission probing
- `internal/discovery/rbac_test.go`
- `internal/discovery/orchestrator.go` — respect RBAC probe results

**Verification**: `make test` passes, restricted ServiceAccount still produces useful output.

---

### WO-T24: Grafana dashboard template

**Goal**: Ship a Grafana dashboard JSON with the Helm chart.

**Dashboard panels**:
- Cert expiry timeline (gauge per cert, color by remaining time)
- Discovery health (per-source success/failure)
- Finding severity distribution (pie/bar)
- Cert count by source (webhooks, secrets, mesh, external)

**Files**:
- `charts/trustwatch/dashboards/trustwatch.json`
- `charts/trustwatch/templates/dashboard-configmap.yaml` (Grafana sidecar pattern)
- `charts/trustwatch/values.yaml` — add `dashboard.enabled: true`

**Verification**: `helm template` renders valid ConfigMap, dashboard JSON imports cleanly in Grafana.

---

## Execution Order

```
WO-T01 → WO-T02 → WO-T03 → WO-T04 → WO-T05  (core discovery)
                                          ↓
WO-T06 → WO-T07 → WO-T08 → WO-T09       (mesh + external)
                                          ↓
WO-T10 → WO-T11 + WO-T12 + WO-T13       (aggregation + output)
                     ↓
                  WO-T14                   (serve integration)
                     ↓
         WO-T15 + WO-T16 + WO-T17        (packaging)
                     ↓
         WO-T18 → WO-T19 → WO-T20        (polish)
```

Critical path: T01 → T02 → T10 → T11 → T14 (minimum viable `now` + `serve`).

Next priorities: T21 (JSON output) → T22 (Gateway API) → T23 (namespace RBAC) → T24 (Grafana dashboard).
