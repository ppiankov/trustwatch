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

### WO-T25: cert-manager Certificate CR discovery

**Goal**: Discover certificate expiry from cert-manager `Certificate` resources without needing the TLS Secret.

Most clusters use cert-manager. Currently trustwatch only sees the resulting TLS Secret (WO-T04), missing cert-manager metadata: issuer reference, renewal time, ready condition, failure reasons.

**Discovery targets**:
- `Certificate` objects (`cert-manager.io/v1`) — read `status.notAfter`, `status.renewalTime`, `status.conditions`
- Link to issuer (`spec.issuerRef`) for context
- If `status.conditions` show `Ready=False`, escalate severity

**Behavior**:
- Gracefully skip if cert-manager CRDs not installed (check API discovery first)
- Deduplicate against Secret findings — if both Certificate and its Secret are found, prefer Certificate (richer metadata), suppress the Secret finding
- Report issuer name in finding metadata

**Files**:
- `internal/discovery/certmanager.go`
- `internal/discovery/certmanager_test.go`

**RBAC**: list/watch on `cert-manager.io` certificates (add to ClusterRole in Helm chart).

**Verification**: `make test` passes, gracefully skips on clusters without cert-manager.

---

### WO-T26: Finding deduplication

**Goal**: Same certificate referenced by multiple sources (Ingress + Secret + Gateway) appears as one finding with multiple sources listed.

Currently the same cert can appear 3 times in output — once per discoverer that found it. This is noise, not signal.

**Deduplication key**: SHA256 fingerprint of the leaf certificate.

**Behavior**:
- After all discoverers complete, group findings by cert fingerprint
- Merge into single finding with `sources: ["ingress/default/my-app", "secret/default/my-app-tls", "gateway/default/my-gw"]`
- Use highest severity from any source
- Keep earliest expiry (should be identical, but defensive)
- `--no-dedup` flag to disable (useful for debugging)

**Files**:
- `internal/discovery/dedup.go`
- `internal/discovery/dedup_test.go`
- `internal/discovery/orchestrator.go` — call dedup after collection

**Verification**: `make test` passes, finding count drops when same cert appears via multiple paths.

---

### WO-T27: Certificate chain validation

**Goal**: Detect broken certificate chains — not just expiry. A cert can be unexpired but have a broken chain, revoked issuer, or wrong SAN. That's a real outage cause trustwatch currently misses.

**Validation checks**:
- Chain completeness: leaf → intermediate(s) → root. Flag if any link missing
- Chain order: certs in `tls.crt` must be leaf-first. Flag misordered bundles
- Issuer match: each cert's `Issuer` must match the next cert's `Subject`
- SAN coverage: for Ingress/Gateway findings, verify the hostname appears in leaf SANs
- Self-signed detection: flag self-signed certs in non-CA positions

**Behavior**:
- Run chain validation after TLS probe or Secret parse (both provide raw cert bytes)
- New finding types: `BROKEN_CHAIN`, `WRONG_SAN`, `SELF_SIGNED_LEAF`, `MISORDERED_CHAIN`
- Severity: `BROKEN_CHAIN` = critical, `WRONG_SAN` = critical, `SELF_SIGNED_LEAF` = warn, `MISORDERED_CHAIN` = warn
- Chain validation runs against system trust store by default, configurable via `--ca-bundle`

**Files**:
- `internal/probe/chain.go` — chain validation logic
- `internal/probe/chain_test.go`
- `internal/store/types.go` — new finding types

**Verification**: `make test` passes, deliberately broken chain produces `BROKEN_CHAIN` finding.

---

### WO-T28: Signed container images and SBOM

**Goal**: Sign container images with Cosign/Sigstore and attach SBOM attestation. Table stakes for security tooling.

**Steps**:
1. Add `cosign sign` step to release workflow after image push
2. Generate SBOM with `syft` during build
3. Attach SBOM as Cosign attestation: `cosign attest --predicate sbom.spdx.json`
4. Document verification: `cosign verify ghcr.io/ppiankov/trustwatch:v0.x.x`
5. Add verification instructions to README install section

**Files**:
- `.github/workflows/release.yml` — add cosign sign + attest steps
- `README.md` — add verification section

**Verification**: `cosign verify` succeeds on published image, SBOM attestation retrievable.

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

All Phase 1 work orders (WO-T01 through WO-T28) are complete as of v0.1.5.

---

## Phase 2: Policy Engine + Persistence (v0.2.x)

---

### WO-T29: TrustPolicy CRD

**Goal**: Replace annotations + ConfigMap with a proper custom resource for declaring trust surfaces. Biggest UX gap — currently scattered config.

**TrustPolicy spec**:
```yaml
apiVersion: trustwatch.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: production-policy
  namespace: default
spec:
  targets:
    - host: api.example.com
      port: 443
      sni: api.example.com
    - service: payment-service
      namespace: payments
      port: 8443
  thresholds:
    warn: 720h    # 30 days
    critical: 168h # 7 days
  rules:
    - minKeyBits: 2048
    - disallowSHA1: true
    - requiredIssuer: "CN=Internal CA"
  schedule:
    interval: 5m
```

**Steps**:
1. Define CRD schema in `api/v1alpha1/trustpolicy_types.go`
2. Generate CRD YAML with `controller-gen` (no full operator framework — just types + YAML)
3. Create `internal/policy/loader.go` — watch TrustPolicy CRs, build target list + rules
4. Create `internal/policy/evaluator.go` — evaluate CertFinding against policy rules
5. Integrate into discovery orchestrator: merge CRD targets with annotation targets
6. Fall back to annotation-based config when no CRD is installed
7. Add `trustwatch apply` command to install CRD into cluster
8. Add `trustwatch policy` command to list active policies and their status

**Files**:
- `api/v1alpha1/trustpolicy_types.go` — CRD types
- `api/v1alpha1/zz_generated.deepcopy.go` — generated
- `deploy/crds/trustpolicy-crd.yaml` — CRD manifest
- `internal/policy/loader.go` + `loader_test.go`
- `internal/policy/evaluator.go` + `evaluator_test.go`
- `internal/cli/apply.go`, `internal/cli/policy.go`

**Verification**: `make test` passes, `trustwatch apply` installs CRD, TrustPolicy CRs produce findings.

---

### WO-T30: SPIFFE/SPIRE Trust Bundle Discovery

**Goal**: Discover SPIFFE trust bundles and detect expiring root certificates. Zero-trust identity is increasingly common alongside mesh — trust bundle expiry matters.

**Details**:
- Query SPIRE server's trust bundle endpoint (gRPC or Workload API)
- Parse SPIFFE trust bundle JWKs → extract X.509 certs
- Probe bundle root cert expiry as a trust surface finding
- Support both in-cluster SPIRE agent and standalone endpoint

**Steps**:
1. Create `internal/discovery/spiffe.go` — SPIFFEDiscoverer
2. Discover SPIRE agent socket at `/run/spire/sockets/agent.sock` (configurable)
3. Call `FetchX509SVID` or trust bundle endpoint
4. Extract root CAs from bundle, create CertFinding for each
5. Add `trustwatch.dev/spiffe-endpoint` annotation for custom endpoints
6. Mark findings as source `spiffe`

**Files**:
- `internal/discovery/spiffe.go` + `spiffe_test.go`
- `internal/store/store.go` — add `SourceSPIFFE` constant

**Verification**: `make test` passes, mock SPIFFE bundle produces correct findings.

---

### WO-T31: Historical Snapshots with SQLite

**Goal**: Persist scan snapshots for trend analysis. Currently everything is in-memory — no history. Enable "this cert has been expiring for 3 scans" tracking.

**Details**:
- SQLite database (single file, zero config, embeds via `modernc.org/sqlite` for CGO-free builds)
- Store each snapshot with timestamp, findings, errors
- Query API: latest N snapshots, findings by host, trend for specific cert
- Retention policy: keep N snapshots (default 1000) or T duration (default 90d)

**Steps**:
1. Create `internal/history/store.go` — SQLite-backed snapshot history
2. Schema: `snapshots(id, timestamp, finding_count, error_count)`, `findings(snapshot_id, host, port, subject, not_after, severity, source, chain_valid)`
3. Auto-migrate schema on first run
4. In `serve` mode: persist each scan to history DB
5. Add `--history-db` flag (default: `./trustwatch.db`, disable with `--history-db=none`)
6. Add `/api/v1/history` endpoint: query past snapshots
7. Add `/api/v1/trend?host=...` endpoint: expiry trend for specific host

**Files**:
- `internal/history/store.go` + `store_test.go`
- `internal/history/migrate.go` — schema migrations
- `internal/web/history.go` — history API handlers
- `internal/cli/serve.go` — add `--history-db` flag

**Verification**: `make test` passes, serve mode persists snapshots, history API returns past scans.

---

### WO-T32: Cloud Provider Certificate Discovery

**Goal**: Discover and monitor certs from AWS ACM, GCP managed certs, and Azure Key Vault. Platform teams care about these alongside in-cluster certs.

**Details**:
- Each provider is a separate discoverer with its own auth
- AWS ACM: list certs via `acm:ListCertificates`, get expiry via `acm:DescribeCertificate`
- GCP: `compute.sslCertificates.list` for managed certs
- Azure: Key Vault `getCertificates` + `getCertificate` for expiry
- Auth: use ambient credentials (IAM role, workload identity, managed identity)
- All read-only — never modify certs

**Steps**:
1. Create `internal/discovery/aws_acm.go` — ACM cert discovery
2. Create `internal/discovery/gcp_certs.go` — GCP managed cert discovery
3. Create `internal/discovery/azure_keyvault.go` — Azure Key Vault cert discovery
4. Enable via config: `--cloud aws,gcp` or TrustPolicy CRD
5. Each discoverer is optional — build-tagged so binaries without cloud SDK stay lean
6. Add `SourceAWSACM`, `SourceGCPCerts`, `SourceAzureKeyVault` to store constants

**Files**:
- `internal/discovery/aws_acm.go` + `aws_acm_test.go`
- `internal/discovery/gcp_certs.go` + `gcp_certs_test.go`
- `internal/discovery/azure_keyvault.go` + `azure_keyvault_test.go`

**Verification**: `make test` passes, mock cloud responses produce correct findings.

---

### WO-T33: cert-manager Renewal Health

**Goal**: Detect stuck cert-manager renewals — CertificateRequest pending, ACME challenge failing — rather than waiting for the cert to expire.

**Problem**: cert-manager Certificate CRs show `Ready=True` until they're not. A stuck renewal (challenge solver misconfigured, DNS propagation failure, rate limit hit) is invisible until the cert actually expires. By then it's too late.

**Details**:
- Check `Certificate.status.conditions` for `Ready=False` with `Reason=` indicating failure
- Check `CertificateRequest` objects for stale `Pending` state (age > 1h)
- Check `Challenge` objects for failed ACME challenges
- New finding types: `RENEWAL_STALLED`, `CHALLENGE_FAILED`, `REQUEST_PENDING`

**Steps**:
1. Extend `internal/discovery/certmanager.go` — query CertificateRequest + Challenge CRs
2. Add staleness threshold: CertificateRequest pending > 1h = warn, > 24h = critical
3. Add `RENEWAL_STALLED` finding when Certificate not Ready and renewal overdue
4. Add `CHALLENGE_FAILED` finding from Challenge `.status.reason`
5. RBAC: list/watch on `cert-manager.io` certificates, certificaterequests, challenges

**Files**:
- `internal/discovery/certmanager.go` — extend existing discoverer
- `internal/discovery/certmanager_test.go` — extend tests

**Verification**: `make test` passes, mock stalled renewal produces correct findings.

---

### WO-T34: Policy Rules Engine

**Goal**: Beyond time thresholds — enforce "all certs in namespace X must use issuer Y", "no RSA keys under 2048 bits", "no SHA-1 signatures". This is where TrustPolicy CRD (WO-T29) becomes powerful.

**Requires**: WO-T29 (TrustPolicy CRD).

**Rule types**:
- `minKeyBits: 2048` — reject weak keys
- `disallowSHA1: true` — reject SHA-1 signatures
- `requiredIssuer: "CN=Internal CA"` — enforce issuer
- `requiredSAN: "*.example.com"` — enforce SAN patterns
- `maxChainDepth: 3` — reject deep chains
- `disallowSelfSigned: true` — reject self-signed leaves (except roots)

**Steps**:
1. Define rule types in `api/v1alpha1/trustpolicy_types.go`
2. Create `internal/policy/rules.go` — rule evaluation functions
3. Each rule returns a finding if violated: `POLICY_VIOLATION` with details
4. Evaluate after chain validation — rules see full chain context
5. `trustwatch rules --export` generates PrometheusRule from active policies

**Files**:
- `api/v1alpha1/trustpolicy_types.go` — extend spec
- `internal/policy/rules.go` + `rules_test.go`
- `internal/policy/evaluator.go` — wire rules into evaluation

**Verification**: `make test` passes, policy violations produce correct findings with severity.

---

### WO-T35: Web UI Interactive Improvements

**Goal**: Current UI is a static table with auto-refresh. Add interactive filtering, detail panel, and trend sparklines for platform teams.

**Details**:
- Filter by source, severity, namespace, host (client-side)
- Click row → detail panel with full cert chain, policy violations, history trend
- Trend sparklines per cert (requires WO-T31 history)
- Dark/light mode toggle
- Still no JS framework — vanilla JS + CSS, ship as embedded static files

**Steps**:
1. Add filter bar: text search + severity/source dropdowns
2. Add detail panel: slide-out showing cert subject, issuer chain, SANs, key info, policy violations
3. Add trend sparkline: mini chart showing days-until-expiry over last N scans
4. Add sort by column (name, expiry, severity, source)
5. Keep it lightweight — no npm, no build step, embedded in Go binary

**Files**:
- `internal/web/static/` — HTML, CSS, JS updates
- `internal/web/handlers.go` — serve trend data

**Verification**: Visual verification, no new external dependencies.

---

### WO-T36: Multi-Cluster Federation

**Goal**: `serve` mode currently watches one cluster. A federated view (multiple kubeconfigs or hub-spoke) is the main scaling story for platform teams managing multiple clusters.

**Details**:
- Accept multiple `--kubeconfig` paths or `--context` names
- Discover independently per cluster, merge into unified snapshot
- Each finding tagged with cluster name
- Web UI and metrics include cluster label
- Hub-spoke mode: central trustwatch queries remote trustwatch instances via `/api/v1/snapshot`

**Steps**:
1. Add `--kubeconfig` multi-value flag and `--cluster-name` mapping
2. Create `internal/discovery/multicluster.go` — parallel orchestration across clusters
3. Add `cluster` label to Prometheus metrics
4. Add cluster column to web UI table
5. Hub-spoke: add `--remote` flag pointing to remote trustwatch `/api/v1/snapshot` endpoints
6. Merge remote snapshots into local view

**Files**:
- `internal/discovery/multicluster.go` + `multicluster_test.go`
- `internal/metrics/collector.go` — add cluster label
- `internal/web/` — cluster column in UI

**Verification**: `make test` passes, multi-context produces findings from both clusters.

---

### WO-T37: OpenTelemetry Trace Instrumentation

**Goal**: Trace discovery + probe latency per source for debugging slow scans in large clusters.

**Details**:
- Instrument orchestrator: span per discoverer, span per TLS probe
- Export via OTLP (gRPC) to any OTel collector
- Enabled via `--otel-endpoint` flag (off by default)
- Trace attributes: source, host, port, namespace, duration
- No performance impact when disabled (noop tracer)

**Steps**:
1. Add `go.opentelemetry.io/otel` dependency
2. Instrument `internal/discovery/orchestrator.go` — span per discoverer
3. Instrument `internal/probe/probe.go` — span per TLS handshake
4. Add `--otel-endpoint` flag to root command
5. Configure tracer provider in CLI init

**Files**:
- `internal/discovery/orchestrator.go` — add tracing spans
- `internal/probe/probe.go` — add tracing spans
- `internal/cli/root.go` — otel flag + tracer init

**Verification**: `make test` passes, trace spans visible in Jaeger/Zipkin when endpoint configured.

---

## Phase 2 Execution Order

```
WO-T29 (TrustPolicy CRD) ──→ WO-T34 (Policy Rules)
         ↓
WO-T30 (SPIFFE) ─────────────────────────────────────→ standalone
WO-T31 (History) ────→ WO-T35 (Web UI) ──────────────→ depends on history
WO-T32 (Cloud Certs) ─────────────────────────────────→ standalone
WO-T33 (cert-manager Renewal) ────────────────────────→ standalone
WO-T36 (Multi-Cluster) ───────────────────────────────→ standalone
WO-T37 (OTel Traces) ─────────────────────────────────→ standalone
```

Critical path: T29 → T34 (policy engine needs CRD first).
High-value standalone: T33 (renewal health), T31 (history), T30 (SPIFFE).

---

## Phase 3: Trust Surface Depth

Phase 3 extends trustwatch from certificate expiry monitoring to full trust surface auditing. The probe already does the TLS handshake — Phase 3 extracts more value from that handshake and builds dependency intelligence on top of existing discovery data.

### WO-T38: TLS posture audit

**Goal**: Extract TLS protocol and cipher data from the handshake the probe already performs. Report weak configurations as findings.

**Details**:
- The probe calls `tls.Client()` and reads `ConnectionState()` — this already contains `Version`, `CipherSuite`, `NegotiatedProtocol`
- Extend `probe.Result` to capture these fields
- Add new finding types for weak configurations
- Evaluate against hardcoded thresholds (no policy CRD needed — policy engine can override later)

**New finding types**:
- `WEAK_TLS_VERSION` — TLS 1.0 or 1.1 accepted (severity: critical)
- `WEAK_CIPHER` — RC4, 3DES, NULL, export ciphers (severity: critical); CBC-mode ciphers (severity: warn)
- `NO_HSTS` — HTTPS endpoint missing `Strict-Transport-Security` header (severity: warn, only for `https://` scheme probes)

**Steps**:
1. Extend `probe.Result`: add `TLSVersion uint16`, `CipherSuite uint16`, `NegotiatedProtocol string`, `HSTSHeader string`
2. Capture from `tlsConn.ConnectionState()` after handshake — zero additional network cost
3. For `https://` targets only: issue HTTP GET to read HSTS header (optional, behind flag `--check-hsts`)
4. Add `internal/probe/posture.go` — `EvaluatePosture(Result) []PostureFinding` with weak version/cipher/HSTS checks
5. Wire posture findings into orchestrator — append to snapshot alongside cert findings
6. Add `TLSVersion`, `CipherSuite` fields to `CertFinding` (or create separate `PostureFinding` type)
7. Update TUI/table/JSON formatters to display posture findings

**Files**:
- `internal/probe/tls.go` — extend Result struct, capture ConnectionState fields
- `internal/probe/posture.go` — new file: posture evaluation logic
- `internal/probe/posture_test.go` — new file: tests with known-weak configurations
- `internal/store/store.go` — add TLS posture fields or new finding types
- `internal/discovery/orchestrator.go` — wire posture evaluation after probe
- `internal/monitor/tui.go`, `table.go`, `json.go` — display posture findings

**Verification**: `make test` passes with -race. Probe against a TLS 1.2 endpoint returns `TLSVersion` and `CipherSuite`. Probe against intentionally weak test server returns `WEAK_TLS_VERSION` finding.

---

### WO-T39: kubectl plugin packaging

**Goal**: Package trustwatch as a kubectl plugin installable via krew.

**Details**:
- kubectl discovers plugins by finding `kubectl-<name>` binaries on PATH
- Krew is the package manager — needs a manifest YAML in `krew-index` or a custom plugin index
- The binary already works standalone — this is packaging, not code changes

**Steps**:
1. Add `kubectl-trustwatch` symlink/rename target to Makefile (`make kubectl-plugin`)
2. Create `.krew.yaml` manifest with plugin metadata, platforms, sha256
3. Add krew install instructions to README
4. Update Homebrew formula to also install `kubectl-trustwatch` symlink
5. Add CI step to generate krew manifest on release (sha256 from goreleaser)

**Files**:
- `Makefile` — add `kubectl-plugin` target
- `.krew.yaml` — new file: krew plugin manifest
- `.goreleaser.yml` — add kubectl-trustwatch binary name
- `README.md` — add krew install instructions

**Verification**: `kubectl trustwatch now --kubeconfig ...` works after `make kubectl-plugin && cp bin/kubectl-trustwatch /usr/local/bin/`. `kubectl plugin list` shows trustwatch.

---

### WO-T40: Revocation checking (OCSP + CRL)

**Goal**: Check certificate revocation status during probe. A revoked intermediate silently breaks trust chains — trustwatch already has the chain, checking revocation is the natural next step.

**Details**:
- Parse `OCSPServer` URLs from leaf certificate's Authority Information Access (AIA) extension
- Parse `CRLDistributionPoints` from certificate extensions
- OCSP: build request, send to responder, parse response status
- CRL: fetch from distribution point, parse, check serial number against revoked list
- Cache CRL responses (they're large and change infrequently) — in-memory with TTL matching CRL nextUpdate
- OCSP stapling: check `ConnectionState().OCSPResponse` from the handshake (already available, currently discarded)

**New finding types**:
- `CERT_REVOKED` — OCSP or CRL confirms revocation (severity: critical)
- `OCSP_UNREACHABLE` — OCSP responder unreachable after retries (severity: warn)
- `CRL_STALE` — CRL past its nextUpdate time, can't confirm status (severity: warn)
- `OCSP_STAPLE_MISSING` — server supports OCSP but doesn't staple (severity: info)
- `OCSP_STAPLE_INVALID` — stapled response is expired or malformed (severity: warn)

**Steps**:
1. Extend `probe.Result`: add `OCSPResponse []byte` from `ConnectionState().OCSPResponse`
2. Create `internal/revocation/ocsp.go` — build OCSP request, send HTTP POST to AIA responder, parse response
3. Create `internal/revocation/crl.go` — fetch CRL from distribution point, parse ASN.1, check serial
4. Create `internal/revocation/cache.go` — in-memory CRL cache with TTL from nextUpdate
5. Wire into orchestrator: after probe + chain validation, run revocation check
6. Flag `--check-revocation` (off by default — adds network calls per cert)

**Files**:
- `internal/probe/tls.go` — capture OCSPResponse from ConnectionState
- `internal/revocation/ocsp.go` — new file: OCSP checking
- `internal/revocation/crl.go` — new file: CRL checking
- `internal/revocation/cache.go` — new file: CRL cache
- `internal/revocation/revocation_test.go` — new file: tests with mock OCSP/CRL responders
- `internal/store/store.go` — add revocation finding types
- `internal/discovery/orchestrator.go` — wire revocation checks

**Verification**: `make test` passes with -race. Test with a known-revoked certificate returns `CERT_REVOKED` finding. Test with unreachable OCSP returns `OCSP_UNREACHABLE`.

---

### WO-T41: CI/CD gate command (`trustwatch check`)

**Goal**: Pre-deploy validation command that exits non-zero on policy violations. Makes trustwatch a structural safeguard in pipelines, not just monitoring.

**Details**:
- `trustwatch check` runs discovery + probe + policy evaluation, then exits with code based on findings
- Designed for CI/CD: no TUI, no serve mode, just scan → evaluate → exit code
- Supports `--policy` flag to specify policy file (YAML or TrustPolicy CRD)
- Supports `--max-severity` flag: fail if any finding at or above this severity (default: critical)
- Machine-readable output: `--output json` for pipeline parsing

**Usage**:
```yaml
# GitHub Actions
- name: Trust surface check
  run: trustwatch check --policy policy.yaml --max-severity warn --output json
```

**Steps**:
1. Create `internal/cli/check.go` — new Cobra command
2. Reuse orchestrator for discovery + probe
3. Reuse policy engine for evaluation
4. Exit code logic: 0=pass, 1=warn findings, 2=critical findings, 3=error
5. Add `--policy` flag (file path to policy YAML)
6. Add `--max-severity` flag (info/warn/critical — fail threshold)
7. Add `--deploy-window` flag (e.g., `24h` — fail if any cert expires within window)
8. JSON output includes finding count per severity + list of violations

**Files**:
- `internal/cli/check.go` — new file: check command implementation
- `internal/cli/check_test.go` — new file: tests for exit code logic, severity threshold
- `internal/cli/root.go` — register check subcommand

**Verification**: `make test` passes. `trustwatch check --policy test-policy.yaml` returns exit code 0 when no violations, exit code 2 when critical findings exist. JSON output parseable by `jq`.

---

### WO-T42: Rotation impact analysis

**Goal**: Answer "if I rotate this CA, what breaks?" by building a dependency graph from discovered issuer chains.

**Details**:
- trustwatch already discovers every cert and its full chain (issuer, intermediates, root)
- Build a reverse index: issuer → list of findings that depend on it
- `trustwatch impact --issuer "CN=My Intermediate"` lists all services, namespaces, severity affected
- `trustwatch impact --serial <hex>` for exact cert match
- Show blast radius: count of affected findings, namespaces, clusters

**Steps**:
1. Create `internal/impact/graph.go` — build issuer dependency graph from snapshot findings
2. Create `internal/impact/query.go` — query by issuer DN, serial, or subject pattern
3. Create `internal/cli/impact.go` — Cobra command with `--issuer`, `--serial`, `--subject` flags
4. Output: table (default) or JSON with affected findings grouped by namespace/cluster
5. Severity inheritance: if root is rotated, all transitive dependents inherit the blast radius

**Files**:
- `internal/impact/graph.go` — new file: issuer dependency graph
- `internal/impact/query.go` — new file: query + blast radius calculation
- `internal/impact/impact_test.go` — new file: tests with multi-level issuer chains
- `internal/cli/impact.go` — new file: impact command
- `internal/cli/root.go` — register impact subcommand

**Verification**: `make test` passes with -race. Given a snapshot with 3 certs sharing an intermediate, `trustwatch impact --issuer "CN=intermediate"` returns all 3 findings with namespace and severity.

---

### WO-T43: Certificate Transparency log monitoring

**Goal**: Watch CT logs for certificates issued for your domains that you didn't request. Detects rogue CA issuance, compromised ACME accounts, and shadow IT cert provisioning.

**Details**:
- Query CT log APIs (Google Argon, Cloudflare Nimbus, etc.) for certificates matching configured domains
- Compare against known certificates from trustwatch discovery
- Flag unknown certificates as findings
- Runs as a background discoverer in `serve` mode or ad-hoc via `trustwatch ct-check`

**New finding types**:
- `CT_UNKNOWN_CERT` — certificate in CT log not found in cluster (severity: warn)
- `CT_ROGUE_ISSUER` — certificate issued by unexpected CA (severity: critical)

**Steps**:
1. Create `internal/ct/monitor.go` — CT log API client, domain matching, known-cert comparison
2. Create `internal/ct/monitor_test.go` — tests with mock CT API responses
3. Create `internal/discovery/ct.go` — CTDiscoverer implementing Discoverer interface
4. Add `--ct-domains` flag (comma-separated list of domains to monitor)
5. Add `--ct-interval` flag for serve mode polling (default: 1h)
6. Register as optional discoverer in orchestrator

**Files**:
- `internal/ct/monitor.go` — new file: CT log API client
- `internal/ct/monitor_test.go` — new file: tests
- `internal/discovery/ct.go` — new file: CTDiscoverer
- `internal/cli/root.go` — add CT flags

**Verification**: `make test` passes. Mock CT API returns a cert not in snapshot → `CT_UNKNOWN_CERT` finding generated.

---

## Phase 3 Execution Order

```
WO-T38 (TLS posture) ────────────→ standalone, low effort, high value
WO-T39 (kubectl plugin) ─────────→ standalone, trivial packaging
WO-T40 (Revocation) ─────────────→ standalone, needs new internal/revocation/
WO-T41 (CI/CD gate) ─────────────→ standalone, reuses orchestrator + policy
WO-T42 (Impact analysis) ────────→ standalone, needs snapshot data
WO-T43 (CT monitoring) ──────────→ standalone, needs external API
```

Suggested shipping order:
- **3a** (ship together): WO-T38 (TLS posture) + WO-T39 (kubectl plugin)
- **3b** (ship together): WO-T40 (Revocation) + WO-T41 (CI/CD gate)
- **3c** (ship together): WO-T42 (Impact analysis) + WO-T43 (CT monitoring)

No dependencies between Phase 3 WOs — all can be parallelized if needed.

---

### WO-T44: Rotation-aware expiry suppression

**Goal**: Don't warn about certificate expiry when cert-manager is actively and healthily managing the renewal. Currently trustwatch sees a cert expiring in 48h and raises critical — even if cert-manager is configured to rotate it every 48h and renewal is working perfectly.

**The problem**:
A cert-manager Certificate with `duration: 48h, renewBefore: 24h` means the cert is always within trustwatch's default warning threshold (30d). trustwatch raises warn/critical on every scan, creating permanent noise for a cert that is being managed correctly.

**Details**:
- During discovery, trustwatch already reads cert-manager Certificate CRs (WO-T25) and renewal health (WO-T33)
- Cross-reference: if a cert's expiry is within the warn/crit threshold BUT a cert-manager Certificate CR manages it AND the Certificate is Ready=True → suppress the expiry finding or downgrade to info
- The logic: "this cert expires soon, but cert-manager knows about it and renewal is healthy — not a problem"
- If the Certificate is NOT Ready, or renewal is stalled/failed → keep the original severity (or escalate)

**Steps**:
1. In orchestrator post-processing: build a map of cert-manager-managed certs (by namespace/name or by serial/issuer match)
2. For each expiry finding, check if a healthy cert-manager Certificate CR covers it
3. If covered and healthy: set `FindingType` to `MANAGED_EXPIRY`, downgrade severity to info, add note "managed by cert-manager Certificate <name>, renewal healthy"
4. If covered but unhealthy: keep severity, add note "managed by cert-manager Certificate <name>, renewal UNHEALTHY"
5. Add `--ignore-managed` flag to suppress managed expiry findings entirely (default: show as info)

**New finding types**:
- `MANAGED_EXPIRY` — cert expiring but renewal is healthy (severity: info)

**Files**:
- `internal/discovery/orchestrator.go` — post-processing step: cross-reference expiry findings with cert-manager state
- `internal/discovery/orchestrator_test.go` — tests: managed cert suppressed, unmanaged cert kept, unhealthy managed cert escalated
- `internal/store/store.go` — add `MANAGED_EXPIRY` finding type constant

**Verification**: `make test` passes with -race. A cert expiring in 24h managed by a healthy cert-manager Certificate → severity info with `MANAGED_EXPIRY` type. Same cert with stalled renewal → severity critical preserved.

---

### WO-T45: Excessive rotation frequency detection

**Goal**: Flag certificates with rotation frequencies that increase operational risk without proportional security gain. Daily rotation of an intermediate CA is churn, not security.

**The problem**:
A Linkerd identity issuer Certificate with `duration: 48h` rotates the intermediate CA daily. This:
- Increases fragility (if cert-manager hiccups, mesh dies in 48h)
- Creates constant Secret churn and audit log noise
- Provides marginal security improvement over 6-12 month rotation for most threat models
- Violates the principle: "if extraordinary effort is needed to maintain safety, the architecture is broken"

**Details**:
- Read cert-manager Certificate CR `spec.duration` and `spec.renewBefore`
- Compare against recommended thresholds based on certificate role:
  - Trust anchor / root CA: 5-10 years is normal, <1 year is excessive rotation
  - Intermediate CA / identity issuer: 6-12 months is normal, <7 days is excessive
  - Leaf / workload cert: hours-to-days is normal, no floor
- Detect role from context: Linkerd trust anchor (source=mesh.linkerd, name contains "trust-anchor"), Linkerd identity issuer (source=mesh.linkerd, name contains "identity"), general CA (isCA=true in cert), leaf (everything else)
- The thresholds are opinionated defaults — overridable via TrustPolicy CRD rules

**New finding types**:
- `EXCESSIVE_ROTATION` — rotation frequency higher than recommended for cert role (severity: warn)

**Recommended rotation thresholds** (defaults, overridable via policy):
| Certificate role | Min recommended duration | Rationale |
|-----------------|------------------------|-----------|
| Trust anchor / root CA | 1 year | Roots are trust distribution points, not attack surfaces |
| Intermediate CA / issuer | 30 days | Balance between blast radius and operational stability |
| Leaf / workload | no minimum | Short-lived by design |

**Steps**:
1. Create `internal/rotation/analyzer.go` — analyze Certificate CR duration against role-based thresholds
2. Detect certificate role from source kind, name patterns, and isCA flag
3. Compare `spec.duration` against minimum threshold for detected role
4. Generate `EXCESSIVE_ROTATION` finding with notes explaining the risk and recommended duration
5. Wire into orchestrator as a post-processing step after cert-manager discovery
6. Make thresholds configurable via TrustPolicy CRD `rotationPolicy` rules (future, after WO-T34)

**Files**:
- `internal/rotation/analyzer.go` — new file: rotation frequency analysis
- `internal/rotation/analyzer_test.go` — new file: tests for role detection and threshold comparison
- `internal/store/store.go` — add `EXCESSIVE_ROTATION` finding type constant
- `internal/discovery/orchestrator.go` — wire rotation analysis after cert-manager discovery

**Verification**: `make test` passes with -race. A Linkerd identity issuer Certificate with `duration: 48h` → `EXCESSIVE_ROTATION` finding with warn severity. Same cert with `duration: 8760h` (1 year) → no finding. A workload cert with `duration: 1h` → no finding (short-lived leaf is expected).

---

## Phase 4: Operational Readiness, Alerting & Integrations, Advanced Analysis

### WO-T46: Remediation playbooks

**Goal**: Add actionable fix suggestions to each finding type. When trustwatch reports a problem, show the user exactly what to do about it.

**Details**:
- Create `internal/remediation/playbook.go` — map FindingType + Source → remediation steps
- Each playbook entry: summary (one line), steps ([]string), docs URL (optional)
- Cover all existing finding types: expiry (warn/critical), MANAGED_EXPIRY, RENEWAL_STALLED, CHALLENGE_FAILED, REQUEST_PENDING, EXCESSIVE_ROTATION, CT_UNKNOWN_CERT, CT_ROGUE_ISSUER, POLICY_VIOLATION, BROKEN_CHAIN, WEAK_TLS_VERSION, WEAK_CIPHER, CERT_REVOKED
- Add `Remediation` field to CertFinding (string, populated in orchestrator post-processing)
- Display in TUI detail panel, web UI detail panel, and JSON output
- Wire into orchestrator as final post-processing step (after policy evaluation)

**Files**:
- `internal/remediation/playbook.go` — new: playbook lookup
- `internal/remediation/playbook_test.go` — new: tests
- `internal/store/store.go` — add Remediation field
- `internal/discovery/orchestrator.go` — wire playbook step
- `internal/monitor/tui.go` — show remediation in detail view
- `internal/web/handler.go` — include in finding row

**Verification**: `make check` passes. Every non-info finding type has a non-empty remediation string.

### WO-T47: PagerDuty integration

**Goal**: Send PagerDuty incidents for critical findings, with automatic resolve when findings clear.

**Details**:
- Add PagerDuty Events API v2 support to `internal/notify/`
- New notifier type: `pagerduty` with routing key config
- Trigger events for critical findings, resolve when finding disappears from next scan
- Track incident dedup keys (source + namespace + name) across scans
- Respect existing cooldown and severity filtering

**Files**:
- `internal/notify/pagerduty.go` — new
- `internal/notify/pagerduty_test.go` — new
- `internal/notify/notify.go` — add PagerDuty dispatch
- `internal/config/config.go` — add RoutingKey to webhook config

**Verification**: `make check` passes. PagerDuty notifier sends trigger and resolve events via httptest mock.

### WO-T48: Compliance snapshot report

**Goal**: Generate a standalone HTML report from a scan snapshot, suitable for compliance audits and email distribution.

**Details**:
- `trustwatch report` command — runs scan, generates self-contained HTML file
- HTML includes: scan timestamp, cluster name, finding summary table, severity counts, per-finding details
- All CSS inline (no external dependencies), printable
- Optional: `--output-file report.html` (default: stdout)
- Uses `html/template` with embedded template

**Files**:
- `internal/cli/report.go` — new: Cobra command
- `internal/report/html.go` — new: HTML template + renderer
- `internal/report/html_test.go` — new: tests

**Verification**: `make check` passes. Generated HTML is valid, contains finding data.

### WO-T49: Certificate drift detection

**Goal**: Compare consecutive snapshots and flag unexpected certificate changes — new certs appearing, certs disappearing, serial number changes, issuer changes.

**Details**:
- Uses existing history store (SQLite) to compare current scan vs previous
- Drift types: `CERT_NEW` (info), `CERT_GONE` (warn), `SERIAL_CHANGED` (info), `ISSUER_CHANGED` (warn)
- Match findings across snapshots by (source, namespace, name) composite key
- Wire into orchestrator as optional post-processing (requires history store)
- `--detect-drift` flag on `now` and `serve` commands (requires `--history-db`)

**Files**:
- `internal/drift/detector.go` — new: snapshot comparison logic
- `internal/drift/detector_test.go` — new: tests
- `internal/discovery/orchestrator.go` — add WithDriftDetection option
- `internal/cli/now.go` + `serve.go` — add `--detect-drift` flag

**Verification**: `make check` passes. Two scans with changed serial → SERIAL_CHANGED finding.

### WO-T50: Probe retry with exponential backoff

**Goal**: Retry failed TLS probes with backoff to handle transient network issues.

**Details**:
- Add retry logic to `internal/probe/tls.go` Probe function
- Default: 2 retries with exponential backoff (1s, 2s)
- Configurable via probe options
- Only retry on connection errors, not TLS handshake failures (those are definitive)
- Track retry count in ProbeResult for observability

**Files**:
- `internal/probe/tls.go` — add retry wrapper
- `internal/probe/tls_test.go` — test retry on transient failure

**Verification**: `make check` passes. Probe retries on connection refused, not on TLS error.

### WO-T51: Grafana annotation push

**Goal**: Push scan events as Grafana annotations so certificate issues appear on dashboards with context.

**Details**:
- New notifier type: `grafana` — POST to Grafana Annotations API
- Annotation includes: severity summary, finding count, tags
- Only fires when findings change (not on every scan cycle)
- Config: Grafana URL + API key + optional dashboard ID

**Files**:
- `internal/notify/grafana.go` — new
- `internal/notify/grafana_test.go` — new
- `internal/notify/notify.go` — add Grafana dispatch
- `internal/config/config.go` — add APIKey to webhook config

**Verification**: `make check` passes. Grafana notifier sends annotation via httptest mock.
