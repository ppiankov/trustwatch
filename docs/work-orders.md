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
