---
name: trustwatch
description: Kubernetes trust surface monitoring — discovers expiring certificates on webhooks, API aggregation, and service mesh
user-invocable: false
metadata: {"requires":{"bins":["trustwatch"]}}
---

# trustwatch — Kubernetes Trust Surface Monitoring

You have access to `trustwatch`, a tool that discovers and monitors TLS certificates across Kubernetes clusters — webhooks, API aggregation, ingress, service mesh issuers, and external endpoints.

## Install

```bash
brew install ppiankov/tap/trustwatch
```

Or as kubectl plugin:

```bash
kubectl trustwatch now --context prod
```

## Commands

| Command | What it does |
|---------|-------------|
| `trustwatch now` | Scan cluster and show trust surface problems |
| `trustwatch now --output json` | Machine-readable scan results |
| `trustwatch serve` | Run as in-cluster service with web UI and /metrics |
| `trustwatch check` | CI/CD gate — exit non-zero on policy violations |
| `trustwatch apply` | Install TrustPolicy CRD |
| `trustwatch policy` | List active TrustPolicy resources |
| `trustwatch rules` | Generate PrometheusRule YAML |
| `trustwatch validate` | Validate config file |
| `trustwatch baseline save` | Save certificate snapshot as baseline |
| `trustwatch baseline check` | Compare scan against baseline |
| `trustwatch report` | Generate self-contained HTML compliance report |
| `trustwatch impact` | Show blast radius of rotating a cert or CA |
| `trustwatch version` | Print version |

## Key Flags

| Flag | Applies to | Description |
|------|-----------|-------------|
| `--output` / `-o` | now, check | Output: json, table, csv |
| `--quiet` / `-q` | now, check | Exit code only, no output |
| `--context` | now, serve, check | Kubernetes context |
| `--kubeconfig` | now, serve, check | Path to kubeconfig |
| `--namespace` | now, serve, check | Namespaces to scan (empty = all) |
| `--warn-before` | now, rules | Warn threshold duration |
| `--crit-before` | now, rules | Critical threshold duration |
| `--tunnel` | now, check | Deploy SOCKS5 relay for in-cluster DNS |
| `--history-db` | now, serve | SQLite history database path |
| `--check-revocation` | now, serve, check | Check OCSP/CRL revocation |
| `--detect-drift` | now, serve, check | Detect cert changes vs previous scan |
| `--max-severity` | check | Failure threshold (info, warn, critical) |

## Agent Usage Pattern

```bash
trustwatch now --context prod --output json
```

### JSON Output Structure

```json
{
  "exitCode": 0,
  "snapshot": {
    "at": "2026-02-20T12:00:00Z",
    "findings": [
      {
        "findingType": "EXPIRING",
        "severity": "critical",
        "source": "k8s.webhook",
        "target": "webhook.example.com:443",
        "namespace": "default",
        "subject": "CN=webhook.example.com",
        "issuer": "CN=Let's Encrypt",
        "notAfter": "2026-03-01T00:00:00Z",
        "notes": "Expires in 10 days",
        "remediation": "Rotate certificate"
      }
    ]
  }
}
```

### Parsing Examples

```bash
# Get exit code (0=healthy, 1=warn, 2=critical)
trustwatch now --context prod --quiet; echo $?

# List critical findings
trustwatch now --context prod --output json | jq '.snapshot.findings[] | select(.severity == "critical")'

# Count by severity
trustwatch now --context prod --output json | jq '.snapshot.findings | group_by(.severity) | map({severity: .[0].severity, count: length})'

# CI gate — fail on critical
trustwatch check --context prod --max-severity critical --output json
```

## Exit Codes

- `0` — no problems
- `1` — warnings (certs expiring within warn threshold)
- `2` — critical (certs expiring within crit threshold or expired)
- `3` — discovery or probe errors

## What trustwatch Does NOT Do

- Does not rotate certificates — discovers and reports only
- Does not use ML — deterministic cert inspection and threshold comparison
- Does not modify cluster state — read-only scanning
- Does not store data remotely — local SQLite history only
