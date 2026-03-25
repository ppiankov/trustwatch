# Finding Types Reference

Every finding trustwatch produces has a severity, source, and optionally a finding type. This document describes each finding type, what triggers it, and how to fix it.

## Named Finding Types

These appear in the `findingType` field of the JSON output and drive specific remediation playbooks.

### SECRET_NOT_FOUND

**Severity:** warn
**Source:** `k8s.ingressTLS`
**Trigger:** An Ingress references a TLS secretName that does not exist in the namespace.
**Fix:** Create the missing TLS secret, or remove the `secretName` from the Ingress TLS stanza if TLS is not needed. If using cert-manager, create a Certificate resource targeting the secret name.

### MANAGED_EXPIRY

**Severity:** info
**Source:** any (post-processing)
**Trigger:** A certificate is within the expiry warning threshold, but a healthy cert-manager Certificate resource manages it and renewal is working.
**Fix:** No action required. cert-manager will renew the certificate automatically.

### RENEWAL_STALLED

**Severity:** warn/critical
**Source:** `certmanager.renewal`
**Trigger:** A cert-manager CertificateRequest has been stuck in a pending state beyond the staleness threshold (>1h = warn, >24h = critical).
**Fix:** Check cert-manager logs, issuer configuration, and RBAC. Run: `kubectl describe certificaterequest -n <namespace>`

### CHALLENGE_FAILED

**Severity:** warn
**Source:** `certmanager.renewal`
**Trigger:** An ACME challenge has failed (DNS propagation, HTTP reachability, rate limit).
**Fix:** Check DNS records, HTTP reachability, and issuer account credentials. Run: `kubectl describe challenge -n <namespace>`

### REQUEST_PENDING

**Severity:** warn
**Source:** `certmanager.renewal`
**Trigger:** A cert-manager Certificate has `Ready=False` and the CertificateRequest is pending.
**Fix:** Check the Certificate status and issuer health. Run: `kubectl describe certificate <name> -n <namespace>`. Common cause: the referenced Issuer or ClusterIssuer does not exist.

### EXCESSIVE_ROTATION

**Severity:** warn
**Source:** `certmanager.renewal`
**Trigger:** A certificate's `spec.duration` is shorter than recommended for its role (e.g., an intermediate CA rotating daily).
**Fix:** Increase `spec.duration` in the cert-manager Certificate CR to reduce rotation frequency. Recommended minimums: trust anchor 1 year, intermediate CA 30 days, leaf/workload no minimum.

### CT_UNKNOWN_CERT

**Severity:** warn
**Source:** `ct`
**Trigger:** A certificate was found in Certificate Transparency logs for a monitored domain that does not appear in the cluster's certificate inventory.
**Fix:** Investigate whether this is a legitimate certificate issued outside the cluster or a potential compromise.

### CT_ROGUE_ISSUER

**Severity:** critical
**Source:** `ct`
**Trigger:** A certificate in CT logs for a monitored domain was issued by an unexpected CA.
**Fix:** Verify the issuing CA is authorized. If not, revoke the certificate and investigate the CA compromise.

### POLICY_VIOLATION

**Severity:** warn
**Source:** `policy`
**Trigger:** A certificate violates a TrustPolicy CRD rule (min key size, no SHA-1, required issuer, no self-signed).
**Fix:** Review the policy and update the certificate to comply (e.g., increase key size, switch issuer, remove self-signed).

## Condition-Based Findings

These findings don't have a named `findingType` — they are identified by their condition (chain errors, posture issues, probe failures, or expiry).

### Chain validation errors

**Severity:** varies
**Condition:** `chainErrors` field is non-empty
**Common errors:**
- `certificate signed by unknown authority` — server doesn't send full intermediate chain, or probing by IP without SNI
- `certificate does not cover hostname` — cert SANs don't include the probed hostname/IP; add `sni` to external target config
- `leaf certificate is self-signed` — expected for some webhooks (e.g., Linkerd with `failurePolicy=Ignore`)
- `certificate has expired` — an intermediate in the chain has expired

**Fix:** Ensure intermediates are present and correctly ordered in the TLS secret or server config.

### TLS posture issues

**Severity:** critical (TLS 1.0/1.1, weak ciphers) or warn (CBC-mode ciphers)
**Condition:** `postureIssues` field is non-empty
**Trigger:** The TLS handshake negotiated a weak protocol version or cipher suite.
**Fix:** Disable TLS <1.2, remove weak ciphers (RC4, 3DES, NULL), and enable TLS 1.3 where possible.

### Revocation issues

**Severity:** critical (revoked) or warn (unreachable OCSP, stale CRL)
**Condition:** `revocationIssues` field is non-empty
**Trigger:** OCSP or CRL check found the certificate is revoked, or the revocation check could not be completed.
**Fix:** If revoked, reissue immediately and rotate all dependents. If OCSP/CRL is unreachable, check network connectivity to the responder.

### Probe failure

**Severity:** info (default finding severity)
**Condition:** `probeOk=false` and `probeError` is set
**Trigger:** trustwatch could not read the certificate — TLS handshake failed, secret is unreadable, or the secret's `tls.crt` key is missing.
**Fix:** Check that the service is running, the port is correct, and TLS is configured. Both `kubernetes.io/tls` and `Opaque` secrets are supported as long as they contain a `tls.crt` key.

### Expiry (no finding type)

**Severity:** critical (within `critBefore` threshold or expired), warn (within `warnBefore` threshold), info (healthy)
**Condition:** `notAfter` is within the configured threshold
**Fix:**
- **Critical/expired:** Renew or rotate the certificate now.
- **Warn:** Schedule renewal before the warning threshold.
- **Info:** No action — certificate is healthy and tracked for inventory.

## Prometheus Alert Mapping

| Alert | Condition | Matches |
|-------|-----------|---------|
| `TrustwatchCertExpiringSoon` | `cert_expires_in_seconds` < warn threshold | Expiry warn |
| `TrustwatchCertExpiryCritical` | `cert_expires_in_seconds` < crit threshold | Expiry critical |
| `TrustwatchCertExpired` | `cert_expires_in_seconds` <= 0 | Expiry expired |
| `TrustwatchProbeFailed` | `probe_success` == 0 for 10m | Probe failure, SECRET_NOT_FOUND |
| `TrustwatchScanStale` | `last_scan_timestamp_seconds` > 10m old | trustwatch itself stopped scanning |
| `TrustwatchDiscoveryErrors` | `discovery_errors_total` increasing | A discoverer is failing |
