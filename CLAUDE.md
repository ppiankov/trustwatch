# Project: trustwatch

Kubernetes trust surface monitoring. Two modes: now (ad-hoc TUI scan), serve (in-cluster web UI + Prometheus metrics). Discovers expiring certs on admission webhooks, API aggregation, service meshes, annotated services, and external dependencies.

## Philosophy: RootOps

Principiis obsta — resist the beginnings. Address root causes, not symptoms. Control over observability. Determinism over ML. Restraint over speed.

## Commands
- `make build` — Build binary
- `make test` — Run tests with race detection
- `make lint` — Run golangci-lint
- `make fmt` — Format with gofmt
- `make vet` — Run go vet
- `make check` — All checks (fmt, vet, lint, test)
- `make clean` — Clean build artifacts

## Architecture
- Entry: `cmd/trustwatch/main.go` (minimal, delegates to internal/)
- CLI: `internal/cli/` — Cobra commands (now, serve, version)
- Discovery: `internal/discovery/` — Pluggable discoverers (webhooks, apiservices, secrets, ingress, linkerd, istio, annotations, externals)
- Probe: `internal/probe/` — TLS handshake probing with SNI support
- Store: `internal/store/` — CertFinding + Snapshot data model
- Config: `internal/config/` — YAML config with sane defaults
- Web: `internal/web/` — Built-in problems UI + JSON API
- Metrics: `internal/metrics/` — Prometheus exporter (trustwatch_cert_expires_in_seconds, etc.)

## Annotations
- `trustwatch.dev/enabled: "true"` — Mark a Service/Deployment for monitoring
- `trustwatch.dev/ports: "443,8443"` — Ports to probe
- `trustwatch.dev/sni: "api.internal"` — SNI override
- `trustwatch.dev/severity: "critical"` — Override severity
- `trustwatch.dev/tls-secret: "mycert"` — Read cert from Secret instead of probing
- `trustwatch.dev/external-targets: |` — Multiline list of external TLS endpoints

## Discovery Priority
1. Auto-critical: webhooks (failurePolicy=Fail), apiservices, apiserver, mesh issuers/roots
2. Opt-in: annotated Services/Deployments + external targets
3. Inventory: TLS secrets (metrics only, not shown in UI unless referenced)

## Code Style
- Go: minimal main.go delegating to internal/, Cobra for CLIs, golangci-lint, race detection in tests
- Comments explain "why" not "what". No decorative comments
- No magic numbers — name and document constants
- Defensive coding: null checks, graceful degradation, fallback to defaults

## Naming
- Go files: snake_case.go
- Go packages: short single-word (cli, discovery, probe, store, config, web, metrics)
- Conventional commits: feat:, fix:, docs:, test:, refactor:, chore:

## Conventions
- Minimal main.go — single Execute() call
- Internal packages: short single-word names
- Discoverers are stateless: Kubernetes API in, []CertFinding out
- Probes are stateless: URL in, Result out
- Version injected via LDFLAGS at build time

## Testing
- Tests are mandatory for all new code. Coverage target: >85%
- Deterministic tests only — no flaky/probabilistic tests
- Go: -race flag always
- Test files alongside source
- TDD preferred: write tests first, then implement to make them pass

## Verification — IMPORTANT
- Run `make test` after code changes (includes -race)
- Run `make lint` before marking complete
- Run `go vet ./...` for suspicious constructs
- Never mark a task complete if tests fail or implementation is partial

## Workflow
- Start complex tasks in Plan mode (Shift+Tab)
- Explore first, plan second, implement third, commit fourth
- Use /clear between unrelated tasks
- Use /compact when context grows — preserve test output and code changes
- Use subagents for investigation to keep main context clean

## Git Safety — CRITICAL
- NEVER force push, reset --hard, or skip hooks (--no-verify) unless explicitly told
- NEVER commit secrets, binaries, backups, or generated files
- NEVER include Co-Authored-By lines in commits — the pre-commit hook blocks them
- NEVER add "Generated with Claude Code" or emoji watermarks to PRs, commits, or code
- Small, focused commits over large monolithic ones

## Commit Messages — IMPORTANT
Format: `type: concise imperative statement` (lowercase after colon, no period)
Types: feat, fix, docs, test, refactor, chore, perf, ci, build
- ONE line. Max 72 chars. Say WHAT changed, not every detail of HOW
- NEVER write changelog-style commit messages

## Anti-Patterns — NEVER Do These
- NEVER add ML, anomaly detection, or probabilistic approaches — all detection is deterministic
- NEVER port-scan by default — discovery is API-driven and annotation-driven
- NEVER alert on mesh leaf/workload certs (24h default TTL creates noise)
- NEVER suppress API errors as empty results
- NEVER skip error handling — always check returned errors
- NEVER use init() functions unless absolutely necessary
- NEVER use global mutable state
- NEVER add features, refactor code, or make improvements beyond what was asked
- NEVER add docstrings/comments/types to code you did not change
- NEVER create helpers or abstractions for one-time operations
- NEVER design for hypothetical future requirements
- NEVER create documentation files unless explicitly requested
- NEVER suppress errors or bypass safety checks as shortcuts
- NEVER remove existing CI jobs when updating workflows — only add or modify

## Token Efficiency
- Keep CLAUDE.md lean — every line must earn its place
- Use /clear between tasks. Stale context wastes tokens on every message
- Point to docs/ files instead of inlining documentation
- Use CLI tools (gh, aws) over MCP servers when possible
- Delegate verbose operations (test runs, log processing) to subagents

## Compact Instructions
When compacting, preserve: list of modified files, test commands used, current task state, any error messages being debugged. Discard: exploration of rejected approaches, file contents already committed.
