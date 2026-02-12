# Contributing to trustwatch

Thank you for your interest in contributing to trustwatch! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)
- [Project Structure](#project-structure)

---

## Code of Conduct

Be respectful, constructive, and professional in all interactions.

---

## Getting Started

### Prerequisites

- **Go** >= 1.25
- **kubectl** configured with access to a Kubernetes cluster (for integration testing)
- **make** (for build automation)
- **git**
- **golangci-lint** (optional, for local linting)

### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/trustwatch.git
cd trustwatch

# Add upstream remote
git remote add upstream https://github.com/ppiankov/trustwatch.git
```

---

## Development Setup

### 1. Install Dependencies

```bash
make deps
```

### 2. Build

```bash
make build
```

Binary will be created at `bin/trustwatch`.

### 3. Run Tests

```bash
make test
```

### 4. Run Linter (Optional)

```bash
make lint
```

**Note:** If golangci-lint is not installed:
```bash
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | \
  sh -s -- -b $(go env GOPATH)/bin
```

---

## Making Changes

### Branching Strategy

Create a feature branch from `main`:

```bash
git checkout -b feature/my-new-feature
# or
git checkout -b fix/bug-description
```

**Branch naming conventions:**
- `feature/*` - New features
- `fix/*` - Bug fixes
- `docs/*` - Documentation updates
- `refactor/*` - Code refactoring
- `test/*` - Test improvements

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type: concise imperative statement
```

Lowercase after colon, no period. Max 72 chars.

**Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`, `ci`, `build`

**Examples:**
```
feat: add linkerd issuer discovery
fix: handle missing webhook service reference
docs: update annotation examples
```

Body (optional, separated by blank line) for WHY, not WHAT.

---

## Testing

### Unit Tests

```bash
# Run all tests
make test

# Run specific package tests
go test ./internal/probe -v

# Run with coverage
make test-coverage
```

### Test Guidelines

- Write tests for new features
- Maintain or improve code coverage (target: >85%)
- Use table-driven tests where appropriate
- Mock Kubernetes API client for unit tests
- Deterministic tests only — no flaky/probabilistic tests

---

## Submitting Changes

### Before Submitting

1. **Run all checks:**
   ```bash
   make check
   ```

2. **Ensure tests pass:**
   ```bash
   make test
   ```

3. **Update documentation** if needed

4. **Add or update tests** for your changes

### Create Pull Request

1. Push your branch
2. Open a Pull Request on GitHub
3. Fill in the PR template (description, testing performed)

### PR Review Process

- CI checks must pass (tests, lint, build)
- At least one approving review required
- Maintainers may request changes

---

## Code Style

### Go Style Guide

- Use `gofmt` for formatting
- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use meaningful variable names
- Comments explain "why" not "what"

### Linter Configuration

We use `golangci-lint` with configuration in `.golangci.yml`.

**Key rules:**
- Max line length: 140 characters
- Max cyclomatic complexity: 15
- Required error checking
- No unused code

---

## Project Structure

```
trustwatch/
├── cmd/
│   └── trustwatch/       # Main entry point
├── internal/
│   ├── cli/              # Cobra commands (now, serve, version)
│   ├── config/           # YAML configuration
│   ├── discovery/        # Discoverer interface + implementations
│   ├── metrics/          # Prometheus exporter
│   ├── probe/            # TLS handshake probing
│   ├── store/            # Data model (CertFinding, Snapshot)
│   └── web/              # Built-in web UI + JSON API
├── docs/                 # Documentation and work orders
├── .github/workflows/    # CI/CD
├── Makefile              # Build automation
├── .golangci.yml         # Linter config
└── go.mod                # Go modules
```

### Adding a New Discoverer

1. Create file in `internal/discovery/` (e.g., `my_source.go`)
2. Implement the `Discoverer` interface
3. Register in the discovery orchestrator
4. Add unit tests
5. Update CLAUDE.md architecture section

---

## Getting Help

- **GitHub Issues**: [Report bugs or request features](https://github.com/ppiankov/trustwatch/issues)
- **Documentation**: [Read the docs](https://github.com/ppiankov/trustwatch/tree/main/docs)

---

Thank you for contributing to trustwatch!
