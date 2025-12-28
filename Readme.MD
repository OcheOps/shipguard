# Shipguard

**Shipguard is a deployment decision engine for container images.**

It turns noisy vulnerability scan output into a clear, actionable verdict:
**DEPLOY**, **WARN**, or **BLOCK**.

---

## Problem

Container scanners produce hundreds of findings.
Engineers are left asking:

- Can we deploy this image?
- What actually blocks production?
- What happens if we ignore this?

Shipguard answers those questions.

---

## What Shipguard Does

- Runs Trivy with safe, CI-friendly defaults
- Normalizes vulnerability findings
- Applies explicit policy rules
- Produces a deterministic deployment verdict
- Exits with CI-compatible exit codes

---

## What Shipguard Is Not

- ❌ A vulnerability scanner
- ❌ A compliance platform
- ❌ A security replacement

Shipguard **supports decisions** — it does not make guarantees.

---

## Installation

```bash
go build -o shipguard ./cmd/shipguard
sudo mv shipguard /usr/local/bin/
