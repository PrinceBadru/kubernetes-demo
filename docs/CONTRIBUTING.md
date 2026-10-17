# Contributor & Local Development Guide

Welcome! This guide outlines how to contribute to the **DevSecOps Kubernetes Demo**, reproduce continuous integration (CI) checks locally, adhere to the scenario contract, and safely run in-cluster demonstrations.

---

## 1. Local Development Prerequisites

- **Node.js:** v18 LTS or later (`node -v`)
- **npm:** v9+ (`npm -v`)
- **Docker:** Docker Engine 20.10+ / Docker Desktop
- **kubectl:** v1.26+ (optional for local unit tests; required for cluster demos)
- **KinD / Minikube:** (optional for unit tests; required for live cluster scenarios)

---

## 2. CI Verification Parity: Local Command Reference

Every check executed in GitHub Actions can be executed locally without requiring cloud infrastructure or privileged tokens:

| CI Stage               | GitHub Actions Workflow      | Local Equivalent Command                                                                                            | Prerequisites                          |
| :--------------------- | :--------------------------- | :------------------------------------------------------------------------------------------------------------------ | :------------------------------------- |
| **ESLint**             | `Code Quality Pipeline`      | `npm run lint`                                                                                                      | Node.js, `npm ci`                      |
| **Prettier**           | `Code Quality Pipeline`      | `npm run format:check`                                                                                              | Node.js, `npm ci`                      |
| **Code Formatting**    | Manual / Pre-commit          | `npm run format`                                                                                                    | Node.js, `npm ci`                      |
| **Unit & Route Tests** | `Code Quality Pipeline`      | `npm test`                                                                                                          | Node.js (pure offline, no Docker/k8s)  |
| **Scenario Catalog**   | `Code Quality Pipeline`      | `npm run validate:catalog`                                                                                          | Node.js (verifies JSON & source paths) |
| **Manifest Linting**   | `Security Scanning Pipeline` | `docker run --rm -v ${PWD}:/workspace -w /workspace stackrox/kube-linter:latest lint k8s/`                          | Docker                                 |
| **Checkov IaC Scan**   | `Security Scanning Pipeline` | `docker run --rm -v ${PWD}:/workspace bridgecrew/checkov:latest -d /workspace/k8s`                                  | Docker                                 |
| **Container Build**    | `Container Build & Scan`     | `docker build -t devsecops-demo-api:latest .`                                                                       | Docker                                 |
| **Trivy Image Scan**   | `Container Build & Scan`     | `docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image devsecops-demo-api:latest` | Docker                                 |
| **Cluster Tests**      | On-demand / Step 4           | `npm run test:cluster`                                                                                              | Running local KinD / Minikube cluster  |

---

## 3. Layered Testing Architecture

The test suite is organized into distinct layers to decouple fast feedback loops from heavy infrastructure dependencies:

### 3.1 Layer 1: Application-Level Unit Tests (`npm test`)

- Located in `tests/unit/` and `tests/metrics.test.js`.
- Pure Node.js using `node:test` and `node:assert`.
- **Zero infrastructure requirements:** Does not require Docker, Kubernetes, PostgreSQL, or Redis.
- Tests cover:
  - Route handlers (`/`, `/healthz`, `/readyz`, `/api/status`, `/api/records`).
  - Security response headers (`X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, `Content-Security-Policy`).
  - Query parameter validation and SQL injection defense (asserting HTTP 400 on malformed IDs and parameterized escaping).
  - Health check decoupling and degraded states.
  - Prometheus metric registration and scraping.

### 3.2 Layer 2: Cluster Integration & Security Tests (`npm run test:cluster`)

- Located in `tests/security/` and `scripts/test-cluster.sh`.
- Tests runtime controls:
  - Pod Security Standards (Restricted) compliance (`container-security.test.sh`).
  - NIST SP 800-207 Zero-Trust Network Microsegmentation (`network-policy.test.sh`).
  - Live parameterized query verification (`sql-injection.test.sh`).
- **Safe Preflight:** If `kubectl` or the cluster is not running, `scripts/test-cluster.sh` prints an informative `[SKIPPED]` notice rather than failing abruptly.

---

## 4. Scenario Catalog Contract (`docs/scenarios/`)

To prevent drift between scripts, manifests, and documentation, every demonstration step is governed by a versioned contract:

- **Specification:** [`docs/scenarios/catalog.json`](scenarios/catalog.json) (and [`catalog.yaml`](scenarios/catalog.yaml)).
- **Schema:** [`docs/scenarios/schema.json`](scenarios/schema.json).
- **Validation:** Run `npm run validate:catalog`.

When introducing a new scenario or modifying existing manifests:

1. Declare the scenario in `docs/scenarios/catalog.json` with its unique ID (`SCN-<CATEGORY>-XX`).
2. Document prerequisites, expected before/during/after state, and reversibility actions.
3. Include all referenced manifests and scripts under `source_paths`.
4. Ensure `npm run validate:catalog` passes before opening a pull request.

---

## 5. Safe Demo Execution & Reversibility

Demo scripts in `demo/` alter cluster workloads (e.g. killing pods, scaling Redis to zero, launching temporary probe containers). To protect operators:

1. **Context Safety Gate:**
   - Demos source `demo/lib/preflight.sh` and refuse to run unless the active context matches recognized disposable sandbox environments (`kind-*`, `minikube*`, `k3d-*`, `docker-desktop`, `colima`, `orbstack`, `microk8s`).
   - To deliberately bypass this check on a custom sandbox cluster:
     ```bash
     DEMO_OVERRIDE_CONTEXT=true bash demo/07-chaos-engineering.sh
     ```

2. **Confirmation Barriers:**
   - Destructive actions (pod termination, Redis outage) prompt for user confirmation (`[y/N]`).
   - To run unattended in CI or automation:
     ```bash
     DEMO_AUTO_CONFIRM=true bash demo/07-chaos-engineering.sh --yes
     ```

3. **Reversibility Traps:**
   - `demo/07-chaos-engineering.sh` records initial replica counts and restores Redis to its original replica count on exit, error, or `SIGINT` (Ctrl+C).
   - `demo/08-show-dashboards.sh` cleanly terminates all port-forward tunnels upon exit.
   - Ephemeral probe pods are trapped and deleted immediately.

---

## 6. Pull Request Guidelines

1. **Clean Fast PRs:** PR workflows execute linting, format checking, unit tests, and catalog validation. Pull requests **do not** require cluster credentials or external cloud resources.
2. **Deterministic Commits:** Keep commits atomic and well-documented.
3. **Preserve Documentation:** Update the component matrix in `README.md` and scenario definitions in `docs/scenarios/catalog.json` when modifying workloads.
