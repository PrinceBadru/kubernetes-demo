# DevSecOps Kubernetes Demo

[![CI Security & Verification](https://github.com/PrinceBadru/kubernetes-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/PrinceBadru/kubernetes-demo/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-v1.26+-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![Pod Security](https://img.shields.io/badge/PSA-Restricted-brightgreen)](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
[![Zero-Trust](https://img.shields.io/badge/NIST-SP%20800--207%20Zero--Trust-orange)](https://csrc.nist.gov/publications/detail/sp/800-207/final)

A production-grade, enterprise reference implementation showcasing **DevSecOps**, **Zero-Trust Network Microsegmentation**, and **Site Reliability Engineering (SRE)** on Kubernetes.

This project demonstrates how to shift security left into container builds, enforce defense-in-depth across Kubernetes runtime primitives, isolate multi-tier workloads with declarative network policies, automate compliance testing, and ensure high availability through self-healing and horizontal autoscaling.

---

## 🏛️ Architecture Overview

The system implements a hardened 3-tier cloud-native architecture deployed in a multi-node Kubernetes cluster:

```
[ External Client / Performance Scanner (k6, curl) ]
                         │
                         ▼ (HTTP 80 / TLS 443)
      ┌──────────────────────────────────────────────┐
      │          NGINX Ingress Controller            │
      │  - Host: devsecops-demo.local                │
      │  - Rate Limiting: 10 req/sec                 │
      │  - Request Body Limit: 1MB                   │
      └──────────────────────┬───────────────────────┘
                             │
      ┌──────────────────────▼───────────────────────────────────────────┐
      │  Namespace: devsecops-demo (PSA Profile: Restricted)             │
      │                                                                  │
      │   ┌──────────────────────────────────────────────────────────┐   │
      │   │ API Service (ClusterIP: Port 80 -> Container Port 3000)  │   │
      │   └──────────────────────────┬───────────────────────────────┘   │
      │                              │                                   │
      │         ┌────────────────────┴────────────────────┐              │
      │         ▼                                         ▼              │
      │  ┌─────────────────────────┐           ┌────────────────────────┐│
      │  │ API Replica 1           │           │ API Replica 2          ││
      │  │ - Express.js / Node 18  │           │ - Express.js / Node 18 ││
      │  │ - Non-Root UID 1001     │◄--Anti---►│ - Non-Root UID 1001    ││
      │  │ - Read-Only RootFS      │  Affinity │ - Read-Only RootFS     ││
      │  │ - Capabilities: DROP ALL│           │ - Capabilities: DROP   ││
      │  │ - Worker Node 1         │           │ - Worker Node 2        ││
      │  └───┬─────────────────┬───┘           └───┬────────────────┬───┘│
      │      │                 │                   │                │    │
      │      │ (TCP 5432)      │ (TCP 6379)        │ (TCP 5432)     │    │
      │      ▼                 ▼                   ▼                ▼    │
      │  ┌─────────────────────────┐           ┌────────────────────────┐│
      │  │ PostgreSQL 15-alpine    │           │ Redis 7-alpine         ││
      │  │ (StatefulSet / Data)    │           │ (Deployment / Cache)   ││
      │  │ Service: postgres:5432  │           │ Service: redis:6379    ││
      │  └─────────────────────────┘           └────────────────────────┘│
      └──────────────────────────────────────────────────────────────────┘
                         ▲
                         │ (Scrape /metrics every 5s)
      ┌──────────────────┴───────────────────────────┐
      │  Prometheus & Grafana Monitoring Gateway     │
      │  (Namespace: monitoring)                     │
      └──────────────────────────────────────────────┘
```

---

## ⚡ Quick Start (5 Commands to Full Demo)

Run the automated demonstration suite from zero to full deployment on a local multi-node KinD cluster:

```bash
# 1. Provision multi-node local cluster with ingress & metrics-server
bash demo/01-setup-cluster.sh

# 2. Build and deploy complete 3-tier hardened stack & monitoring
bash demo/02-deploy-full-stack.sh

# 3. Verify zero-trust microsegmentation network policies
bash demo/03-verify-network-policies.sh

# 4. Simulate real-world container & network attacks (all blocked)
bash demo/06-simulate-attack.sh

# 5. Open observability dashboards in your browser
bash demo/08-show-dashboards.sh
```

---

## 📁 Project Structure

```
kubernetes-demo/
├── demo/                                # Automated demo orchestration scripts
│   ├── 01-setup-cluster.sh              # Multi-node KinD cluster with ingress & metrics-server
│   ├── 02-deploy-full-stack.sh          # Full stack build, deploy, & rollout verification
│   ├── 03-verify-network-policies.sh    # Zero-Trust microsegmentation test suite
│   ├── 04-run-security-tests.sh         # Security compliance test runner (CIS, OWASP, DAST)
│   ├── 05-run-performance-tests.sh      # Performance & load testing runner (k6)
│   ├── 06-simulate-attack.sh            # Live real-world adversary attack simulation
│   ├── 07-chaos-engineering.sh          # Pod failure injection & HPA elasticity demo
│   ├── 08-show-dashboards.sh            # Observability tunnels (Grafana, Prometheus, API)
│   └── README.md                        # Comprehensive demo walkthrough & talking points
│
├── k8s/                                 # Declarative Kubernetes Manifests
│   ├── namespace.yaml                   # Namespace with PSA 'restricted' enforcement
│   ├── base/                            # Core workload manifests
│   │   ├── api-deployment.yaml          # Express API Deployment (2 replicas, anti-affinity)
│   │   ├── api-service.yaml             # API ClusterIP Service (Port 80 -> 3000)
│   │   ├── api-hpa.yaml                 # Horizontal Pod Autoscaler (2-5 replicas, 70% CPU)
│   │   ├── postgres-statefulset.yaml    # PostgreSQL 15-alpine StatefulSet
│   │   ├── postgres-service.yaml        # Headless/ClusterIP database service
│   │   ├── redis-deployment.yaml        # Redis 7-alpine cache deployment
│   │   ├── redis-service.yaml           # Redis ClusterIP service
│   │   ├── ingress.yaml                 # NGINX Ingress with rate limiting & SSL redirect
│   │   ├── configmap.yaml               # Environment decoupled application configuration
│   │   ├── secrets.yaml                 # Credentials isolation
│   │   └── kustomization.yaml           # Kustomize base configuration
│   └── security/                        # Security governance manifests
│       ├── network-policies.yaml        # NIST SP 800-207 Zero-Trust microsegmentation
│       ├── pod-security.yaml            # Pod Security Standards (PSS) definitions
│       ├── rbac.yaml                    # Least-privilege Role and RoleBinding
│       ├── service-account.yaml         # Dedicated ServiceAccount (token automount disabled)
│       └── resource-quotas.yaml         # Namespace ResourceQuota & LimitRange
│
├── src/                                 # Express.js Application Source (Node.js 18 LTS)
│   ├── db.js                            # PostgreSQL connection pool with prepared statements
│   ├── cache.js                         # Redis client connection management
│   ├── health.js                        # Deep dependency health evaluation module
│   └── metrics.js                       # Prometheus metrics middleware and /metrics handler
│
├── tests/                               # Automated Test Suites
│   └── security/                        # Security validation tests
│       ├── container-security.test.sh   # CIS Benchmark container hardening test
│       ├── network-policy.test.sh       # Zero-trust network policy test
│       └── sql-injection.test.sh        # OWASP A03 SQL injection defense test
│
├── scripts/k6/                          # Performance & Load Test Suites
│   ├── smoke.js                         # Baseline smoke test (1 VU)
│   ├── load.js                          # Steady-state load test (25 VUs)
│   └── stress.js                        # HPA elasticity stress test (150 VUs)
│
├── docs/                                # Technical Architecture & Decision Records
│   ├── PROJECT_CONTEXT.md               # Context, scope, and threat model
│   ├── architecture.md                  # Comprehensive architectural reference
│   └── adr/                             # Architectural Decision Records (ADRs)
│       ├── 0001-scope.md                # ADR 0001: Project Scope
│       ├── 0002-nodejs.md               # ADR 0002: Runtime Selection (Node.js 18)
│       └── 0003-kubernetes.md           # ADR 0003: Orchestration Selection (Kubernetes)
│
├── Dockerfile                           # Multi-stage hardened non-root container image
├── docker-compose.yaml                  # Local development compose environment
├── index.js                             # Express.js application entrypoint
└── package.json                         # Node.js dependencies & scripts (type: module)
```

---

## 🛡️ DevSecOps Principles Matrix

| DevSecOps Principle                     | Implementation in Project                                                                                 | Threat Mitigated                                                                       |
| :-------------------------------------- | :-------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------- |
| **Principle of Least Privilege (PoLP)** | Non-root container UID `1001`, dedicated `api-service-account` with `automountServiceAccountToken: false` | Container escape privilege escalation & cluster control-plane takeover.                |
| **Zero-Trust Microsegmentation**        | Declarative `NetworkPolicy` with `default-deny-all` for Ingress & Egress (NIST SP 800-207)                | Lateral movement between compromised pods; blocks direct external access to databases. |
| **Immutable Infrastructure**            | `readOnlyRootFilesystem: true` with ephemeral `/tmp` emptyDir volume mount                                | Runtime malware downloads, binary patching, and unauthorized backdoor persistence.     |
| **Kernel Hardening**                    | `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `seccompProfile: RuntimeDefault`         | Linux kernel exploits, setuid privilege elevation, and raw network socket abuse.       |
| **Admission Governance**                | Namespace labeled with `pod-security.kubernetes.io/enforce: restricted`                                   | Ingestion of non-hardened, privileged containers onto cluster nodes.                   |
| **Injection Defense**                   | Parameterized SQL queries ($1, $2 placeholders) and centralized error masking                             | OWASP Top 10 A03:2021 Injection and database schema information leaks (CWE-200).       |
| **Denial of Service (DoS) Defense**     | Ingress rate limiting (10 rps), payload limits (1MB), resource requests/limits                            | Volumetric Layer 7 flooding, noisy neighbors, and memory exhaustion crashes.           |
| **SRE Probing Architecture**            | Decoupled `/healthz` (Liveness), `/readyz` (Readiness), and `/api/health` (Deep Check)                    | Cascading pod crash loops during transient database or cache hiccups.                  |
| **Elastic Self-Healing**                | Horizontal Pod Autoscaler (2-5 replicas), ReplicaSets with Pod Anti-Affinity                              | Service unavailability during traffic spikes or single-node hardware outages.          |

---

## 🎯 Scope, Boundaries & Limitations

This repository is an **educational reference implementation and runnable DevSecOps showcase**. It illustrates how declarative security policies, Pod Security Standards, Zero-Trust network microsegmentation, and Site Reliability Engineering principles are practically deployed in Kubernetes.

### What is Implemented & Verified

- **Hardened Application Runtime:** Express.js API on Node 18 LTS running with non-root UID 1001, immutable read-only root filesystem, stripped Linux kernel capabilities, and OWASP security headers.
- **SQL Injection Defense:** Real database-backed endpoint at `GET /api/records` using parameterized queries (`$1`, `$2`), strict type validation, and seed data, verified by automated tests asserting HTTP 200/400 and zero data leaks.
- **Zero-Trust Network Policies:** Declarative default-deny ingress and egress policies with explicit pod selector whitelisting, preventing lateral pod-to-pod pivoting.
- **Decoupled SRE Health Probes:** Separation of shallow liveness (`/healthz`) from deep dependency checking (`/api/health`) to prevent cascading crash loops.
- **Layered Automated Testing:** Local unit test layer (`npm test`) running completely offline without clusters, cluster integration tests (`npm run test:cluster`), and declarative scenario catalog validation (`npm run validate:catalog`).
- **Safe & Reversible Demos:** Shared preflight checks context safety, gates destructive operations with confirmation prompts, and uses signal traps to restore cluster state.

### What is Illustrative & NOT Validated for Production

- **Stateful PostgreSQL:** Deployed as a single-replica demo StatefulSet with ephemeral/local storage. Production deployments require managed databases (e.g. AWS RDS, GCP Cloud SQL) or high-availability operators (e.g. CloudNativePG) with automated backups and replication.
- **Credential Storage:** Secrets are stored as standard Kubernetes Secrets for demo simplicity. Production deployments should integrate external secret managers (e.g. HashiCorp Vault, AWS Secrets Manager, Sealed Secrets).
- **Ingress & Certificates:** Uses self-signed or demo TLS certs with local ingress hostnames. Production requires automated certificate lifecycle management (e.g. cert-manager with Let's Encrypt).
- **Observability Stack:** Single-replica Prometheus and Grafana instances run without persistent volumes or remote storage backends.

### Local Demo Safety Warning

Demo scripts in `demo/` alter running cluster state (e.g. killing pods, scaling Redis to zero, running ephemeral attacker containers, and establishing port-forward tunnels). Demos enforce context safety checks that restrict execution to recognized disposable local clusters (`kind-*`, `minikube*`, `k3d-*`, `docker-desktop`).

---

## 🔍 Component Verification Matrix

Every architectural and security claim made in this repository is explicitly mapped to its implementing manifest and its automated verification mechanism:

| Control / Claim                         | Category             | Implementation Manifest / Code                                         | Verification Method                                             | Status                | Scenario ID     |
| :-------------------------------------- | :------------------- | :--------------------------------------------------------------------- | :-------------------------------------------------------------- | :-------------------- | :-------------- |
| **Non-Root Execution (UID 1001)**       | Container Hardening  | `k8s/base/api-deployment.yaml`, `Dockerfile`                           | `tests/security/container-security.test.sh`                     | Verified Live         | `SCN-PSS-01`    |
| **Immutable Root Filesystem**           | Container Hardening  | `k8s/base/api-deployment.yaml`                                         | `demo/06-simulate-attack.sh` (Attack 3)                         | Verified Live         | `SCN-FS-01`     |
| **Capability Dropping (`ALL`)**         | Kernel Hardening     | `k8s/base/api-deployment.yaml`                                         | `tests/security/container-security.test.sh`                     | Verified Live         | `SCN-PSS-01`    |
| **ServiceAccount Token Isolation**      | Identity Isolation   | `k8s/base/api-deployment.yaml` (`automountServiceAccountToken: false`) | `tests/security/container-security.test.sh`                     | Verified Live         | `SCN-RBAC-01`   |
| **Pod Security Standards (Restricted)** | Admission Control    | `k8s/namespace.yaml`                                                   | `tests/security/container-security.test.sh`                     | Verified Live         | `SCN-PSS-01`    |
| **Zero-Trust Default Deny**             | Network Security     | `k8s/security/network-policies.yaml`                                   | `tests/security/network-policy.test.sh`                         | Verified Live         | `SCN-NETPOL-01` |
| **Lateral Movement Drop**               | Network Security     | `k8s/security/network-policies.yaml`                                   | `demo/06-simulate-attack.sh` (Attack 5)                         | Verified Live         | `SCN-NETPOL-01` |
| **Egress Internet Blocking**            | Network Security     | `k8s/security/network-policies.yaml`                                   | `tests/security/network-policy.test.sh` (Test 7)                | Verified Live         | `SCN-NETPOL-01` |
| **Parameterized SQL Queries**           | Application Security | `src/db.js`, `index.js`, `src/db/init.sql`                             | `tests/unit/db.test.js`, `tests/security/sql-injection.test.sh` | Verified Live & Local | `SCN-SQLI-01`   |
| **Decoupled Health Probing**            | Reliability / SRE    | `src/health.js`, `index.js`                                            | `tests/unit/health.test.js`, `demo/07-chaos-engineering.sh`     | Verified Live & Local | `SCN-PROBES-01` |
| **ReplicaSet Self-Healing**             | Resilience           | `k8s/base/api-deployment.yaml`                                         | `demo/07-chaos-engineering.sh` (Chaos 1)                        | Verified Live         | `SCN-CHAOS-01`  |
| **Horizontal Pod Autoscaling (HPA)**    | Elasticity           | `k8s/base/api-hpa.yaml`                                                | `demo/07-chaos-engineering.sh` (Chaos 2), k6 stress             | Verified Live         | `SCN-CHAOS-02`  |
| **Golden Signals Telemetry**            | Observability        | `src/metrics.js`, `k8s/monitoring/`                                    | `tests/metrics.test.js`, `demo/08-show-dashboards.sh`           | Verified Live & Local | `SCN-OBS-01`    |
| **PostgreSQL High Availability**        | Database HA          | `k8s/base/postgres-statefulset.yaml`                                   | N/A (Single replica demo)                                       | Illustrative Only     | N/A             |
| **KMS Secret Encryption**               | Secret Governance    | `k8s/base/secrets.yaml`                                                | N/A (Kubernetes plain secret)                                   | Illustrative Only     | N/A             |

---

## 🧪 Testing Layers & Local Execution

| Command                                 | Layer                     | Scope                                                                                                     | Cluster Required?                        |
| :-------------------------------------- | :------------------------ | :-------------------------------------------------------------------------------------------------------- | :--------------------------------------- |
| `npm test`                              | **Unit & Integration**    | Route shapes, security headers, parameterized query input validation, health checks, metrics registration | ❌ **No** (pure offline Node.js)         |
| `npm run validate:catalog`              | **Contract Validation**   | Scenario catalog schema, uniqueness, and file path verification                                           | ❌ **No**                                |
| `npm run lint`                          | **Static Analysis**       | ESLint with zero-warning threshold                                                                        | ❌ **No**                                |
| `npm run format:check`                  | **Code Style**            | Prettier code style validation                                                                            | ❌ **No**                                |
| `npm run test:cluster`                  | **Cluster Security**      | Container hardening, zero-trust network policies, live SQLi assertions                                    | ✅ **Yes** (gracefully skips if offline) |
| `bash demo/04-run-security-tests.sh`    | **Orchestrated Security** | Runs container, network policy, and SQLi suites; exports Markdown & JSON reports                          | ✅ **Yes**                               |
| `bash demo/05-run-performance-tests.sh` | **Performance / SLOs**    | Executes k6 smoke, load, and stress tests; records JSON summary                                           | ✅ **Yes** (or local API instance)       |

For complete contributor workflow and local Docker/Checkov/Kube-Linter commands, see [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

---

## 📋 Prerequisites

Before running the demo or scripts, ensure your system meets the following requirements:

- **Docker:** Engine 20.10+ / Docker Desktop running.
- **kubectl:** v1.26+ installed and in system PATH.
- **KinD (Kubernetes in Docker):** v0.20+ (or Minikube v1.31+).
- **curl:** Standard HTTP CLI.
- **k6 (Optional):** Performance test runner (the demo scripts automatically use the `grafana/k6` Docker container if `k6` is not found locally).

---

## 📚 Detailed Documentation Links

- [Demo Walkthrough & Presentation Script](file:///c:/Users/user/Desktop/Personal%20Projects/kubernetes-demo/demo/README.md)
- [Project Context & Executive Scope](file:///c:/Users/user/Desktop/Personal%20Projects/kubernetes-demo/docs/PROJECT_CONTEXT.md)
- [System Architecture & Network Topology](file:///c:/Users/user/Desktop/Personal%20Projects/kubernetes-demo/docs/architecture.md)
- [ADR 0001: Project Scope](file:///c:/Users/user/Desktop/Personal%20Projects/kubernetes-demo/docs/adr/0001-scope.md)
- [ADR 0002: Node.js Runtime Selection](file:///c:/Users/user/Desktop/Personal%20Projects/kubernetes-demo/docs/adr/0002-nodejs.md)
- [ADR 0003: Kubernetes Orchestration Selection](file:///c:/Users/user/Desktop/Personal%20Projects/kubernetes-demo/docs/adr/0003-kubernetes.md)

---

## 📜 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.
