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

| DevSecOps Principle | Implementation in Project | Threat Mitigated |
| :--- | :--- | :--- |
| **Principle of Least Privilege (PoLP)** | Non-root container UID `1001`, dedicated `api-service-account` with `automountServiceAccountToken: false` | Container escape privilege escalation & cluster control-plane takeover. |
| **Zero-Trust Microsegmentation** | Declarative `NetworkPolicy` with `default-deny-all` for Ingress & Egress (NIST SP 800-207) | Lateral movement between compromised pods; blocks direct external access to databases. |
| **Immutable Infrastructure** | `readOnlyRootFilesystem: true` with ephemeral `/tmp` emptyDir volume mount | Runtime malware downloads, binary patching, and unauthorized backdoor persistence. |
| **Kernel Hardening** | `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `seccompProfile: RuntimeDefault` | Linux kernel exploits, setuid privilege elevation, and raw network socket abuse. |
| **Admission Governance** | Namespace labeled with `pod-security.kubernetes.io/enforce: restricted` | Ingestion of non-hardened, privileged containers onto cluster nodes. |
| **Injection Defense** | Parameterized SQL queries ($1, $2 placeholders) and centralized error masking | OWASP Top 10 A03:2021 Injection and database schema information leaks (CWE-200). |
| **Denial of Service (DoS) Defense** | Ingress rate limiting (10 rps), payload limits (1MB), resource requests/limits | Volumetric Layer 7 flooding, noisy neighbors, and memory exhaustion crashes. |
| **SRE Probing Architecture** | Decoupled `/healthz` (Liveness), `/readyz` (Readiness), and `/api/health` (Deep Check) | Cascading pod crash loops during transient database or cache hiccups. |
| **Elastic Self-Healing** | Horizontal Pod Autoscaler (2-5 replicas), ReplicaSets with Pod Anti-Affinity | Service unavailability during traffic spikes or single-node hardware outages. |

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
