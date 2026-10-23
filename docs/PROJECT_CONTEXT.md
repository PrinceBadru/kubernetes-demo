# Project Context: DevSecOps Kubernetes Demo

## 1. Project Identification & Executive Purpose

- **Project Name:** DevSecOps Kubernetes Demo (`devsecops-demo`)
- **Repository:** `https://github.com/PrinceBadru/kubernetes-demo`
- **Primary Domain:** Cloud-Native Security, DevSecOps Automation, Resilient Container Orchestration
- **Audience:** Cloud Architects, Security Engineers, DevOps/Platform Practitioners, Software Developers

### Purpose & Vision

The **DevSecOps Kubernetes Demo** serves as an enterprise-grade reference architecture illustrating how modern DevSecOps, Site Reliability Engineering (SRE), and Zero-Trust principles are implemented across the entire software development and deployment lifecycle in Kubernetes.

Rather than treating security as a perimeter-only or post-deployment audit gate, this project demonstrates **Security as Code**, **Defense-in-Depth**, and **Shift-Left/Shift-Right verification** baked directly into:

1. Container image builds (non-root execution, minimal attack surface, multi-stage builds).
2. Declarative Kubernetes manifests (Pod Security Admission Restricted profile, resource quotas, dropped capabilities, read-only root filesystem).
3. Zero-trust network segmentation (NIST SP 800-207 compliant default-deny network policies).
4. Automated security compliance test suites (CIS benchmarks, OWASP Top 10 injection defenses).
5. Continuous observability & automated scaling (Prometheus Golden Signals, Grafana telemetry, Horizontal Pod Autoscaler).

---

## 2. System Architecture Overview

The system implements a hardened **3-tier cloud-native architecture**:

```
 [ External Client / Ingress ]
              │
              ▼ (TLS Port 443 / HTTP Port 80)
   ┌──────────────────────┐
   │ NGINX Ingress Router │ Rate limiting (10 rps), payload capping (1MB)
   └──────────┬───────────┘
              │
              ▼ (TCP Port 3000)
   ┌────────────────────────────────────────┐
   │ Express.js API Tier                    │ Replicas: 2 (HPA 2-5)
   │  - Non-root UID 1001                   │ Read-only root filesystem
   │  - Security headers & error masking    │ Prometheus /metrics
   │  - Health endpoints (/healthz, /readyz)│ Deep check (/api/health)
   └───┬───────────────────────────────┬────┘
       │                               │
       │ (TCP Port 5432)               │ (TCP Port 6379)
       ▼                               ▼
┌──────────────┐               ┌──────────────┐
│  PostgreSQL  │               │    Redis     │
│  15-alpine   │               │   7-alpine   │
│ (Persistence)│               │  (In-Memory) │
└──────────────┘               └──────────────┘
```

### Tier Responsibilities

1. **Edge & Ingress Tier:**
   - **Component:** NGINX Ingress Controller.
   - **Responsibility:** Ingress TLS termination, centralized host routing (`devsecops-demo.local`), request payload capping (1MB) to prevent buffer-exhaustion attacks, and per-IP rate limiting (10 requests/second) mitigating Layer 7 volumetric Denial of Service (DoS).

2. **Application Tier (`devsecops-demo-api`):**
   - **Component:** Node.js 20 LTS / Express.js REST API.
   - **Responsibility:** Request routing, input sanitization, parameterized SQL querying, caching orchestration, structured audit logging, Prometheus telemetry generation, and Kubernetes health probing.
   - **Resilience:** Minimum 2 replicas with pod anti-affinity, scaling to 5 replicas via Horizontal Pod Autoscaler based on CPU utilization (>70%).

3. **Data & Cache Tier:**
   - **PostgreSQL 15-alpine (Port 5432):** Relational state persistence for audit records and system state. Deployed as a Kubernetes `StatefulSet` with an isolated headless service (`postgres`).
   - **Redis 7-alpine (Port 6379):** High-throughput, in-memory caching and session store deployed as a Kubernetes `Deployment` with a dedicated ClusterIP service (`redis`).

4. **Observability & Telemetry Tier (`monitoring` namespace):**
   - **Prometheus (Port 9090):** Time-series database scraping `/metrics` endpoints.
   - **Grafana (Port 3000 / 3001 host-forwarded):** Centralized telemetry dashboard visualizing request rates, p95/p99 latencies, error percentages, and system saturation.

---

## 3. Technology Stack Reference

| Layer / Concern         | Technology                  | Version             | Rationale                                                                                         |
| :---------------------- | :-------------------------- | :------------------ | :------------------------------------------------------------------------------------------------ |
| **Language Runtime**    | Node.js (Alpine Base)       | 20 LTS              | Enterprise long-term support, asynchronous event-driven I/O, minimal attack surface               |
| **Framework**           | Express.js                  | 5.x / 4.x           | Minimalist HTTP routing with robust middleware pipeline (headers, rate limiting, metrics)         |
| **Database**            | PostgreSQL                  | 15-alpine           | ACID compliance, prepared statement parameterization, lightweight Alpine container                |
| **Cache Store**         | Redis                       | 7-alpine            | Sub-millisecond latency caching layer, non-root Alpine container footprint                        |
| **Orchestration**       | Kubernetes                  | v1.26+              | De-facto standard for containerized workloads, native self-healing, PSS, HPA, and NetworkPolicies |
| **Local Cluster**       | KinD (Kubernetes in Docker) | v0.20+              | Multi-node topology simulation, Ingress host-port bindings, lightweight developer experience      |
| **Ingress Controller**  | Ingress-NGINX               | v1.11.3 (pinned)    | Advanced annotation-based rate limiting, SSL redirection, and request size enforcement            |
| **Metrics & Telemetry** | Prometheus & Grafana        | v2.45.0 / v10.0.3   | Industry standard SRE telemetry, native Kubernetes endpoint discovery                             |
| **Load Testing**        | k6 by Grafana Labs          | v0.45+ (pinned)     | Scriptable performance testing evaluating SLOs and triggering autoscaling                         |
| **Security Scanning**   | OWASP ZAP & Custom Suites   | 2.15.0 / Trivy 0.36 | Dynamic Application Security Testing (DAST) and CIS Benchmark compliance checking                 |

---

## 4. DevSecOps Principles Implemented

| DevSecOps Principle                 | Implementation in Project                                                                        | Primary Security Benefit                                                                                                       |
| :---------------------------------- | :----------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------- |
| **Least Privilege (PoLP)**          | Non-root container UID 1001, dedicated ServiceAccount with `automountServiceAccountToken: false` | Prevents container breakouts from inheriting host root or Kubernetes cluster-admin credentials.                                |
| **Zero-Trust Microsegmentation**    | Declarative NetworkPolicies with default-deny ingress and egress (NIST SP 800-207)               | Blocks lateral movement across pods; isolates PostgreSQL and Redis from unauthorized workloads.                                |
| **Immutable Infrastructure**        | `readOnlyRootFilesystem: true` with ephemeral `/tmp` emptyDir volume mount                       | Prevents adversaries from modifying application binaries, downloading malware, or maintaining persistence.                     |
| **Kernel Hardening**                | `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `RuntimeDefault` seccomp        | Eliminates Linux kernel capabilities (e.g. `CAP_NET_RAW`, `CAP_SYS_ADMIN`), thwarting privilege escalation exploits.           |
| **Pod Security Standards (PSS)**    | Namespace labeled with `pod-security.kubernetes.io/enforce: restricted`                          | Kubernetes rejects any workload violating the strictest pod security standards at admission time.                              |
| **Defense Against Injection**       | Parameterized queries with prepared statements ($1, $2) and global error masking                 | Mitigates OWASP Top 10 A03:2021 Injection and prevents database schema leakage (CWE-200).                                      |
| **Denial of Service (DoS) Defense** | Ingress rate limiting (10 rps), payload limits (1MB body, 100kb JSON), resource requests/limits  | Prevents noisy neighbors, memory exhaustion attacks, and volumetric Layer 7 request flooding.                                  |
| **SRE Health Probing**              | Distinct `/healthz` (Liveness), `/readyz` (Readiness), and `/api/health` (Deep Check)            | Prevents cascading pod crashes during temporary backing database or cache blips.                                               |
| **Elastic Auto-Healing**            | Horizontal Pod Autoscaler (HPA 2-5 replicas), ReplicaSets with Pod Anti-Affinity                 | Automatically absorbs traffic spikes and maximizes high availability across distinct worker nodes via preferred anti-affinity. |

---

## 5. Key Design Decisions & Rationale

1. **Why Multi-Node Cluster Topology for Demos?**
   - By configuring KinD with 1 control plane and 2 worker nodes, preferred `podAntiAffinity` guides replica pods across separate worker nodes, accurately mirroring production failure domain separation without blocking scheduling on single-node clusters.

2. **Why Decouple Liveness from Deep Health Checks?**
   - A common anti-pattern is configuring Kubernetes liveness probes to ping PostgreSQL or Redis. If the database experiences a 10-second failover, Kubernetes kills all API pods simultaneously, causing a catastrophic cluster-wide crash loop. In this architecture:
     - `/healthz` checks solely that the Node.js process is alive and responsive.
     - `/api/health` performs deep synthetic dependency checks for monitoring alerts without triggering pod restarts.

3. **Why Disable ServiceAccount Token Automounting?**
   - CIS Kubernetes Benchmark 5.1.6 recommends disabling token automounting unless a workload explicitly interacts with the Kubernetes API server. Since this Express.js API does not call Kubernetes APIs, disabling token automounting eliminates the risk of an attacker using an extracted token to query the cluster control plane.

4. **Why Strict Read-Only Root Filesystem with an Ephemeral `/tmp`?**
   - Node.js runtime and various libraries occasionally require scratch storage (e.g. temporary sockets, file buffers). Mounting a small (64Mi) memory- or disk-backed `emptyDir` at `/tmp` while keeping the root filesystem read-only ensures functional compatibility without sacrificing immutability.
