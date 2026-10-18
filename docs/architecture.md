# System Architecture & DevSecOps Reference Guide

This document describes the architectural topology, security boundaries, communication data flows, and deployment resilience mechanisms implemented in the **DevSecOps Kubernetes Demo**.

---

## 1. System Architecture Overview

The system is designed as a secure, hardened 3-tier microservice architecture deployed in Kubernetes:

```
[ External Client / Traffic Generator (k6, curl) ]
                      │
                      ▼ (TLS / Port 80)
      ┌────────────────────────────────┐
      │     NGINX Ingress Controller   │  (Namespace: ingress-nginx)
      │  - Rate Limiting: 10 rps       │
      │  - Max Body Size: 1m           │
      └───────────────┬────────────────┘
                      │
      ┌───────────────▼─────────────────────────────────────────────────┐
      │  devsecops-demo Namespace (PSA Profile: Restricted)             │
      │                                                                 │
      │   ┌────────────────────────────────────────────────────────┐    │
      │   │ API Service (ClusterIP: Port 80 -> TargetPort 3000)     │    │
      │   └────────────────────────┬───────────────────────────────┘    │
      │                            │                                    │
      │         ┌──────────────────┴──────────────────┐                 │
      │         ▼                                     ▼                 │
      │  ┌───────────────────────┐         ┌───────────────────────┐    │
      │  │ API Pod 1             │         │ API Pod 2             │    │
      │  │ - UID: 1001 (non-root)│         │ - UID: 1001 (non-root)│    │
      │  │ - Read-Only RootFS    │         │ - Read-Only RootFS    │    │
      │  │ - Capabilities: DROP  │         │ - Capabilities: DROP  │    │
      │  │ - Worker Node 1       │         │ - Worker Node 2       │    │
      │  └───┬───────────────┬───┘         └───┬───────────────┬───┘    │
      │      │               │                 │               │        │
      │      │ (TCP 5432)    │ (TCP 6379)      │ (TCP 5432)    │ (6379) │
      │      ▼               ▼                 ▼               ▼        │
      │  ┌───────────────────────┐         ┌───────────────────────┐    │
      │  │ PostgreSQL 15-alpine  │         │ Redis 7-alpine        │    │
      │  │ (StatefulSet / Data)  │         │ (Deployment / Cache)  │    │
      │  │ Service: postgres:5432│         │ Service: redis:6379   │    │
      │  └───────────────────────┘         └───────────────────────┘    │
      └─────────────────────────────────────────────────────────────────┘
                      ▲
                      │ (Scrape /metrics on Port 3000)
      ┌───────────────┴────────────────┐
      │   Prometheus Monitoring        │  (Namespace: monitoring)
      │   - Scrapes API every 15s      │
      │   - Grafana Port 3001          │
      └────────────────────────────────┘
```

---

## 2. Component Responsibilities

### 2.1 Ingress Controller (`ingress-nginx`)

- **Ingress Routing:** Evaluates HTTP `Host` headers (`devsecops-demo.local`) and path prefixes.
- **Edge Security Controls:**
  - `nginx.ingress.kubernetes.io/limit-rps: "10"`: Enforces strict per-client IP rate limiting to mitigate Layer 7 volumetric Denial of Service (DoS) and brute-force attacks.
  - `nginx.ingress.kubernetes.io/proxy-body-size: "1m"`: Rejects oversized HTTP bodies before they reach application containers.
  - `nginx.ingress.kubernetes.io/ssl-redirect: "true"`: Automatically redirects insecure HTTP traffic to HTTPS.

### 2.2 API Application Tier (`devsecops-demo-api`)

- **Runtime:** Node.js 20 LTS running Express.js in ES Module mode (`"type": "module"`).
- **Core Endpoints:**
  - `GET /`: Returns service metadata, runtime uptime, and pod hostname (`HOSTNAME`).
  - `GET /healthz`: Kubernetes **Liveness Probe**. Non-blocking health ping validating event-loop responsiveness.
  - `GET /readyz`: Kubernetes **Readiness Probe**. Indicates whether the pod should receive service endpoint traffic.
  - `GET /api/health`: **Deep Health Check**. Synthetically verifies connectivity to PostgreSQL (via `SELECT 1`) and Redis (via `PING`). Returns HTTP 200 when healthy, HTTP 503 when degraded.
  - `GET /api/records`: **Audit Records Endpoint**. Parameterized database queries (`$1, $2`) with strict integer ID validation and input sanitization to neutralize SQL injection.
  - `GET /api/status`: Diagnostic endpoint reporting process uptime, memory usage, V8 heap stats, and Node.js version.
  - `GET /metrics`: Standardized Prometheus scrape endpoint exposing latency histograms, request counters, and connection pool saturation metrics.
- **Security Hardening:**
  - Express security headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy`, `Strict-Transport-Security`).
  - Removal of fingerprint headers (`app.disable('x-powered-by')`).
  - JSON payload size limiting (100kb).
  - Global exception masking preventing database error leaks or stack traces (CWE-200 defense).

### 2.3 Persistence Tier (`postgres`)

- **Engine:** PostgreSQL 15-alpine.
- **Workload Type:** Kubernetes `StatefulSet` with headless/ClusterIP Service `postgres`.
- **Port:** TCP 5432.
- **Security Controls:**
  - Non-root execution.
  - Parameterized prepared statements executed via user `app` into database `auditor`.
  - Ingress strictly restricted via NetworkPolicy to pods matching `app.kubernetes.io/name: api`. Direct access from any other pod or namespace is dropped.

### 2.4 Cache Tier (`redis`)

- **Engine:** Redis 7-alpine.
- **Workload Type:** Kubernetes `Deployment` with ClusterIP Service `redis`.
- **Port:** TCP 6379.
- **Security Controls:**
  - Isolated from external ingress routing.
  - NetworkPolicy restricts ingress strictly to API pods on port 6379.

---

## 3. Network Topology & Micro-Segmentation Matrix

The cluster employs **NIST SP 800-207 Zero-Trust Architecture** micro-segmentation. By default, all ingress and egress within the `devsecops-demo` namespace is denied (`default-deny-all`). Traffic flows are explicitly authorized based on fine-grained selectors:

| Source                    | Destination           | Protocol / Port | NetworkPolicy Rule      | Expected Behavior                              |
| :------------------------ | :-------------------- | :-------------- | :---------------------- | :--------------------------------------------- |
| `ingress-nginx` namespace | `api` pod             | TCP / 3000      | `allow-api-ingress`     | **ALLOWED** (Web user ingress)                 |
| `monitoring` namespace    | `api` pod             | TCP / 3000      | `allow-api-ingress`     | **ALLOWED** (Prometheus scraping)              |
| `api` pod                 | `postgres` pod        | TCP / 5432      | `allow-api-to-postgres` | **ALLOWED** (SQL queries)                      |
| `api` pod                 | `redis` pod           | TCP / 6379      | `allow-api-to-redis`    | **ALLOWED** (Cache reads/writes)               |
| `api` pod                 | `kube-system` CoreDNS | UDP/TCP / 53    | `allow-api-dns`         | **ALLOWED** (Internal DNS resolution)          |
| `postgres` pod            | `kube-system` CoreDNS | UDP/TCP / 53    | `allow-postgres-dns`    | **ALLOWED** (Internal DNS resolution)          |
| `redis` pod               | `kube-system` CoreDNS | UDP/TCP / 53    | `allow-redis-dns`       | **ALLOWED** (Internal DNS resolution)          |
| **Rogue Pod**             | `postgres` pod        | TCP / 5432      | _Default Deny_          | **BLOCKED** (Lateral movement prevented)       |
| `redis` pod               | `postgres` pod        | TCP / 5432      | _Default Deny_          | **BLOCKED** (Inter-tier pivot prevented)       |
| **External / Internet**   | `redis` pod           | TCP / 6379      | _Default Deny_          | **BLOCKED** (Cache is private)                 |
| `api` pod                 | Public Internet       | ANY             | _Default Deny_          | **BLOCKED** (Data exfiltration & C2 prevented) |

---

## 4. Multi-Layer Security Boundaries

```
┌────────────────────────────────────────────────────────────────────────┐
│  Perimeter Tier: Ingress Rate Limiting (10 rps), TLS, Body Capping     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│  Admission Control: Pod Security Admission (PSA Profile: Restricted)   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│  Network Layer: NIST SP 800-207 Default-Deny-All Network Policies      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│  Identity Layer: Dedicated ServiceAccount (automountToken: false)      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│  OS / Kernel Layer: Non-Root UID 1001, Drop All Capabilities, Seccomp │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│  Storage Layer: Read-Only Root Filesystem, Ephemeral Writable /tmp     │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Pod Security Admission (PSA):**
   - The namespace enforces `pod-security.kubernetes.io/enforce: restricted`.
   - Workloads must run as non-root, drop all Linux capabilities except `NET_BIND_SERVICE` (if needed), utilize `RuntimeDefault` seccomp profile, and disallow privilege escalation.

2. **Linux User & Capability Dropping:**
   - Pods run under explicit non-root user `1001` (`runAsUser: 1001`, `runAsGroup: 1001`).
   - `allowPrivilegeEscalation: false` blocks setuid binaries.
   - `capabilities: drop: ["ALL"]` strips all 38+ default Linux capabilities.

3. **Read-Only Root Filesystem:**
   - `readOnlyRootFilesystem: true` enforces immutability.
   - Any runtime attempt to write to `/app`, `/etc`, or `/bin` fails with `Read-only file system`.
   - Ephemeral writable storage is strictly limited to an `emptyDir` mount at `/tmp` with a 64Mi quota.

4. **ServiceAccount Token Isolation:**
   - `automountServiceAccountToken: false` on `api-service-account` prevents the kubelet from projecting API bearer tokens into container filesystems, preventing attackers from pivoting to the Kubernetes control plane.

---

## 5. End-to-End Data Flows

### 5.1 Standard Read / Write Flow

1. Client sends HTTP `GET /api/status` to `devsecops-demo.local`.
2. NGINX Ingress validates rate limits and proxy body limits, then routes to ClusterIP service `api:80`.
3. kube-proxy load balances request across healthy API pods.
4. API middleware calculates request duration and increments Prometheus counter `http_requests_total`.
5. API checks Redis (`redis:6379`) for cached response. On cache miss, queries PostgreSQL (`postgres:5432`) using prepared statement.
6. Result is cached in Redis with TTL and returned to client as JSON.

### 5.2 Observability Scrape Flow

1. Prometheus server (in `monitoring` namespace) discovers pods using Kubernetes Pod service discovery (`role: pod`) matching `app.kubernetes.io/name: api` in namespace `devsecops-demo`.
2. Prometheus issues HTTP `GET /metrics` on TCP port 3000 every 15 seconds.
3. NetworkPolicy `allow-api-ingress` permits ingress from `namespaceSelector: { kubernetes.io/metadata.name: monitoring }`.
4. API formats registered Prom-Client metrics and streams text response back to Prometheus.

---

## 6. Deployment Architecture & High Availability

```
                  ┌────────────────────────────────────────┐
                  │ KinD / Production Kubernetes Cluster   │
                  └───────────────────┬────────────────────┘
                                      │
            ┌─────────────────────────┴─────────────────────────┐
            ▼                                                   ▼
┌───────────────────────┐                           ┌───────────────────────┐
│ Worker Node 1         │                           │ Worker Node 2         │
│                       │                           │                       │
│  - API Pod 1 (Active) │◄───── podAntiAffinity ────►  - API Pod 2 (Active) │
│  - PostgreSQL Pod     │                           │  - Redis Pod          │
└───────────────────────┘                           └───────────────────────┘
            ▲                                                   ▲
            └─────────────────────────┬─────────────────────────┘
                                      │
                         ┌────────────┴────────────┐
                         │  Horizontal Pod         │ Target: 70% CPU
                         │  Autoscaler (HPA)       │ Range:  2 - 5 Replicas
                         └─────────────────────────┘
```

1. **Pod Anti-Affinity:**
   - Soft (preferred) anti-affinity ensures API replica pods are scheduled onto different worker nodes (`topologyKey: kubernetes.io/hostname`). If one worker node suffers hardware failure, the peer node continues serving traffic without downtime.

2. **Zero-Downtime Rolling Updates:**
   - Deployment configured with `strategy: RollingUpdate`, `maxSurge: 1`, `maxUnavailable: 0`.
   - New pods must pass readiness probes before old pods receive `SIGTERM`.
   - `terminationGracePeriodSeconds: 30` allows in-flight HTTP connections to drain cleanly.

3. **Horizontal Pod Autoscaling (HPA):**
   - Monitors target CPU utilization (`targetAverageUtilization: 70%`).
   - Scales replica count dynamically between **2** (baseline high availability) and **5** (peak surge capacity).

---

## 7. Scope, Boundaries & Verification Architecture

### 7.1 Scope & Intended Usage

This codebase is an educational reference implementation demonstrating how to architect and enforce DevSecOps, SRE, and Zero-Trust principles in Kubernetes. Workloads and policies are designed to run in local disposable sandbox clusters (KinD, Minikube).

### 7.2 Implemented & Verified vs. Illustrative Controls

- **Verified Runtime Controls:** Non-root UID 1001 execution, stripped Linux capabilities, immutable read-only filesystem, NIST SP 800-207 network policies (default-deny and explicit ingress/egress whitelisting), decoupled health probes, and parameterized SQL queries (`GET /api/records`).
- **Illustrative Architectural Elements:** Single-replica PostgreSQL StatefulSet (no HA replication or WAL archiving), local Kubernetes Secrets (unencrypted at rest without KMS), and self-signed ingress TLS.

### 7.3 Scenario Catalog & Test Contract

All system scenarios and verification procedures are declared in [`docs/scenarios/catalog.json`](scenarios/catalog.json) and validated by `scripts/validate-catalog.js`. Local unit tests run offline without clusters, while cluster security tests are orchestrated by `demo/04-run-security-tests.sh` generating machine-readable JSON reports.
