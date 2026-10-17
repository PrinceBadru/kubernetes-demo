# DevSecOps Kubernetes Demo: Orchestration & Demonstration Guide

This guide provides end-to-end instructions for orchestrating, presenting, and verifying the **DevSecOps Kubernetes Demo**. It includes a 5-command Quick Start, deep-dive walkthroughs for each demonstration script, talking points aligned with DevSecOps governance frameworks, troubleshooting steps, and teardown commands.

---

## 📋 Prerequisites Checklist

Ensure your workstation satisfies these requirements prior to running the demo scripts:

| Requirement            | Supported Versions                         | Verification Command       | Purpose                                                   |
| :--------------------- | :----------------------------------------- | :------------------------- | :-------------------------------------------------------- |
| **Operating System**   | Linux, macOS, or Windows (WSL2 / Git Bash) | `uname -a`                 | Bash scripting environment                                |
| **Docker**             | Engine 20.10+ / Desktop 4.0+               | `docker info`              | Container image builds & local Kind nodes                 |
| **kubectl**            | v1.26+                                     | `kubectl version --client` | Kubernetes cluster management CLI                         |
| **KinD** (or Minikube) | KinD v0.20+ / Minikube v1.31+              | `kind version`             | Multi-node local Kubernetes cluster                       |
| **curl**               | 7.68+                                      | `curl --version`           | HTTP API probing and attack simulation                    |
| **k6** (Optional)      | v0.45+                                     | `k6 version`               | Performance load testing (Docker runner used as fallback) |

---

## ⚡ Quick Start (5 Commands to Full Demo)

Run the entire demonstration workflow from scratch using five sequential commands:

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

## 🎬 Step-by-Step Walkthrough Guide

### Step 1: `demo/01-setup-cluster.sh` — Local Cluster Setup

- **What it does:**
  - Validates prerequisites (`docker`, `kubectl`, `kind`/`minikube`).
  - Creates a 3-node KinD cluster (1 control plane + 2 worker nodes) with port forwards for host ports 80 and 443.
  - Installs the official NGINX Ingress Controller.
  - Deploys and patches the Kubernetes `metrics-server` with `--kubelet-insecure-tls` for local certificate compatibility.
- **What to show the audience:**
  ```bash
  kubectl get nodes -o wide
  kubectl get pods -n ingress-nginx
  kubectl top nodes
  ```
- **Key DevSecOps Talking Points:**
  - _Infrastructure as Code (IaC):_ Declarative, repeatable cluster topologies.
  - _Multi-Node Realism:_ A multi-node topology is essential to demonstrate `podAntiAffinity`, ensuring replicas are never co-located on a single physical host.
  - _Dynamic Capacity:_ `metrics-server` enables native Kubernetes resource telemetry for the Horizontal Pod Autoscaler (HPA).

---

### Step 2: `demo/02-deploy-full-stack.sh` — Full Stack Deployment

- **What it does:**
  - Builds the production image `devsecops-demo-api:latest` locally and sideloads it into the cluster nodes without exposing it to public registries.
  - Applies the namespace with **Pod Security Admission (PSA) `restricted` profile**.
  - Deploys security governance resources (`pod-security.yaml`, `resource-quotas.yaml`, `service-account.yaml`, `rbac.yaml`, and `network-policies.yaml`).
  - Injects `ConfigMap` and `Secret` configuration.
  - Rolls out PostgreSQL 15-alpine (StatefulSet), Redis 7-alpine (Deployment), and Express.js API (2 replicas Deployment + HPA).
  - Waits for readiness probes to turn green.
  - Deploys NGINX Ingress rules and a Prometheus/Grafana monitoring stack.
- **What to show the audience:**
  ```bash
  kubectl get all,networkpolicy,hpa -n devsecops-demo
  curl -H "Host: devsecops-demo.local" http://localhost/
  curl -H "Host: devsecops-demo.local" http://localhost/api/health
  ```
- **Key DevSecOps Talking Points:**
  - _Defense-in-Depth:_ Multiple layers of security are applied before the first container starts.
  - _Zero-Downtime Rollouts:_ `RollingUpdate` with `maxUnavailable: 0` ensures service continuity during redeployments.
  - _Secret Isolation:_ Decoupling application configuration from sensitive database credentials prevents accidental credential leakage in Git repositories.

---

### Step 3: `demo/03-verify-network-policies.sh` — Zero-Trust Network Verification

- **What it does:**
  - Tests 5 distinct network paths to prove NIST SP 800-207 Zero-Trust Micro-segmentation:
    1. `API -> PostgreSQL:5432` (**ALLOWED**)
    2. `API -> Redis:6379` (**ALLOWED**)
    3. `Rogue Pod -> PostgreSQL:5432` (**BLOCKED**)
    4. `Redis Pod -> PostgreSQL:5432` (**BLOCKED**)
    5. `Rogue Pod -> Redis:6379` (**BLOCKED**)
- **What to show the audience:**
  - The live connection timeouts when unauthorized pods attempt to reach PostgreSQL or Redis.
  - The clean summary table demonstrating that default-deny is active.
- **Key DevSecOps Talking Points:**
  - _Default Deny:_ Standard Kubernetes allows flat, uninhibited inter-pod traffic. With zero-trust network policies, every connection must be explicitly permitted.
  - _Lateral Movement Prevention:_ If a public-facing container or Redis cache is compromised, attackers cannot reach the transactional PostgreSQL database.

---

### Step 4: `demo/04-run-security-tests.sh` — Security Test Suites

- **What it does:**
  - Executes automated shell test suites against the running environment:
    - `tests/security/container-security.test.sh`: Verifies non-root user UID 1001, read-only root filesystem, dropped capabilities, and token isolation.
    - `tests/security/network-policy.test.sh`: Automated probe tests against network isolation.
    - `tests/security/sql-injection.test.sh`: Fuzzes API endpoints with SQLi payloads to verify parameterized queries and absence of SQL error leaks.
    - OWASP ZAP baseline scan (optional/containerized).
  - Generates a consolidated Markdown audit report in `artifacts/security/security-summary.md`.
- **What to show the audience:**
  - The automated test execution passing in terminal.
  - The generated audit artifact `artifacts/security/security-summary.md`.
- **Key DevSecOps Talking Points:**
  - _Automated Quality Gates:_ Security policies must be tested in CI/CD pipelines just like unit and integration tests.
  - _Compliance Alignment:_ Tests explicitly map back to CIS Kubernetes Benchmarks and OWASP ASVS v4.0.

---

### Step 5: `demo/05-run-performance-tests.sh` — Performance Testing with k6

- **What it does:**
  - Runs three progressive performance test stages:
    1. Smoke test (`scripts/k6/smoke.js`): 1 VU for 30s.
    2. Load test (`scripts/k6/load.js`): 25 VUs steady-state for 1m.
    3. Stress test (`scripts/k6/stress.js`): Up to 150 VUs to evaluate elasticity.
  - Outputs structured telemetry to `artifacts/k6/`.
- **What to show the audience:**
  - k6 latency distributions: p(95) < 300ms under nominal load.
  - The Horizontal Pod Autoscaler reacting to CPU spikes.
- **Key DevSecOps Talking Points:**
  - _Resilience Engineering:_ Verifies non-functional requirements (NFRs) before production deployment.
  - _SRE Golden Signals:_ Continuous measurement of latency, traffic, errors, and saturation.

---

### Step 6: `demo/06-simulate-attack.sh` — Live Attack Simulation

- **What it does:**
  - Simulates 5 real-world attack vectors in real time:
    1. **SQL Injection:** Issues raw SQL queries (`id=1' OR '1'='1`) to verify input sanitization.
    2. **Root Execution Check:** Probes the container (`whoami`, `id -u`) to verify execution as unprivileged user (UID 1001).
    3. **Malware Drop:** Attempts writing an exploit (`echo malware > /app/evil.js`) to verify read-only filesystem protection.
    4. **Privilege Escalation:** Attempts `su root` to demonstrate disabled privilege escalation (`allowPrivilegeEscalation: false`).
    5. **Database Pivoting:** Provisions an unauthorized pod to establish direct database connections, proving network policy interception.
- **What to show the audience:**
  - Real-time `Read-only file system` and `Operation not permitted` errors.
  - Every attack being decisively rejected by Kubernetes kernel and network primitives.
- **Key DevSecOps Talking Points:**
  - _Immutable Infrastructure:_ Attackers cannot install tools (`curl`, `nmap`) or drop backdoors into containers with read-only root filesystems.
  - _Least Privilege:_ Dropping all Linux capabilities (`capabilities: drop: [ALL]`) strips the container of dangerous kernel attack surfaces.

---

### Step 7: `demo/07-chaos-engineering.sh` — Chaos & Auto-Healing

- **What it does:**
  - Scenario 1: Abruptly deletes an active API pod while continuously firing HTTP requests. Proves zero-downtime rolling health via ReplicaSet and peer pod.
  - Scenario 2: Launches concurrent traffic workers, driving CPU utilization past 70% and triggering HPA scale-out from 2 up to 5 replicas.
  - Scenario 3: Scales Redis to 0 replicas to test health probe decoupling: `/api/health` reports 503 degraded while `/healthz` stays 200, preventing cascading crash loops.
- **What to show the audience:**
  - The instant creation of replacement pods by Kubernetes ReplicaSet controllers.
  - The HPA status transitioning from 2 to 3+ replicas.
- **Key DevSecOps Talking Points:**
  - _Decoupled Probing:_ Separating shallow liveness (`/healthz`) from deep dependency health (`/api/health`) avoids cluster-wide cascading restart loops when a database or cache blips.
  - _Self-Healing:_ Declarative controllers automatically restore system health without human intervention.

---

### Step 8: `demo/08-show-dashboards.sh` — Monitoring Dashboards

- **What it does:**
  - Establishes persistent background port-forwarding tunnels:
    - **Grafana:** `http://localhost:3001` (admin / admin)
    - **Prometheus:** `http://localhost:9090`
    - **API Health:** `http://localhost:3000/api/health`
    - **API Metrics:** `http://localhost:3000/metrics`
  - Traps `Ctrl+C` to cleanly kill background forwarders upon exit.
- **What to show the audience:**
  - Prometheus `/targets` scraping `devsecops-demo-api` endpoints.
  - Real-time HTTP request counters and duration histograms in Prometheus.

---

## 🛠️ Troubleshooting & Common Issues

| Issue / Error                                     | Likely Cause                                             | Solution                                                                                         |
| :------------------------------------------------ | :------------------------------------------------------- | :----------------------------------------------------------------------------------------------- |
| `Cannot connect to the Docker daemon`             | Docker Desktop / Engine is stopped                       | Start Docker Desktop or run `sudo systemctl start docker`.                                       |
| `failed to create cluster: node(s) already exist` | Stale KinD cluster remains from earlier run              | Run `kind delete cluster --name devsecops-cluster` and retry.                                    |
| `Port 80/443 already in use`                      | Another local web server (IIS, Apache, NGINX) is running | Stop the conflicting local process or change host ports in `demo/01-setup-cluster.sh`.           |
| `Metrics server rollout wait timed out`           | Self-signed kubelet certificates                         | Ensure `--kubelet-insecure-tls` flag was patched into `metrics-server` deployment.               |
| `ImagePullBackOff` on `devsecops-demo-api`        | Local image was not sideloaded into KinD                 | Run `kind load docker-image devsecops-demo-api:latest --name devsecops-cluster`.                 |
| `k6: command not found`                           | k6 is not installed locally                              | `demo/05-run-performance-tests.sh` automatically falls back to Docker. Ensure Docker is running. |

---

## 🧹 Clean Up & Teardown

To release all allocated system resources, simply delete the local cluster:

```bash
# Delete the KinD cluster and all associated resources
kind delete cluster --name devsecops-cluster

# Or if using Minikube:
minikube delete -p devsecops-cluster

# Clean up generated test artifacts
rm -rf artifacts/
```
