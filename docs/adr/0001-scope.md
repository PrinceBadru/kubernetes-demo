# ADR 0001: Project Scope - Read-Only System Auditor & DevSecOps Reference Implementation

- **Status:** Accepted
- **Date:** 2026-10-13
- **Deciders:** DevSecOps Architecture Team

---

## Context

When building reference architectures and enterprise demonstration environments, organizations often face a trade-off between excessive business domain complexity and realistic security controls. Building a full e-commerce or complex ERP system introduces domain logic that distracts from core platform engineering, container hardening, zero-trust network policies, and CI/CD security automation.

Conversely, trivial "Hello World" sample apps fail to demonstrate authentic microservice interactions, multi-tier persistence, caching behaviors, connection pooling, or realistic threat models.

## Decision

We decided to define the application scope as a **hardened 3-tier system auditor and health gateway** (`devsecops-demo`):

1. **Core Workloads:**
   - Stateless Express.js API (`devsecops-demo-api`).
   - Relational persistence via PostgreSQL (`auditor` database) for audit records.
   - High-throughput caching via Redis (`redis` service).
2. **Read-Focused Architectural Paradigm:**
   - The primary endpoints serve system diagnostics, deep dependency health checks (`/api/health`), and Prometheus operational metrics (`/metrics`).
   - Minimizes write attack surfaces while providing authentic backing data flows to test connection pools, latency distributions, and lateral movement defenses.
3. **Primary Evaluation Target:**
   - The workload serves as a live target to demonstrate Pod Security Admission (Restricted), NetworkPolicies, CIS Kubernetes Benchmarks, OWASP Top 10 mitigation, and Chaos Engineering auto-healing.

## Consequences

### Positive

- **High DevSecOps Focus:** The codebase remains concise and readable, enabling developers and security auditors to focus on infrastructure-as-code hardening, network segmentation, and policy enforcement rather than business CRUD boilerplate.
- **Authentic Multi-Tier Telemetry:** Exercising real PostgreSQL connections and Redis cache lookups generates authentic metrics for Prometheus, Grafana, and k6 load tests.
- **Low Maintenance Overhead:** Reduced domain dependencies simplify automated CI/CD pipeline scanning and container image vulnerability management.

### Trade-offs / Limitations

- **Not a Production Multi-Tenant App:** Does not include complex OAuth2/OIDC user login workflows or multi-tenant database partitioning. Those patterns can be added as layered extensions without altering the core infrastructure security posture.
