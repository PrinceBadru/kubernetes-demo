# ADR 0003: Selection of Kubernetes for Orchestration and DevSecOps Showcase

- **Status:** Accepted
- **Date:** 2026-10-13
- **Deciders:** DevSecOps Architecture Team

---

## Context

Deploying containerized microservices requires an orchestration platform capable of managing service discovery, traffic routing, rolling deployments, health self-healing, resource isolation, and declarative security policies.

Alternatives considered included:

1. **Docker Compose / Docker Swarm:** Simple local development workflows, but lacks native admission control policies (Pod Security Admission), enterprise zero-trust network policies, multi-node anti-affinity controls, or automated metric-based horizontal pod autoscaling.
2. **Serverless / Managed PaaS (e.g. AWS ECS / Cloud Run):** Reduces control-plane management burden, but abstracts away the underlying Linux kernel boundaries, networking overlays, CNI micro-segmentation, and cluster-level governance controls that are central to demonstrating enterprise DevSecOps engineering.
3. **Kubernetes (K8s):** The de-facto industry standard for container orchestration, offering a rich ecosystem of declarative APIs, admission controllers, policy engines, and security primitives.

## Decision

We selected **Kubernetes (v1.26+)** as the primary orchestration foundation for this project:

1. **Declarative Security as Code:**
   - Security configurations (NetworkPolicies, Pod Security Admission, RBAC, ResourceQuotas, ServiceAccounts) are expressed as declarative version-controlled YAML files, allowing continuous GitOps governance.
2. **Zero-Trust Microsegmentation via NetworkPolicies:**
   - Kubernetes NetworkPolicy API provides native, CNI-level traffic isolation without requiring proprietary third-party proxies.
3. **Pod Security Standards (PSS) & Admission Enforcement:**
   - Native namespace-level enforcement (`pod-security.kubernetes.io/enforce: restricted`) rejects non-compliant workloads at admission time.
4. **Resilience & Chaos Engineering Capabilities:**
   - Declarative controllers (Deployments, StatefulSets, ReplicaSets) continuously reconcile state, enabling self-healing, rolling zero-downtime updates, and dynamic Horizontal Pod Autoscaling (HPA).
5. **Local KinD Simulation:**
   - KinD (Kubernetes in Docker) allows running authentic multi-node clusters on local developer workstations, bridging the gap between local development and production cloud clusters (EKS, GKE, AKS).

## Consequences

### Positive

- **Production-Identical Security Posture:** Security policies tested locally in KinD translate directly to enterprise cloud-managed Kubernetes environments without modification.
- **Clear Separation of Concerns:** Application developers focus on container logic, while platform/security engineers enforce cluster guardrails via namespaces, admission controllers, and network policies.
- **Industry Standard DevSecOps Showcase:** Demonstrates real-world skills in Kubernetes hardening, CIS Benchmarks, SRE golden signals, and automated chaos resilience.

### Trade-offs / Mitigations

- **Operational Complexity:** Kubernetes has a steeper learning curve and higher configuration surface area compared to basic Docker Compose.
  - _Mitigation:_ Comprehensive orchestration shell scripts (`demo/01-setup-cluster.sh` through `demo/08-show-dashboards.sh`) automate cluster provisioning, image sideloading, policy enforcement, and verification into one-click commands.
