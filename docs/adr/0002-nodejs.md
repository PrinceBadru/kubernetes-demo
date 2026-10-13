# ADR 0002: Selection of Node.js 18 LTS Runtime and Express.js

- **Status:** Accepted
- **Date:** 2026-10-13
- **Deciders:** DevSecOps Architecture Team

---

## Context
Choosing an application runtime for containerized microservice architectures requires balancing multiple operational and security concerns:
1. **Container Image Footprint & Attack Surface:** Smaller base images minimize Common Vulnerabilities and Exposures (CVEs) and image transfer times.
2. **Ecosystem & Industry Adoption:** The runtime must be broadly recognized and adopted across enterprise engineering teams.
3. **Observability & Instrumentation:** First-class native support for Prometheus metrics, OpenTelemetry, and structured JSON logging.
4. **Asynchronous Non-Blocking I/O:** High concurrency performance suitable for API gateways and microservices handling frequent I/O-bound database and cache lookups.

Potential candidate runtimes considered were:
- **Go:** Excellent single-binary compilation and low memory footprint, but steeper learning curve for generic developer security training demos.
- **Java (Spring Boot):** Robust enterprise adoption, but higher memory consumption, slower startup times (impacting rapid autoscaling and liveness probes), and heavier base images.
- **Python (FastAPI / Flask):** Rapid prototyping, but lower raw I/O throughput in high-concurrency environments without complex ASGI worker tuning.
- **Node.js (Express.js):** Lightweight event-driven concurrency, ubiquitous industry adoption, extensive DevSecOps ecosystem (npm audit, Snyk, ESLint security plugins), and rapid container startup times.

## Decision
We selected **Node.js 18 LTS** using modern **ECMAScript Modules (ESM - `"type": "module"`)** and **Express.js** for the API tier:
1. **Alpine Linux Base Image:** Deployed on `node:18-alpine` to maintain an image size under 150MB and drastically minimize base OS vulnerabilities.
2. **Built-in Non-Root User:** Utilizes the built-in non-root `node` user (UID 1000/1001), satisfying Kubernetes Pod Security Standards (PSS) Restricted profile out of the box.
3. **Graceful Signal Handling:** Native event handling for `SIGTERM` and `SIGINT` enables zero-downtime rolling updates in Kubernetes by draining in-flight requests and closing connection pools cleanly.
4. **Native Prometheus Client (`prom-client`):** High-performance histograms and counters for HTTP latency, database connection pools, and runtime memory metrics.

## Consequences

### Positive
- **Rapid Startup & Elastic Autoscaling:** Containers initialize in sub-second times, allowing the Kubernetes Horizontal Pod Autoscaler (HPA) to rapidly scale replicas during sudden traffic spikes.
- **Vast Security Tooling Support:** Seamlessly integrates with automated SCA (Software Composition Analysis) scanners like `npm audit`, Dependabot, Snyk, and Trivy.
- **Standardized Middleware Pipeline:** Express middleware facilitates uniform enforcement of security headers (`helmet` equivalents), request duration timing, and centralized error masking.

### Trade-offs / Mitigations
- **Single-Threaded Event Loop Bottlenecks:** CPU-intensive tasks could block the main event loop.
  - *Mitigation:* The API delegates computational work, strictly acts as an I/O coordinator, and leverages Kubernetes Horizontal Pod Autoscaler across multiple pods to distribute load.
- **Prototype Pollution & npm Dependency Risks:** Dynamic JavaScript object prototypes and deep dependency trees require strict supply chain governance.
  - *Mitigation:* Multi-stage builds running `npm ci --omit=dev`, locked dependency trees (`package-lock.json`), and CI/CD automated vulnerability scanning.
