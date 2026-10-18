# ==============================================================================
# DevSecOps Hardened Multi-Stage Dockerfile for API Service
# Base Specification: Node.js 20 LTS on Alpine Linux
# Architecture: Multi-Stage Build (deps -> production)
# Compliance Standards: CIS Docker Benchmark 4.1, 4.6, 4.8; NIST SP 800-190
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Dependencies (deps)
# Purpose: Isolate build tooling, native compilation dependencies, and package
# installation from the final runtime image to minimize attack surface and size.
# ------------------------------------------------------------------------------
FROM node:20-alpine AS deps

# NIST SP 800-190 Section 3.1.1: Minimize base image footprint using Alpine Linux
WORKDIR /app

# DevSecOps Layer Caching: Copy only package manifests first.
# This prevents rebuilding and reinstalling dependencies unless packages change.
COPY package.json package-lock.json* ./

# DevSecOps Supply Chain Hardening:
# 1. npm ci: Deterministic, repeatable install matching package-lock.json exactly.
# 2. --omit=dev: Strips devDependencies (linters, test runners, build tools) from runtime.
# 3. --ignore-scripts: Mitigates malicious preinstall/postinstall lifecycle scripts from dependencies.
# 4. npm cache clean --force: Purges package download tarballs to prevent disk bloat.
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

# ------------------------------------------------------------------------------
# Stage 2: Production Runtime (production)
# Purpose: Minimal, hardened container containing only the application code and
# production dependencies, running under an unprivileged user.
# ------------------------------------------------------------------------------
FROM node:20-alpine AS production

# OCI (Open Container Initiative) Image Specification Labels for traceability:
# Enables automated vulnerability scanners, SBOM tooling, and catalog auditing.
LABEL org.opencontainers.image.title="devsecops-demo-api" \
      org.opencontainers.image.description="DevSecOps Kubernetes Demo API" \
      org.opencontainers.image.source="https://github.com/PrinceBadru/kubernetes-demo" \
      org.opencontainers.image.vendor="DevSecOps Demo" \
      app.kubernetes.io/name="devsecops-demo-api" \
      app.kubernetes.io/part-of="devsecops-demo"

# Security & Runtime Hardening Environment Variables:
# 1. NODE_ENV=production: Enforces production optimizations in Express and disables verbose debug dumps.
# 2. PYTHONDONTWRITEBYTECODE=1: Prevents creation of .pyc bytecode files if auxiliary tools run.
ENV NODE_ENV=production \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# NIST SP 800-190 Section 3.1.2: Copy only verified production node_modules from the deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy application source code and entrypoints
COPY src/ ./src/
COPY index.js package.json ./

# CIS Docker Benchmark 4.1: Ensure that a user for the container has been created.
# NIST SP 800-190 Section 3.3.1: Mitigate container breakout by enforcing non-root execution.
# - Creates an explicit unprivileged system group (appgroup: GID 1001)
# - Creates an explicit unprivileged system user (appuser: UID 1001)
# - Allocates dedicated /tmp/app scratch space owned by appuser for safe ephemeral writes
RUN apk upgrade --no-cache && \
    addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup && \
    mkdir -p /tmp/app && chown appuser:appgroup /tmp/app && \
    rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack

# Enforce non-root execution for all subsequent instructions and runtime processes
USER appuser

# CIS Docker Benchmark 4.6: Ensure HEALTHCHECK instructions have been added to container images.
# Validates API liveness against Express /healthz endpoint.
# Detects locked event loops and hung processes for automated container restarts.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/healthz || exit 1

# Document target port (Security Best Practice: documentation only, does not publish to host)
EXPOSE 3000

# Exec form of CMD ensures Node.js runs as PID 1 to directly receive POSIX signals (SIGTERM/SIGINT)
# for graceful termination.
CMD ["node", "index.js"]
