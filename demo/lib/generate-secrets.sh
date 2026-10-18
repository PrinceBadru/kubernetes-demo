#!/usr/bin/env bash
# ==============================================================================
# DevSecOps Demo: Dynamic Credential Generator
# ==============================================================================
# Principle:
# Generates strong, cryptographically random credentials for local demo
# deployments to ensure no shared, default, or committed passwords are ever used.
# (NIST SP 800-53 IA-5 Authenticator Management).
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

generate_random_token() {
  if command -v openssl &>/dev/null; then
    openssl rand -hex 16
  elif command -v node &>/dev/null; then
    node -e "process.stdout.write(require('crypto').randomBytes(16).toString('hex'))"
  else
    # Fallback to /dev/urandom
    head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

echo "==> Generating disposable environment secrets..."

DB_PASSWORD="${DB_PASSWORD:-$(generate_random_token)}"
API_TOKEN="${API_TOKEN:-$(generate_random_token)}"
GRAFANA_PASSWORD="${GRAFANA_PASSWORD:-$(generate_random_token)}"

# 1. Generate k8s/base/secrets.yaml
cat <<EOF > "${REPO_ROOT}/k8s/base/secrets.yaml"
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: devsecops-demo
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/component: api
    app.kubernetes.io/part-of: devsecops-demo
    app.kubernetes.io/managed-by: kubectl
type: Opaque
stringData:
  PG_PASSWORD: "${DB_PASSWORD}"
  POSTGRES_PASSWORD: "${DB_PASSWORD}"
  API_AUTH_TOKEN: "${API_TOKEN}"
EOF
chmod 600 "${REPO_ROOT}/k8s/base/secrets.yaml" 2>/dev/null || true
echo "  [✓] Generated ${REPO_ROOT}/k8s/base/secrets.yaml"

# 2. Generate k8s/monitoring/grafana-secrets.yaml
cat <<EOF > "${REPO_ROOT}/k8s/monitoring/grafana-secrets.yaml"
apiVersion: v1
kind: Secret
metadata:
  name: grafana-admin-credentials
  namespace: monitoring
  labels:
    app.kubernetes.io/name: grafana
    app.kubernetes.io/component: monitoring
    app.kubernetes.io/part-of: devsecops-demo
    app.kubernetes.io/managed-by: kubectl
type: Opaque
stringData:
  admin-user: 'admin'
  admin-password: "${GRAFANA_PASSWORD}"
EOF
chmod 600 "${REPO_ROOT}/k8s/monitoring/grafana-secrets.yaml" 2>/dev/null || true
echo "  [✓] Generated ${REPO_ROOT}/k8s/monitoring/grafana-secrets.yaml"

echo "Secrets generated successfully."
