#!/usr/bin/env bash
# ==============================================================================
# DevSecOps Demo: Step 8 - Observability Dashboards & Telemetry Gateway
# ==============================================================================
# Purpose:
#   Initiates background Kubernetes port-forward tunnels to expose observability
#   interfaces and operational health endpoints for real-time demonstration:
#   - Grafana (Port 3001 -> Service 3000 in 'monitoring' namespace)
#   - Prometheus (Port 9090 -> Service 9090 in 'monitoring' namespace)
#   - Express API (Port 3000 -> Service 80 in 'devsecops-demo' namespace)
#
# DevSecOps Principles:
#   - SRE Golden Signals: Real-time visualization of Traffic, Latency, Errors, Saturation.
#   - Secure Local Bastion: Uses ephemeral authenticated kubectl port-forwarding
#     instead of exposing management ports to the public Internet or NodePorts.
#   - Clean Teardown: Handles SIGINT/SIGTERM to cleanly terminate background tunnels.
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Formatting and UI Helpers
# ------------------------------------------------------------------------------
COLOR_RESET="\033[0m"
COLOR_GREEN="\033[1;32m"
COLOR_RED="\033[1;31m"
COLOR_YELLOW="\033[1;33m"
COLOR_BLUE="\033[1;34m"
COLOR_CYAN="\033[1;36m"
COLOR_MAGENTA="\033[1;35m"
BOLD="\033[1m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/lib/preflight.sh" ]]; then
  # shellcheck source=demo/lib/preflight.sh
  source "${SCRIPT_DIR}/lib/preflight.sh"
fi

MONITORING_NAMESPACE="${MONITORING_NAMESPACE:-monitoring}"
APP_NAMESPACE="${NAMESPACE:-devsecops-demo}"

echo -e "${COLOR_CYAN}${BOLD}"
echo "======================================================================"
echo " 📊 DevSecOps Demo: Step 8 - Observability & Telemetry Gateway"
echo "======================================================================"
echo -e "${COLOR_RESET}"

if type run_standard_preflight &>/dev/null; then
  run_standard_preflight "${APP_NAMESPACE}"
fi

PIDS=()

cleanup() {
  echo -e "\n${COLOR_YELLOW}Stopping background port-forwarding tunnels...${COLOR_RESET}"
  for pid in "${PIDS[@]}"; do
    kill "${pid}" 2>/dev/null || true
  done
  echo -e "${COLOR_GREEN}Tunnels terminated cleanly.${COLOR_RESET}"
  exit 0
}

trap cleanup INT TERM EXIT

# ------------------------------------------------------------------------------
# 1. Port-Forward Grafana
# ------------------------------------------------------------------------------
if kubectl get svc/grafana -n "${MONITORING_NAMESPACE}" &>/dev/null; then
  echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} Starting Grafana tunnel on http://localhost:3001..."
  kubectl port-forward -n "${MONITORING_NAMESPACE}" svc/grafana 3001:3000 >/dev/null 2>&1 &
  PIDS+=($!)
else
  echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} Service 'grafana' not found in namespace '${MONITORING_NAMESPACE}'."
fi

# ------------------------------------------------------------------------------
# 2. Port-Forward Prometheus
# ------------------------------------------------------------------------------
if kubectl get svc/prometheus -n "${MONITORING_NAMESPACE}" &>/dev/null; then
  echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} Starting Prometheus tunnel on http://localhost:9090..."
  kubectl port-forward -n "${MONITORING_NAMESPACE}" svc/prometheus 9090:9090 >/dev/null 2>&1 &
  PIDS+=($!)
else
  echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} Service 'prometheus' not found in namespace '${MONITORING_NAMESPACE}'."
fi

# ------------------------------------------------------------------------------
# 3. Port-Forward API Service
# ------------------------------------------------------------------------------
if kubectl get svc/api -n "${APP_NAMESPACE}" &>/dev/null; then
  echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} Starting API service tunnel on http://localhost:3000..."
  kubectl port-forward -n "${APP_NAMESPACE}" svc/api 3000:80 >/dev/null 2>&1 &
  PIDS+=($!)
else
  echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} Service 'api' not found in namespace '${APP_NAMESPACE}'."
fi

# Allow tunnels a brief moment to bind and verify
sleep 2

if [[ ${#PIDS[@]} -eq 0 ]]; then
  echo -e "\n${COLOR_RED}[FAIL] No port-forward tunnels could be established. Ensure workloads are deployed.${COLOR_RESET}"
  exit 1
fi

GRAFANA_PW=$(kubectl get secret grafana-secrets -n "${MONITORING_NAMESPACE}" -o jsonpath='{.data.admin-password}' 2>/dev/null | base64 --decode 2>/dev/null || echo "(see k8s/monitoring/grafana-secrets.yaml)")

echo ""
echo -e "${COLOR_GREEN}${BOLD}======================================================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}${BOLD} ✅ Observability Dashboards & Endpoints Active!${COLOR_RESET}"
echo -e "${COLOR_GREEN}${BOLD}======================================================================${COLOR_RESET}"
echo -e "  📊 ${BOLD}Grafana Dashboard:${COLOR_RESET}  http://localhost:3001"
echo -e "     - Username:        admin"
echo -e "     - Password:        ${GRAFANA_PW}"
echo -e ""
echo -e "  📈 ${BOLD}Prometheus Server:${COLOR_RESET}  http://localhost:9090"
echo -e "     - Targets status:  http://localhost:9090/targets"
echo -e ""
echo -e "  🏥 ${BOLD}API Health Check:${COLOR_RESET}   http://localhost:3000/api/health"
echo -e "  📉 ${BOLD}API Raw Metrics:${COLOR_RESET}    http://localhost:3000/metrics"
echo -e "  ℹ️  ${BOLD}API Status Info:${COLOR_RESET}    http://localhost:3000/api/status"
echo ""
echo -e "${COLOR_CYAN}Press Ctrl+C to terminate port-forwarding and release local ports.${COLOR_RESET}"

wait
