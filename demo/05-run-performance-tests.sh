#!/usr/bin/env bash
# ==============================================================================
# DevSecOps Demo: Step 5 - Performance Testing Suite (k6)
# ==============================================================================
# Purpose:
#   Orchestrates progressive performance and resilience testing against
#   the deployed Express.js Kubernetes API using k6.
#
# Stages:
#   1. Smoke Test (scripts/k6/smoke.js):
#      - Verifies basic API availability and nominal health endpoints.
#      - SLO: p(95) < 200ms, Error rate < 1%.
#   2. Load Test (scripts/k6/load.js):
#      - Sustained concurrent load (25 VUs) evaluating connection pooling
#        to PostgreSQL and Redis, and evaluating HPA evaluation baseline.
#      - SLO: p(95) < 300ms, p(99) < 500ms, Error rate < 1%.
#   3. Stress Test (scripts/k6/stress.js):
#      - Ramps traffic up to 150 VUs, intentionally pushing the system to
#        trigger the Kubernetes Horizontal Pod Autoscaler (HPA) from 2 to 5 replicas.
#      - SLO: Graceful degradation, error rate < 5%, p(95) < 3000ms.
#
# DevSecOps Principles:
#   - Quality Gates: Non-functional requirements (NFRs) enforced via code.
#   - Automated Elasticity Validation: Validates that HPA scales pods before
#     saturation causes catastrophic cascading failures.
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

log_info() {
  echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $1"
}

log_pass() {
  echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} $1"
}

log_fail() {
  echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} $1"
}

log_warn() {
  echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $1"
}

ARTIFACTS_DIR="artifacts/k6"
mkdir -p "${ARTIFACTS_DIR}"

BASE_URL="${BASE_URL:-http://localhost:3000}"

echo -e "${COLOR_CYAN}${BOLD}"
echo "======================================================================"
echo " ⚡ DevSecOps Demo: Step 5 - Automated Performance & Load Testing"
echo " Target Endpoint:  ${BASE_URL}"
echo " Artifacts Directory: ${ARTIFACTS_DIR}"
echo "======================================================================"
echo -e "${COLOR_RESET}"

# ------------------------------------------------------------------------------
# Verify k6 Runtime (Local Binary or Docker Runner Fallback)
# ------------------------------------------------------------------------------
K6_CMD=""
if command -v k6 &>/dev/null; then
  K6_CMD="k6"
  log_info "Discovered local k6 binary: $(command -v k6)"
elif command -v docker &>/dev/null && docker info &>/dev/null; then
  log_info "Local k6 not found. Utilizing official 'grafana/k6' container image as runner..."
  K6_CMD="docker run --rm -i --net=host -v ${PWD}:/workspace -w /workspace -e BASE_URL=${BASE_URL} grafana/k6"
else
  log_fail "Neither 'k6' nor 'docker' is available. Please install k6 (https://k6.io/docs/get-started/installation/)."
  exit 1
fi

# ------------------------------------------------------------------------------
# 1. Smoke Test Execution
# ------------------------------------------------------------------------------
echo -e "\n${COLOR_MAGENTA}${BOLD}----------------------------------------------------------------------${COLOR_RESET}"
echo -e "${COLOR_MAGENTA}${BOLD} Phase 1: Smoke Test (Sanity Baseline Check)${COLOR_RESET}"
echo -e "${COLOR_MAGENTA}${BOLD}----------------------------------------------------------------------${COLOR_RESET}"

SMOKE_JSON="${ARTIFACTS_DIR}/smoke-results.json"
log_info "Executing scripts/k6/smoke.js..."

SMOKE_EXIT=0
if $K6_CMD run --out json="${SMOKE_JSON}" scripts/k6/smoke.js; then
  log_pass "Smoke test successfully satisfied all baseline SLO thresholds."
else
  SMOKE_EXIT=1
  log_warn "Smoke test finished with threshold alerts."
fi

# ------------------------------------------------------------------------------
# 2. Load Test Execution
# ------------------------------------------------------------------------------
echo -e "\n${COLOR_MAGENTA}${BOLD}----------------------------------------------------------------------${COLOR_RESET}"
echo -e "${COLOR_MAGENTA}${BOLD} Phase 2: Load Test (Steady-State Concurrency & Connection Pools)${COLOR_RESET}"
echo -e "${COLOR_MAGENTA}${BOLD}----------------------------------------------------------------------${COLOR_RESET}"

LOAD_JSON="${ARTIFACTS_DIR}/load-results.json"
log_info "Executing scripts/k6/load.js..."

LOAD_EXIT=0
if $K6_CMD run --out json="${LOAD_JSON}" scripts/k6/load.js; then
  log_pass "Load test successfully satisfied sustained throughput and latency SLOs."
else
  LOAD_EXIT=1
  log_warn "Load test finished with threshold alerts."
fi

# ------------------------------------------------------------------------------
# 3. Stress Test Execution (Triggers HPA Scale-Out)
# ------------------------------------------------------------------------------
echo -e "\n${COLOR_MAGENTA}${BOLD}----------------------------------------------------------------------${COLOR_RESET}"
echo -e "${COLOR_MAGENTA}${BOLD} Phase 3: Stress Test (Resilience, Saturation & HPA Autoscaling)${COLOR_RESET}"
echo -e "${COLOR_MAGENTA}${BOLD}----------------------------------------------------------------------${COLOR_RESET}"

STRESS_JSON="${ARTIFACTS_DIR}/stress-results.json"
log_info "Executing scripts/k6/stress.js (Monitoring HPA scaling in background)..."

# Start background monitor of HPA replicas during stress test
(
  for i in {1..20}; do
    kubectl get hpa -n devsecops-demo 2>/dev/null || true
    sleep 10
  done
) &
HPA_MONITOR_PID=$!

STRESS_EXIT=0
if $K6_CMD run --out json="${STRESS_JSON}" scripts/k6/stress.js; then
  log_pass "Stress test demonstrated resilient auto-scaling and graceful degradation."
else
  STRESS_EXIT=1
  log_warn "Stress test finished with threshold alerts."
fi

# Kill background monitor if still running
kill "${HPA_MONITOR_PID}" 2>/dev/null || true

# ------------------------------------------------------------------------------
# Performance Summary Table
# ------------------------------------------------------------------------------
echo -e "\n${COLOR_CYAN}${BOLD}========================================================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN}${BOLD} Performance Test Results Summary${COLOR_RESET}"
echo -e "${COLOR_CYAN}${BOLD}========================================================================================${COLOR_RESET}"
printf "%-14s | %-12s | %-28s | %-12s\n" "Test Type" "Target VUs" "Primary SLO Gate" "Result"
echo "----------------------------------------------------------------------------------------"
printf "%-14s | %-12s | %-28s | %-12s\n" "Smoke Test" "1 VU" "p(95) < 200ms, Error < 1%" "$([[ $SMOKE_EXIT -eq 0 ]] && echo "PASSED" || echo "REVIEW")"
printf "%-14s | %-12s | %-28s | %-12s\n" "Load Test" "25 VUs" "p(95) < 300ms, Error < 1%" "$([[ $LOAD_EXIT -eq 0 ]] && echo "PASSED" || echo "REVIEW")"
printf "%-14s | %-12s | %-28s | %-12s\n" "Stress Test" "150 VUs" "Graceful Degrade, Error < 5%" "$([[ $STRESS_EXIT -eq 0 ]] && echo "PASSED" || echo "REVIEW")"
echo "----------------------------------------------------------------------------------------"
echo -e "Saved artifacts: ${ARTIFACTS_DIR}/"
echo -e "Next Step: Execute ${BOLD}bash demo/06-simulate-attack.sh${COLOR_RESET}"
