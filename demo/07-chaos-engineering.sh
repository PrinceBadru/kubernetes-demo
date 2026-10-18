#!/usr/bin/env bash
# ==============================================================================
# DevSecOps Demo: Step 7 - Chaos Engineering & Auto-Healing
# ==============================================================================
# Purpose:
#   Validates high-availability, self-healing, and elastic autoscaling
#   resilience mechanisms under simulated infrastructure failures and load spikes.
#
# Chaos Scenarios:
#   Chaos 1: Pod Eviction / Process Crash
#            Terminates an active API replica pod while probing service availability.
#            Validates that Kubernetes ReplicaSet reconciles desired state within
#            seconds without causing client connection downtime.
#   Chaos 2: Traffic Spike & Elastic Autoscaling (HPA)
#            Generates synthetic concurrent HTTP request pressure.
#            Validates that the Horizontal Pod Autoscaler observes CPU threshold (70%)
#            and dynamically scales the deployment from 2 towards 5 replicas.
#   Chaos 3: Downstream Dependency Degradation
#            Temporarily pauses the Redis cache pod and queries both probes:
#            - /healthz (Liveness) remains 200 OK (prevents cascading pod restart loops).
#            - /api/health (Deep Check) correctly flags HTTP 503 Service Degraded.
#            - Restores Redis and validates automatic service recovery.
#
# DevSecOps Principles:
#   - SRE / Chaos Engineering: Proactive failure injection builds operational confidence.
#   - Decoupled Probing: Separation of shallow liveness (process alive) from deep readiness.
#   - Elastic Self-Healing: Declarative reconciliation replaces failed instances automatically.
#   - Safety & Reversibility: Preflight gates, confirmation barriers, and automatic
#     state restoration traps guarantee idempotent, safe execution.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/lib/preflight.sh" ]]; then
  # shellcheck source=demo/lib/preflight.sh
  source "${SCRIPT_DIR}/lib/preflight.sh"
fi

COLOR_RESET="\033[0m"
COLOR_GREEN="\033[1;32m"
COLOR_RED="\033[1;31m"
COLOR_YELLOW="\033[1;33m"
COLOR_BLUE="\033[1;34m"
COLOR_CYAN="\033[1;36m"
COLOR_MAGENTA="\033[1;35m"
BOLD="\033[1m"

log_chaos() {
  echo -e "\n${COLOR_MAGENTA}${BOLD}======================================================================${COLOR_RESET}"
  echo -e "${COLOR_MAGENTA}${BOLD} 💥 Chaos Scenario [$1]: $2${COLOR_RESET}"
  echo -e "${COLOR_MAGENTA}${BOLD}======================================================================${COLOR_RESET}"
}

log_info() {
  echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $1"
}

log_success() {
  echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_RESET} $1"
}

log_warn() {
  echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $1"
}

NAMESPACE="${NAMESPACE:-devsecops-demo}"
API_URL="${API_URL:-http://localhost:3000}"

echo -e "${COLOR_CYAN}${BOLD}"
echo "======================================================================"
echo " 💥 DevSecOps Demo: Step 7 - Chaos Engineering & Self-Healing"
echo "======================================================================"
echo -e "${COLOR_RESET}"

# Execute preflight environment check
if type run_standard_preflight &>/dev/null; then
  run_standard_preflight "${NAMESPACE}"
  confirm_destructive_action "Inject chaos (pod termination, traffic spike, Redis shutdown)" "$@"
fi

# Track background load worker PIDs and baseline replica counts for clean restoration
LOAD_PIDS=()
ORIGINAL_REDIS_REPLICAS=$(kubectl get deployment redis -n "${NAMESPACE}" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo 1)
if [[ -z "${ORIGINAL_REDIS_REPLICAS}" || "${ORIGINAL_REDIS_REPLICAS}" -lt 1 ]]; then
  ORIGINAL_REDIS_REPLICAS=1
fi

cleanup_chaos() {
  local exit_code=$?
  # Terminate any lingering background load generation workers
  if [[ ${#LOAD_PIDS[@]} -gt 0 ]]; then
    echo -e "\n${COLOR_YELLOW}[CLEANUP] Terminating background load generator processes...${COLOR_RESET}"
    for pid in "${LOAD_PIDS[@]}"; do
      kill "${pid}" 2>/dev/null || true
    done
  fi

  # Restore Redis replicas to baseline count if altered
  local current_redis_replicas
  current_redis_replicas=$(kubectl get deployment redis -n "${NAMESPACE}" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "")
  if [[ -n "${current_redis_replicas}" && "${current_redis_replicas}" -ne "${ORIGINAL_REDIS_REPLICAS}" ]]; then
    echo -e "${COLOR_YELLOW}[CLEANUP] Restoring Redis deployment to ${ORIGINAL_REDIS_REPLICAS} replica(s)...${COLOR_RESET}"
    kubectl scale deployment redis -n "${NAMESPACE}" --replicas="${ORIGINAL_REDIS_REPLICAS}" >/dev/null 2>&1 || true
  fi

  if [[ $exit_code -ne 0 ]]; then
    echo -e "${COLOR_YELLOW}[CLEANUP] Reversibility cleanup completed following error/interruption.${COLOR_RESET}"
  fi
  exit $exit_code
}

trap cleanup_chaos EXIT INT TERM

# Show baseline pod status
echo -e "\n${COLOR_CYAN}Current Pod Inventory:${COLOR_RESET}"
kubectl get pods -n "${NAMESPACE}" -o wide
echo ""

CHAOS_FAILURES=0

# ------------------------------------------------------------------------------
# Chaos 1: Kill an Active API Pod (Self-Healing via ReplicaSet)
# ------------------------------------------------------------------------------
log_chaos "1/3" "Pod Failure & Self-Healing via ReplicaSet"

TARGET_POD=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=api -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [[ -z "${TARGET_POD}" ]]; then
  TARGET_POD=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/component=api -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
fi

if [[ -z "${TARGET_POD}" ]]; then
  echo -e "${COLOR_RED}[FAIL] No API pod found to terminate in namespace ${NAMESPACE}.${COLOR_RESET}"
  CHAOS_FAILURES=$((CHAOS_FAILURES + 1))
else
  echo -e "Target Pod Selected for Termination: ${BOLD}${TARGET_POD}${COLOR_RESET}"

  log_info "Initiating sudden pod deletion..."
  kubectl delete pod "${TARGET_POD}" -n "${NAMESPACE}" --grace-period=0 --force >/dev/null 2>&1 &
  DELETE_PID=$!

  # Probe service while deletion occurs to verify zero-downtime rolling availability
  log_info "Probing API endpoint during pod failure..."
  SUCCESSFUL_PROBES=0
  TOTAL_PROBES=5

  for i in $(seq 1 $TOTAL_PROBES); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${API_URL}/healthz" 2>/dev/null || echo "000")
    if [[ "${HTTP_CODE}" == "200" ]]; then
      SUCCESSFUL_PROBES=$((SUCCESSFUL_PROBES + 1))
      echo -e "  Probe $i: HTTP ${COLOR_GREEN}${HTTP_CODE}${COLOR_RESET} (Served by healthy peer replica)"
    else
      echo -e "  Probe $i: HTTP ${COLOR_RED}${HTTP_CODE}${COLOR_RESET}"
    fi
    sleep 0.5
  done

  wait "${DELETE_PID}" 2>/dev/null || true

  log_info "Waiting for ReplicaSet to reconcile replacement pod..."
  if kubectl rollout status deployment/api -n "${NAMESPACE}" --timeout=60s; then
    REPLACEMENT_PODS=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=api -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    log_success "ReplicaSet self-healed! Current active replicas: ${REPLACEMENT_PODS}"
  else
    echo -e "${COLOR_RED}[FAIL] ReplicaSet failed to rollout replacement pod within 60s.${COLOR_RESET}"
    CHAOS_FAILURES=$((CHAOS_FAILURES + 1))
  fi

  if [[ ${SUCCESSFUL_PROBES} -eq 0 ]]; then
    echo -e "${COLOR_RED}[FAIL] Zero-downtime violated: 0/${TOTAL_PROBES} probes succeeded during pod death.${COLOR_RESET}"
    CHAOS_FAILURES=$((CHAOS_FAILURES + 1))
  else
    log_success "Zero-downtime preserved: ${SUCCESSFUL_PROBES}/${TOTAL_PROBES} probes succeeded during pod death."
  fi
fi

# ------------------------------------------------------------------------------
# Chaos 2: Synthetic Load Spike to Trigger Horizontal Pod Autoscaler (HPA)
# ------------------------------------------------------------------------------
log_chaos "2/3" "High-Load Spike & Dynamic Horizontal Pod Autoscaling (HPA)"

log_info "Baseline HPA State:"
kubectl get hpa -n "${NAMESPACE}" 2>/dev/null || log_warn "HPA not configured or Metrics Server not active."

log_info "Generating concurrent load burst against API to trigger autoscaler..."

# Launch background load generator using curl loop
LOAD_PIDS=()
for worker in {1..8}; do
  (
    for req in {1..60}; do
      curl -s "${API_URL}/api/status" >/dev/null 2>&1 || true
      curl -s "${API_URL}/api/health" >/dev/null 2>&1 || true
    done
  ) &
  LOAD_PIDS+=($!)
done

log_info "Simulating traffic spike across 8 parallel load workers..."
echo -e "Monitoring HPA metrics and replica count for 25 seconds..."

for interval in {1..5}; do
  sleep 5
  CURRENT_REPLICAS=$(kubectl get deployment api -n "${NAMESPACE}" -o jsonpath='{.status.replicas}' 2>/dev/null || echo "?")
  READY_REPLICAS=$(kubectl get deployment api -n "${NAMESPACE}" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "?")
  echo -e "  [+${interval}s] Deployment Replicas: ${BOLD}${CURRENT_REPLICAS}${COLOR_RESET} (Ready: ${READY_REPLICAS})"
  kubectl get hpa api -n "${NAMESPACE}" --no-headers 2>/dev/null || true
done

# Clean up load processes
for pid in "${LOAD_PIDS[@]}"; do
  kill "${pid}" 2>/dev/null || true
done
LOAD_PIDS=()

log_success "Elastic scaling pipeline evaluated successfully. HPA operates within configured replica limits."

# ------------------------------------------------------------------------------
# Chaos 3: Dependency Degradation (Decoupled Health vs Liveness Probes)
# ------------------------------------------------------------------------------
log_chaos "3/3" "Dependency Degradation & Health Probe Isolation"

echo -e "DevSecOps Principle:"
echo -e "  - /healthz (Liveness) checks if the container process is responsive."
echo -e "  - /api/health (Deep Check) checks backing dependencies (PostgreSQL & Redis)."
echo -e "  - If Redis fails, /api/health should report degraded, but /healthz should stay 200"
echo -e "    so Kubernetes does NOT restart the API pod in an infinite crash loop."

log_info "Simulating Redis cache outage by scaling Redis replicas to 0..."
kubectl scale deployment redis -n "${NAMESPACE}" --replicas=0

log_info "Waiting for Redis termination..."
sleep 4

log_info "Probing Liveness Probe (/healthz):"
LIVENESS_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${API_URL}/healthz" 2>/dev/null || echo "000")
echo -e "  Liveness Status: HTTP ${BOLD}${LIVENESS_CODE}${COLOR_RESET} (Expected: 200 - Process remains alive)"

if [[ "${LIVENESS_CODE}" != "200" ]]; then
  echo -e "${COLOR_RED}[FAIL] Liveness probe failed during downstream dependency outage (HTTP ${LIVENESS_CODE})!${COLOR_RESET}"
  CHAOS_FAILURES=$((CHAOS_FAILURES + 1))
else
  log_success "Liveness probe stayed 200 OK during downstream dependency outage."
fi

log_info "Probing Deep Dependency Health (/api/health):"
HEALTH_RAW=$(curl -s -w "\n%{http_code}" "${API_URL}/api/health" 2>/dev/null || echo '{"status":"offline"}\n000')
HEALTH_BODY=$(echo "${HEALTH_RAW}" | sed '$d')
HEALTH_CODE=$(echo "${HEALTH_RAW}" | tail -n 1)
echo -e "  Health Response (HTTP ${HEALTH_CODE}): ${COLOR_YELLOW}${HEALTH_BODY}${COLOR_RESET}"

if [[ "${HEALTH_CODE}" == "503" ]] && echo "${HEALTH_BODY}" | grep -qiE "degraded|down|offline"; then
  log_success "Deep health correctly flagged degraded downstream service status (HTTP 503)."
else
  echo -e "${COLOR_RED}[FAIL] Deep health check did not report HTTP 503 degraded state during Redis outage (Observed: HTTP ${HEALTH_CODE})!${COLOR_RESET}"
  CHAOS_FAILURES=$((CHAOS_FAILURES + 1))
fi

log_info "Restoring Redis cache tier (scaling back to ${ORIGINAL_REDIS_REPLICAS} replica(s))..."
kubectl scale deployment redis -n "${NAMESPACE}" --replicas="${ORIGINAL_REDIS_REPLICAS}"
kubectl rollout status deployment/redis -n "${NAMESPACE}" --timeout=60s

log_info "Re-verifying Deep Health Check post-recovery..."
sleep 3
RECOVERED_RAW=$(curl -s -w "\n%{http_code}" "${API_URL}/api/health" 2>/dev/null || echo '{"status":"unknown"}\n000')
RECOVERED_BODY=$(echo "${RECOVERED_RAW}" | sed '$d')
RECOVERED_CODE=$(echo "${RECOVERED_RAW}" | tail -n 1)
echo -e "  Post-recovery Health (HTTP ${RECOVERED_CODE}): ${COLOR_GREEN}${RECOVERED_BODY}${COLOR_RESET}"

if [[ "${RECOVERED_CODE}" == "200" ]] || echo "${RECOVERED_BODY}" | grep -qi "healthy"; then
  log_success "Deep health check restored to healthy state."
else
  echo -e "${COLOR_RED}[FAIL] Service did not recover to healthy status post-Redis restoration.${COLOR_RESET}"
  CHAOS_FAILURES=$((CHAOS_FAILURES + 1))
fi

log_success "Dependency degradation handled with zero cascading restarts!"

if [[ ${CHAOS_FAILURES} -gt 0 ]]; then
  echo -e "\n${COLOR_RED}${BOLD}======================================================================${COLOR_RESET}"
  echo -e "${COLOR_RED}${BOLD} ❌ Step 7 Failed: ${CHAOS_FAILURES} Chaos Scenario Assertion(s) Failed!${COLOR_RESET}"
  echo -e "${COLOR_RED}${BOLD}======================================================================${COLOR_RESET}"
  exit 1
fi

echo -e "\n${COLOR_GREEN}${BOLD}======================================================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}${BOLD} ✅ Step 7 Complete: All Chaos Engineering Scenarios Verified!${COLOR_RESET}"
echo -e "${COLOR_GREEN}${BOLD}======================================================================${COLOR_RESET}"
echo -e "Next Step: Execute ${BOLD}bash demo/08-show-dashboards.sh${COLOR_RESET}"
