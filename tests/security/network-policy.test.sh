#!/usr/bin/env bash
# ==============================================================================
# DevSecOps Demo - Network Policy & Zero-Trust Verification Test Suite
# ==============================================================================
# Architecture & Principles:
#   - NIST SP 800-207 Zero-Trust Architecture: "Never Trust, Always Verify".
#   - Default Deny (Ingress & Egress): All traffic is rejected by default unless
#     an explicit declarative NetworkPolicy permits it.
#   - Lateral Movement Prevention: Workloads that do not require inter-service
#     communication (e.g. Redis -> PostgreSQL) are strictly isolated.
#   - Egress Control: Microservices are forbidden from initiating outbound
#     connections to external public IPs, preventing C2 beaconing and exfiltration.
#   - Microsegmentation: Traffic is restricted to authorized pod selectors and ports.
# ==============================================================================

set -euo pipefail

# Configuration
NAMESPACE="${NAMESPACE:-devsecops-demo}"
POSTGRES_SVC="${POSTGRES_SVC:-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
REDIS_SVC="${REDIS_SVC:-redis}"
REDIS_PORT="${REDIS_PORT:-6379}"
TIMEOUT_SEC="${TIMEOUT_SEC:-5}"

# Test tracking
PASSED=0
FAILED=0
TOTAL=0

# Formatting helpers
COLOR_RESET="\033[0m"
COLOR_GREEN="\033[1;32m"
COLOR_RED="\033[1;31m"
COLOR_YELLOW="\033[1;33m"
COLOR_BLUE="\033[1;34m"
COLOR_CYAN="\033[1;36m"

log_info() {
  echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $1"
}

log_warn() {
  echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $1"
}

test_result() {
  local test_id="$1"
  local test_name="$2"
  local status="$3"
  local details="$4"

  TOTAL=$((TOTAL + 1))
  if [[ "$status" == "PASS" ]]; then
    PASSED=$((PASSED + 1))
    echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} [${test_id}] ${test_name}"
    if [[ -n "$details" ]]; then
      echo -e "       ${COLOR_CYAN}Details:${COLOR_RESET} ${details}"
    fi
  else
    FAILED=$((FAILED + 1))
    echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} [${test_id}] ${test_name}"
    if [[ -n "$details" ]]; then
      echo -e "       ${COLOR_RED}Reason:${COLOR_RESET}  ${details}"
    fi
  fi
}

# Cleanup handler for ephemeral resources
UNAUTH_POD_NAME="netpol-unauthorized-probe-$RANDOM"
cleanup() {
  log_info "Cleaning up ephemeral test resources..."
  kubectl delete pod "${UNAUTH_POD_NAME}" -n "${NAMESPACE}" --ignore-not-found=true --grace-period=0 --force >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN} Starting Zero-Trust Network Policy Verification Tests${COLOR_RESET}"
echo -e "${COLOR_CYAN} Namespace: ${NAMESPACE}${COLOR_RESET}"
echo -e "${COLOR_CYAN} Connection Timeout: ${TIMEOUT_SEC}s${COLOR_RESET}"
echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"

# Verify cluster connectivity
if ! kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1; then
  echo -e "${COLOR_RED}[FATAL] Namespace '${NAMESPACE}' does not exist or cluster is unreachable.${COLOR_RESET}"
  exit 1
fi

# Locate API Pod
API_POD=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=devsecops-demo-api -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [[ -z "${API_POD}" ]]; then
  API_POD=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/component=api -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
fi

# Locate Redis Pod
REDIS_POD=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=redis -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

# Locate Postgres Pod
POSTGRES_POD=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=postgres -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${API_POD}" ]]; then
  echo -e "${COLOR_RED}[FATAL] Could not locate API pod in namespace '${NAMESPACE}'. Ensure deployment is active.${COLOR_RESET}"
  exit 1
fi

log_info "Discovered API Pod:      ${API_POD}"
log_info "Discovered Redis Pod:    ${REDIS_POD:-none}"
log_info "Discovered Postgres Pod: ${POSTGRES_POD:-none}"

# Launch unauthorized test probe pod (without matching security labels)
log_info "Provisioning unauthorized test probe pod: ${UNAUTH_POD_NAME}..."
kubectl run "${UNAUTH_POD_NAME}" \
  --namespace="${NAMESPACE}" \
  --image="busybox:1.36" \
  --labels="app.kubernetes.io/name=unauthorized-probe,app.kubernetes.io/part-of=external-tester" \
  --restart=Never \
  --command -- sleep 3600 >/dev/null 2>&1

kubectl wait --namespace="${NAMESPACE}" --for=condition=Ready "pod/${UNAUTH_POD_NAME}" --timeout=30s >/dev/null 2>&1

# Helper function to test TCP port reachability from a pod
check_tcp_connection() {
  local from_pod="$1"
  local target_host="$2"
  local target_port="$3"

  # Use nc (netcat) with timeout or /dev/tcp if available
  kubectl exec -n "${NAMESPACE}" "${from_pod}" -- \
    sh -c "nc -z -w ${TIMEOUT_SEC} ${target_host} ${target_port} || nc -w ${TIMEOUT_SEC} ${target_host} ${target_port} < /dev/null" >/dev/null 2>&1
}

# ------------------------------------------------------------------------------
# Test 1: API can reach PostgreSQL on port 5432 (Expected: PASS)
# Rationale: API service is authorized to access PostgreSQL for relational data.
# ------------------------------------------------------------------------------
if check_tcp_connection "${API_POD}" "${POSTGRES_SVC}" "${POSTGRES_PORT}"; then
  test_result "NETPOL-01" "API can reach PostgreSQL (${POSTGRES_SVC}:${POSTGRES_PORT})" "PASS" "Authorized database connection succeeded"
else
  test_result "NETPOL-01" "API can reach PostgreSQL (${POSTGRES_SVC}:${POSTGRES_PORT})" "FAIL" "Authorized connection blocked or database unreachable"
fi

# ------------------------------------------------------------------------------
# Test 2: API can reach Redis on port 6379 (Expected: PASS)
# Rationale: API service is authorized to access Redis for caching and session state.
# ------------------------------------------------------------------------------
if check_tcp_connection "${API_POD}" "${REDIS_SVC}" "${REDIS_PORT}"; then
  test_result "NETPOL-02" "API can reach Redis (${REDIS_SVC}:${REDIS_PORT})" "PASS" "Authorized Redis cache connection succeeded"
else
  test_result "NETPOL-02" "API can reach Redis (${REDIS_SVC}:${REDIS_PORT})" "FAIL" "Authorized connection blocked or Redis unreachable"
fi

# ------------------------------------------------------------------------------
# Test 3: Random unauthorized pod CANNOT reach PostgreSQL (Expected: BLOCKED)
# Rationale: Zero-trust ingress rules must block traffic from any unselected pod.
# ------------------------------------------------------------------------------
if check_tcp_connection "${UNAUTH_POD_NAME}" "${POSTGRES_SVC}" "${POSTGRES_PORT}"; then
  test_result "NETPOL-03" "Unauthorized pod CANNOT reach PostgreSQL" "FAIL" "SECURITY BREACH: Unauthorized pod successfully connected to PostgreSQL"
else
  test_result "NETPOL-03" "Unauthorized pod CANNOT reach PostgreSQL" "PASS" "Connection timed out/rejected as expected by NetworkPolicy"
fi

# ------------------------------------------------------------------------------
# Test 4: Random unauthorized pod CANNOT reach Redis (Expected: BLOCKED)
# Rationale: Redis ingress must strictly restrict access to the API tier only.
# ------------------------------------------------------------------------------
if check_tcp_connection "${UNAUTH_POD_NAME}" "${REDIS_SVC}" "${REDIS_PORT}"; then
  test_result "NETPOL-04" "Unauthorized pod CANNOT reach Redis" "FAIL" "SECURITY BREACH: Unauthorized pod successfully connected to Redis"
else
  test_result "NETPOL-04" "Unauthorized pod CANNOT reach Redis" "PASS" "Connection timed out/rejected as expected by NetworkPolicy"
fi

# ------------------------------------------------------------------------------
# Test 5: Redis CANNOT reach PostgreSQL (Expected: BLOCKED / Lateral Movement)
# Rationale: If Redis is compromised, attacker must not be able to pivot laterally
# into PostgreSQL database.
# ------------------------------------------------------------------------------
if [[ -n "${REDIS_POD}" ]]; then
  if check_tcp_connection "${REDIS_POD}" "${POSTGRES_SVC}" "${POSTGRES_PORT}"; then
    test_result "NETPOL-05" "Redis CANNOT reach PostgreSQL (Lateral Movement)" "FAIL" "LATERAL MOVEMENT RISK: Redis pod reached PostgreSQL database"
  else
    test_result "NETPOL-05" "Redis CANNOT reach PostgreSQL (Lateral Movement)" "PASS" "Cross-tier lateral movement successfully blocked by NetworkPolicy"
  fi
else
  test_result "NETPOL-05" "Redis CANNOT reach PostgreSQL (Lateral Movement)" "FAIL" "Redis pod not found to execute lateral movement test"
fi

# ------------------------------------------------------------------------------
# Test 6: API can resolve DNS (CoreDNS / kube-dns access works)
# Rationale: Egress policy must explicitly allow UDP/TCP port 53 to kube-dns,
# otherwise service discovery fails.
# ------------------------------------------------------------------------------
DNS_STATUS=0
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  sh -c "nslookup ${POSTGRES_SVC}.${NAMESPACE}.svc.cluster.local >/dev/null 2>&1 || getent hosts ${POSTGRES_SVC} >/dev/null 2>&1" || DNS_STATUS=$?

if [[ ${DNS_STATUS} -eq 0 ]]; then
  test_result "NETPOL-06" "API can resolve cluster DNS (CoreDNS port 53)" "PASS" "DNS resolution succeeded"
else
  test_result "NETPOL-06" "API can resolve cluster DNS (CoreDNS port 53)" "FAIL" "DNS resolution failed; verify egress rules permit kube-dns access"
fi

# ------------------------------------------------------------------------------
# Test 7: API CANNOT reach external internet (Egress blocked)
# Rationale: Preventing arbitrary internet egress thwarts reverse shells,
# external data exfiltration, and C2 communication.
# ------------------------------------------------------------------------------
# Attempt outbound TCP connection to public DNS/Web (1.1.1.1 on port 80/443)
if check_tcp_connection "${API_POD}" "1.1.1.1" "80" || check_tcp_connection "${API_POD}" "8.8.8.8" "53"; then
  test_result "NETPOL-07" "API outbound internet access blocked" "FAIL" "SECURITY BREACH: API pod can initiate external internet egress"
else
  test_result "NETPOL-07" "API outbound internet access blocked" "PASS" "External internet egress blocked as required by zero-trust egress policy"
fi

# ------------------------------------------------------------------------------
# Execution Summary
# ------------------------------------------------------------------------------
echo -e "\n${COLOR_CYAN}=================================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN} Network Policy Verification Summary${COLOR_RESET}"
echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"
echo -e " Total Tests:  ${TOTAL}"
echo -e " Passed Tests: ${COLOR_GREEN}${PASSED}${COLOR_RESET}"
echo -e " Failed Tests: ${COLOR_RED}${FAILED}${COLOR_RESET}"

if [[ ${FAILED} -eq 0 ]]; then
  echo -e "\n${COLOR_GREEN}✓ All network policy verification tests PASSED.${COLOR_RESET}"
  exit 0
else
  echo -e "\n${COLOR_RED}✗ Some network policy verification tests FAILED.${COLOR_RESET}"
  exit 1
fi
