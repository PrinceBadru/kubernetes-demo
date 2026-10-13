#!/usr/bin/env bash
# ==============================================================================
# DevSecOps Demo - Container Security Verification Test Suite
# ==============================================================================
# Standards:
#   - CIS Kubernetes Benchmark v1.8 (Section 5 - Pod Security Policies/Standards)
#   - CIS Docker Benchmark v1.6 (Section 4 & 5 - Container Images & Runtime)
#   - Kubernetes Pod Security Standards (PSS) - Restricted Profile
#
# Principles:
#   - Defense-in-Depth: Enforce principle of least privilege at container runtime.
#   - Immutability: Read-only root filesystem prevents runtime malware persistence.
#   - Isolation: Non-root execution, privilege escalation denial, dropped capabilities.
#   - Resilience: Strict resource requests and limits mitigate DoS / noisy neighbor issues.
#   - Minimal Surface: Auto-mounting API service tokens is disabled when unused.
# ==============================================================================

set -euo pipefail

# Configuration
NAMESPACE="${NAMESPACE:-devsecops-demo}"
APP_LABEL="${APP_LABEL:-app.kubernetes.io/part-of=devsecops-demo}"
TARGET_POD="${TARGET_POD:-}"

# Counters
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

echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN} Starting Container Security & CIS Compliance Verification${COLOR_RESET}"
echo -e "${COLOR_CYAN} Namespace: ${NAMESPACE}${COLOR_RESET}"
echo -e "${COLOR_CYAN} Target Label: ${APP_LABEL}${COLOR_RESET}"
echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"

# Verify cluster connectivity and namespace existence
if ! kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1; then
  echo -e "${COLOR_RED}[FATAL] Namespace '${NAMESPACE}' does not exist or cluster is unreachable.${COLOR_RESET}"
  exit 1
fi

# Locate running target pods
if [[ -z "${TARGET_POD}" ]]; then
  TARGET_POD=$(kubectl get pods -n "${NAMESPACE}" -l "${APP_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
fi

# Fallback to any pod in the namespace if app label did not match
if [[ -z "${TARGET_POD}" ]]; then
  TARGET_POD=$(kubectl get pods -n "${NAMESPACE}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
fi

if [[ -z "${TARGET_POD}" ]]; then
  echo -e "${COLOR_RED}[FATAL] No running pods found in namespace '${NAMESPACE}' to evaluate.${COLOR_RESET}"
  exit 1
fi

log_info "Evaluating pod: ${TARGET_POD} in namespace: ${NAMESPACE}"

# Retrieve Pod specification in JSON format for safe evaluation
POD_JSON=$(kubectl get pod "${TARGET_POD}" -n "${NAMESPACE}" -o json)

# ------------------------------------------------------------------------------
# Test 1: Verify containers run as non-root (CIS 4.1 / PSS Restricted)
# Rationale: Running as non-root mitigates container breakout vulnerabilities by
# ensuring the process inside the container cannot acquire root privileges on host.
# ------------------------------------------------------------------------------
RUN_AS_NON_ROOT=$(echo "${POD_JSON}" | kubectl get -f - -o jsonpath='{.spec.securityContext.runAsNonRoot}' 2>/dev/null || true)
CONTAINER_RUN_AS_NON_ROOT=$(echo "${POD_JSON}" | kubectl get -f - -o jsonpath='{.spec.containers[0].securityContext.runAsNonRoot}' 2>/dev/null || true)
RUN_AS_USER=$(echo "${POD_JSON}" | kubectl get -f - -o jsonpath='{.spec.securityContext.runAsUser}' 2>/dev/null || true)
CONTAINER_RUN_AS_USER=$(echo "${POD_JSON}" | kubectl get -f - -o jsonpath='{.spec.containers[0].securityContext.runAsUser}' 2>/dev/null || true)

if [[ "${RUN_AS_NON_ROOT}" == "true" || "${CONTAINER_RUN_AS_NON_ROOT}" == "true" ]]; then
  test_result "CIS-4.1" "Container runs as non-root (runAsNonRoot=true)" "PASS" "runAsNonRoot is explicitly enforced (pod=${RUN_AS_NON_ROOT}, container=${CONTAINER_RUN_AS_NON_ROOT}, uid=${RUN_AS_USER:-$CONTAINER_RUN_AS_USER})"
elif [[ -n "${RUN_AS_USER}" && "${RUN_AS_USER}" -gt 0 ]] || [[ -n "${CONTAINER_RUN_AS_USER}" && "${CONTAINER_RUN_AS_USER}" -gt 0 ]]; then
  test_result "CIS-4.1" "Container runs as non-root (runAsUser > 0)" "PASS" "UID is non-zero (pod=${RUN_AS_USER}, container=${CONTAINER_RUN_AS_USER})"
else
  test_result "CIS-4.1" "Container runs as non-root" "FAIL" "Neither runAsNonRoot=true nor non-zero runAsUser is configured"
fi

# ------------------------------------------------------------------------------
# Test 2: Verify no privileged containers (CIS 5.4 / PSS Restricted)
# Rationale: Privileged containers disable all container isolation mechanisms,
# effectively granting root access to the underlying host.
# ------------------------------------------------------------------------------
PRIVILEGED=$(echo "${POD_JSON}" | kubectl get -f - -o jsonpath='{.spec.containers[*].securityContext.privileged}' 2>/dev/null || true)

if [[ "${PRIVILEGED}" =~ "true" ]]; then
  test_result "CIS-5.4" "No privileged containers allowed" "FAIL" "Found container with securityContext.privileged=true"
else
  test_result "CIS-5.4" "No privileged containers allowed" "PASS" "All containers run in non-privileged mode"
fi

# ------------------------------------------------------------------------------
# Test 3: Verify Linux capabilities are dropped (CIS 5.3 / PSS Restricted)
# Rationale: Dropping ALL Linux capabilities adheres to least-privilege, preventing
# the container from performing raw socket crafting, kernel module loading, etc.
# ------------------------------------------------------------------------------
DROPPED_CAPS=$(echo "${POD_JSON}" | kubectl get -f - -o jsonpath='{.spec.containers[0].securityContext.capabilities.drop[*]}' 2>/dev/null || true)

if [[ "${DROPPED_CAPS}" =~ "ALL" || "${DROPPED_CAPS}" =~ "all" ]]; then
  test_result "CIS-5.3" "Linux capabilities dropped (drop: [ALL])" "PASS" "Capabilities drop list includes: ${DROPPED_CAPS}"
else
  test_result "CIS-5.3" "Linux capabilities dropped (drop: [ALL])" "FAIL" "Capabilities do not explicitly drop ALL (found: '${DROPPED_CAPS}')"
fi

# ------------------------------------------------------------------------------
# Test 4: Verify read-only root filesystem (CIS 5.12 / PSS Restricted)
# Rationale: An immutable root filesystem prevents attackers from writing payloads,
# modifying system binaries, or maintaining persistence if breached.
# ------------------------------------------------------------------------------
READ_ONLY_ROOT=$(echo "${POD_JSON}" | kubectl get -f - -o jsonpath='{.spec.containers[0].securityContext.readOnlyRootFilesystem}' 2>/dev/null || true)

if [[ "${READ_ONLY_ROOT}" == "true" ]]; then
  test_result "CIS-5.12" "Read-only root filesystem enabled" "PASS" "readOnlyRootFilesystem is set to true"
else
  test_result "CIS-5.12" "Read-only root filesystem enabled" "FAIL" "readOnlyRootFilesystem is not enabled (found: '${READ_ONLY_ROOT}')"
fi

# ------------------------------------------------------------------------------
# Test 5: Verify no privilege escalation (CIS 5.25 / PSS Restricted)
# Rationale: allowPrivilegeEscalation=false sets the no_new_privs bit in Linux,
# blocking processes from gaining privileges via SUID binaries.
# ------------------------------------------------------------------------------
ALLOW_PRIV_ESC=$(echo "${POD_JSON}" | kubectl get -f - -o jsonpath='{.spec.containers[0].securityContext.allowPrivilegeEscalation}' 2>/dev/null || true)

if [[ "${ALLOW_PRIV_ESC}" == "false" ]]; then
  test_result "CIS-5.25" "Privilege escalation disallowed" "PASS" "allowPrivilegeEscalation is set to false"
else
  test_result "CIS-5.25" "Privilege escalation disallowed" "FAIL" "allowPrivilegeEscalation is not set to false (found: '${ALLOW_PRIV_ESC}')"
fi

# ------------------------------------------------------------------------------
# Test 6: Verify resource limits and requests are defined (CIS 5.10)
# Rationale: Setting CPU and Memory requests and limits prevents DoS attacks,
# runaway memory leaks, and host resource starvation by noisy neighbors.
# ------------------------------------------------------------------------------
CPU_LIMIT=$(echo "${POD_JSON}" | kubectl get -f - -o jsonpath='{.spec.containers[0].resources.limits.cpu}' 2>/dev/null || true)
MEM_LIMIT=$(echo "${POD_JSON}" | kubectl get -f - -o jsonpath='{.spec.containers[0].resources.limits.memory}' 2>/dev/null || true)
CPU_REQ=$(echo "${POD_JSON}" | kubectl get -f - -o jsonpath='{.spec.containers[0].resources.requests.cpu}' 2>/dev/null || true)
MEM_REQ=$(echo "${POD_JSON}" | kubectl get -f - -o jsonpath='{.spec.containers[0].resources.requests.memory}' 2>/dev/null || true)

if [[ -n "${CPU_LIMIT}" && -n "${MEM_LIMIT}" && -n "${CPU_REQ}" && -n "${MEM_REQ}" ]]; then
  test_result "CIS-5.10" "Resource requests and limits defined" "PASS" "Limits: CPU=${CPU_LIMIT}, Mem=${MEM_LIMIT} | Requests: CPU=${CPU_REQ}, Mem=${MEM_REQ}"
else
  test_result "CIS-5.10" "Resource requests and limits defined" "FAIL" "Missing resource boundaries (limits: cpu=${CPU_LIMIT}, mem=${MEM_LIMIT}; requests: cpu=${CPU_REQ}, mem=${MEM_REQ})"
fi

# ------------------------------------------------------------------------------
# Test 7: Verify ServiceAccount token not auto-mounted (CIS 5.1.6)
# Rationale: Disabling automountServiceAccountToken prevents pod compromises from
# escalating into Kubernetes API attacks if the pod has no reason to talk to K8s API.
# ------------------------------------------------------------------------------
AUTOMOUNT_TOKEN=$(echo "${POD_JSON}" | kubectl get -f - -o jsonpath='{.spec.automountServiceAccountToken}' 2>/dev/null || true)

if [[ "${AUTOMOUNT_TOKEN}" == "false" ]]; then
  test_result "CIS-5.1.6" "ServiceAccount token auto-mounting disabled" "PASS" "automountServiceAccountToken is explicitly set to false"
else
  test_result "CIS-5.1.6" "ServiceAccount token auto-mounting disabled" "FAIL" "automountServiceAccountToken is not disabled (found: '${AUTOMOUNT_TOKEN}')"
fi

# ------------------------------------------------------------------------------
# Test 8: Verify Seccomp Profile is configured (PSS Restricted / CIS 5.7.2)
# Rationale: RuntimeDefault seccomp profile restricts the available system calls,
# preventing exploitation of obscure Linux kernel vulnerabilities.
# ------------------------------------------------------------------------------
SECCOMP_POD=$(echo "${POD_JSON}" | kubectl get -f - -o jsonpath='{.spec.securityContext.seccompProfile.type}' 2>/dev/null || true)
SECCOMP_CONTAINER=$(echo "${POD_JSON}" | kubectl get -f - -o jsonpath='{.spec.containers[0].securityContext.seccompProfile.type}' 2>/dev/null || true)

if [[ "${SECCOMP_POD}" == "RuntimeDefault" || "${SECCOMP_CONTAINER}" == "RuntimeDefault" || "${SECCOMP_POD}" == "Localhost" || "${SECCOMP_CONTAINER}" == "Localhost" ]]; then
  test_result "CIS-5.7.2" "Seccomp security profile configured" "PASS" "Seccomp profile type: pod=${SECCOMP_POD:-none}, container=${SECCOMP_CONTAINER:-none}"
else
  test_result "CIS-5.7.2" "Seccomp security profile configured" "FAIL" "Seccomp profile is not RuntimeDefault or Localhost (pod=${SECCOMP_POD:-none}, container=${SECCOMP_CONTAINER:-none})"
fi

# ------------------------------------------------------------------------------
# Execution Summary
# ------------------------------------------------------------------------------
echo -e "\n${COLOR_CYAN}=================================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN} Container Security Verification Summary${COLOR_RESET}"
echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"
echo -e " Total Tests:  ${TOTAL}"
echo -e " Passed Tests: ${COLOR_GREEN}${PASSED}${COLOR_RESET}"
echo -e " Failed Tests: ${COLOR_RED}${FAILED}${COLOR_RESET}"

if [[ ${FAILED} -eq 0 ]]; then
  echo -e "\n${COLOR_GREEN}✓ All container security verification tests PASSED.${COLOR_RESET}"
  exit 0
else
  echo -e "\n${COLOR_RED}✗ Some container security verification tests FAILED.${COLOR_RESET}"
  exit 1
fi
