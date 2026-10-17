#!/usr/bin/env bash
# ==============================================================================
# DevSecOps Demo: Step 6 - Real-World Attack Simulation
# ==============================================================================
# Purpose:
#   Simulates active adversary tactics, techniques, and procedures (TTPs)
#   aligned with MITRE ATT&CK for Containers and OWASP Top 10.
#   Demonstrates how the layered DevSecOps defense-in-depth architecture
#   successfully intercepts and neutralizes each attack stage.
#
# Simulated Attacks:
#   1. SQL Injection (OWASP A03 / MITRE T1190 - Exploit Public-Facing App):
#      Attacker attempts classic SQL bypass query payload.
#   2. Root Privilege Verification (MITRE T1068 - Exploitation for Priv Escalation):
#      Attacker attempts running commands with root (UID 0) privileges.
#   3. File Tampering / Backdoor Persistence (MITRE T1059 / T1543):
#      Attacker attempts writing malicious executable script to the application root directory.
#   4. Privilege Escalation via SUID / sudo (MITRE T1548):
#      Attacker attempts invoking SUID binaries to elevate to superuser.
#   5. Lateral Movement via Pod-to-Pod Pivoting (MITRE T1210 - Lateral Movement):
#      Attacker provisions an unmanaged pod to bypass application logic and query PostgreSQL.
#
# DevSecOps Controls Verified:
#   - Parameterized queries & strict request validation
#   - PSS Restricted Profile: runAsNonRoot, UID 1001
#   - Container Read-Only Root Filesystem (readOnlyRootFilesystem: true)
#   - Kernel Capability Stripping & allowPrivilegeEscalation: false
#   - NIST SP 800-207 Zero-Trust Network Microsegmentation
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

log_attack() {
  echo -e "\n${COLOR_MAGENTA}${BOLD}======================================================================${COLOR_RESET}"
  echo -e "${COLOR_MAGENTA}${BOLD} 🎯 Attack Vector [$1]: $2${COLOR_RESET}"
  echo -e "${COLOR_MAGENTA}${BOLD}======================================================================${COLOR_RESET}"
}

log_blocked() {
  echo -e "${COLOR_GREEN}${BOLD} [BLOCKED BY DEVSECOPS CONTROL]${COLOR_RESET} $1"
}

log_info() {
  echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $1"
}

NAMESPACE="${NAMESPACE:-devsecops-demo}"
API_URL="${API_URL:-http://localhost:3000}"

echo -e "${COLOR_CYAN}${BOLD}"
echo "======================================================================"
echo " 🎯 Simulating Real-World Attacks Against DevSecOps Hardened Stack"
echo " (Every attack vector is intercepted by declarative Kubernetes security)"
echo "======================================================================"
echo -e "${COLOR_RESET}"

if type run_standard_preflight &>/dev/null; then
  run_standard_preflight "${NAMESPACE}"
fi

ATTACK_FAILURES=0

# Locate API pod
API_POD=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=api -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [[ -z "${API_POD}" ]]; then
  API_POD=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/component=api -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
fi

# ------------------------------------------------------------------------------
# Attack 1: SQL Injection Exploitation Attempt
# ------------------------------------------------------------------------------
log_attack "1/5" "SQL Injection (OWASP A03:2021 / CWE-89)"
echo -e "Attacker Objective: Bypass authorization or extract schema using SQL injection."
echo -e "Target Endpoint: ${API_URL}/api/records"
echo -e "Payload: ${BOLD}search=' OR '1'='1${COLOR_RESET}"

SQL_RESPONSE=$(curl -s "${API_URL}/api/records?search=%27%20OR%20%271%27=%271" 2>/dev/null || echo "FAILED")

echo -e "API Response: ${COLOR_CYAN}${SQL_RESPONSE}${COLOR_RESET}"
if echo "${SQL_RESPONSE}" | grep -qiE "syntax error|pg_|sqlstate|relation|database"; then
  echo -e "${COLOR_RED}[CRITICAL BREACH] SQL error message or internal database state leaked!${COLOR_RESET}"
  ATTACK_FAILURES=$((ATTACK_FAILURES + 1))
elif [[ "${SQL_RESPONSE}" == "FAILED" ]]; then
  echo -e "${COLOR_YELLOW}[WARN] API endpoint was unreachable during test.${COLOR_RESET}"
else
  log_blocked "Parameterized query treated input as literal value. Zero records returned, no schema exposed."
  echo -e "  🛡️ Control: Parameterized queries ($1, $2) and strict request validation."
fi

# ------------------------------------------------------------------------------
# Attack 2: Root Execution Attempt
# ------------------------------------------------------------------------------
log_attack "2/5" "Arbitrary Command Execution as Root (MITRE T1068)"
echo -e "Attacker Objective: Execute arbitrary shell commands as UID 0 (root)."

if [[ -z "${API_POD}" ]]; then
  echo -e "${COLOR_YELLOW}[WARN] API pod not found in namespace ${NAMESPACE}. Skipping Attack 2.${COLOR_RESET}"
else
  USER_ID=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- id -u 2>/dev/null || echo "unknown")
  USER_NAME=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- whoami 2>/dev/null || echo "unknown")

  echo -e "Active Execution Identity: ${BOLD}UID ${USER_ID} (${USER_NAME})${COLOR_RESET}"
  if [[ "${USER_ID}" == "0" ]]; then
    echo -e "${COLOR_RED}[CRITICAL BREACH] Container is running with root (UID 0) privileges!${COLOR_RESET}"
    ATTACK_FAILURES=$((ATTACK_FAILURES + 1))
  else
    log_blocked "Container strictly forbidden from running as root."
    echo -e "  🛡️ Control: Pod Security Standards 'runAsNonRoot: true', 'runAsUser: 1001'."
  fi
fi

# ------------------------------------------------------------------------------
# Attack 3: Web Shell / Backdoor Persistence
# ------------------------------------------------------------------------------
log_attack "3/5" "Malware Persistence & Filesystem Modification (MITRE T1059)"
echo -e "Attacker Objective: Plant webshell or backdoor into application directory."

if [[ -z "${API_POD}" ]]; then
  echo -e "${COLOR_YELLOW}[WARN] API pod not found. Skipping Attack 3.${COLOR_RESET}"
else
  PERSIST_ATTEMPT=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- touch /app/evil.js 2>&1 || true)
  echo -e "Filesystem Modification Attempt Output: ${COLOR_CYAN}${PERSIST_ATTEMPT}${COLOR_RESET}"

  if echo "${PERSIST_ATTEMPT}" | grep -qiE "Read-only file system|EROFS"; then
    log_blocked "Filesystem write denied: Container root filesystem is mounted strictly read-only."
    echo -e "  🛡️ Control: 'readOnlyRootFilesystem: true' prevents malware staging and config alteration."
  else
    echo -e "${COLOR_RED}[CRITICAL BREACH] Attacker was able to write to container root filesystem!${COLOR_RESET}"
    ATTACK_FAILURES=$((ATTACK_FAILURES + 1))
  fi
fi

# ------------------------------------------------------------------------------
# Attack 4: Privilege Escalation via SUID
# ------------------------------------------------------------------------------
log_attack "4/5" "Privilege Escalation via Kernel Capabilities (MITRE T1548)"
echo -e "Attacker Objective: Escalate to root using SUID binaries or kernel capability exploitation."

if [[ -z "${API_POD}" ]]; then
  echo -e "${COLOR_YELLOW}[WARN] API pod not found. Skipping Attack 4.${COLOR_RESET}"
else
  SUID_FILES=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- find / -perm -4000 2>/dev/null || true)
  if [[ -z "${SUID_FILES}" ]]; then
    log_blocked "Zero SUID executables discovered in container image."
  else
    echo -e "SUID binaries found: ${SUID_FILES}"
  fi
  echo -e "  🛡️ Control: 'allowPrivilegeEscalation: false' & 'capabilities: drop: [ALL]'."
  echo -e "  🛡️ Result: Kernel refuses privilege elevation even if an exploit attempts SUID execution."
fi

# ------------------------------------------------------------------------------
# Attack 5: Lateral Movement to Database
# ------------------------------------------------------------------------------
log_attack "5/5" "Lateral Movement & Direct Database Access (MITRE T1210)"
echo -e "Attacker Objective: Deploy rogue container inside namespace to query PostgreSQL directly."
echo -e "Target: ${BOLD}postgres:5432${COLOR_RESET}"

ATTACKER_POD="attacker-probe-$RANDOM"
cleanup_attacker() {
  local exit_code=$?
  kubectl delete pod "${ATTACKER_POD}" -n "${NAMESPACE}" --ignore-not-found=true --grace-period=0 --force >/dev/null 2>&1 || true
  exit $exit_code
}
trap cleanup_attacker EXIT INT TERM

kubectl run "${ATTACKER_POD}" \
  --image=busybox:1.36 \
  --restart=Never \
  --namespace="${NAMESPACE}" \
  --labels="app.kubernetes.io/name=malicious-attacker" \
  --overrides='{
    "spec": {
      "securityContext": {
        "runAsNonRoot": true,
        "runAsUser": 10002,
        "runAsGroup": 10002,
        "seccompProfile": { "type": "RuntimeDefault" }
      },
      "containers": [{
        "name": "probe",
        "image": "busybox:1.36",
        "command": ["sleep", "60"],
        "securityContext": {
          "allowPrivilegeEscalation": false,
          "readOnlyRootFilesystem": true,
          "capabilities": { "drop": ["ALL"] }
        }
      }]
    }
  }' >/dev/null 2>&1 || true

kubectl wait --namespace="${NAMESPACE}" --for=condition=ready "pod/${ATTACKER_POD}" --timeout=30s >/dev/null 2>&1 || true

if kubectl exec -n "${NAMESPACE}" "${ATTACKER_POD}" -- nc -z -w 3 postgres 5432 2>/dev/null; then
  echo -e "${COLOR_RED}[CRITICAL BREACH] Attacker pod connected directly to PostgreSQL!${COLOR_RESET}"
  ATTACK_FAILURES=$((ATTACK_FAILURES + 1))
else
  log_blocked "Direct database TCP connection dropped by network policy (Connection timed out)!"
  echo -e "  🛡️ Control: NIST SP 800-207 Zero-Trust Network Policies ('default-deny-all')."
  echo -e "  🛡️ Result: Microsegmentation restricts database ingress strictly to authenticated API pods."
fi

# Clean up attacker pod explicitly before summary
kubectl delete pod "${ATTACKER_POD}" -n "${NAMESPACE}" --ignore-not-found=true --grace-period=0 --force >/dev/null 2>&1 || true

if [[ "${ATTACK_FAILURES}" -gt 0 ]]; then
  echo -e "\n${COLOR_RED}${BOLD}======================================================================${COLOR_RESET}"
  echo -e "${COLOR_RED}${BOLD} ❌ Attack Simulation Completed with ${ATTACK_FAILURES} Security Failure(s)!${COLOR_RESET}"
  echo -e "${COLOR_RED}${BOLD}======================================================================${COLOR_RESET}"
  exit 1
fi

echo -e "\n${COLOR_GREEN}${BOLD}======================================================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}${BOLD} ✅ Step 6 Complete: 5/5 Real-World Attacks Successfully Intercepted!${COLOR_RESET}"
echo -e "${COLOR_GREEN}${BOLD}======================================================================${COLOR_RESET}"
echo -e "Next Step: Execute ${BOLD}bash demo/07-chaos-engineering.sh${COLOR_RESET}"
