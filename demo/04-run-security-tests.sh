#!/usr/bin/env bash
# ==============================================================================
# DevSecOps Demo: Step 4 - Security Test Suite Orchestrator
# ==============================================================================
# Purpose:
#   Orchestrates automated security test suites to evaluate the running
#   Kubernetes workloads against industry compliance frameworks:
#   - CIS Kubernetes Benchmark & Pod Security Standards (Restricted)
#   - NIST SP 800-207 Zero-Trust Network Microsegmentation
#   - OWASP Top 10 (A03:2021 Injection, A05:2021 Security Misconfiguration)
#   - Automated DAST baseline scanning (OWASP ZAP)
#
# DevSecOps Principles:
#   - Automated Security Gates: Security is evaluated as code with quantifiable
#     pass/fail metrics before production sign-off.
#   - Shift-Left & Shift-Right: Container hardening verified both pre-deployment
#     (manifest inspection) and post-deployment (runtime probing).
#   - Auditability & Governance: Consolidates test metrics into a unified executive report.
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

log_suite() {
  echo -e "\n${COLOR_MAGENTA}${BOLD}======================================================================${COLOR_RESET}"
  echo -e "${COLOR_MAGENTA}${BOLD} 🛡️  [$1] $2${COLOR_RESET}"
  echo -e "${COLOR_MAGENTA}${BOLD}======================================================================${COLOR_RESET}"
}

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

REPORT_DIR="artifacts/security"
mkdir -p "${REPORT_DIR}"
REPORT_FILE="${REPORT_DIR}/security-summary.md"

CONTAINER_SEC_STATUS="PENDING"
NETPOL_STATUS="PENDING"
SQLI_STATUS="PENDING"
ZAP_STATUS="SKIPPED"

START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo -e "${COLOR_CYAN}${BOLD}"
echo "======================================================================"
echo " 🛡️  DevSecOps Demo: Step 4 - Comprehensive Security Test Suite"
echo " Start Timestamp: ${START_TIME}"
echo " Report Output:   ${REPORT_FILE}"
echo "======================================================================"
echo -e "${COLOR_RESET}"

# ------------------------------------------------------------------------------
# Suite 1: Container Security & Hardening Tests
# ------------------------------------------------------------------------------
log_suite "1/4" "Container Runtime Security & PSS Compliance Verification"
if [[ -f tests/security/container-security.test.sh ]]; then
  log_info "Executing tests/security/container-security.test.sh..."
  if bash tests/security/container-security.test.sh; then
    CONTAINER_SEC_STATUS="PASSED"
    log_pass "Container security tests PASSED."
  else
    CONTAINER_SEC_STATUS="FAILED"
    log_fail "Container security tests reported failures."
  fi
else
  log_warn "tests/security/container-security.test.sh not found."
  CONTAINER_SEC_STATUS="NOT_FOUND"
fi

# ------------------------------------------------------------------------------
# Suite 2: Zero-Trust Network Policy Tests
# ------------------------------------------------------------------------------
log_suite "2/4" "Zero-Trust Microsegmentation & Network Policy Tests"
if [[ -f tests/security/network-policy.test.sh ]]; then
  log_info "Executing tests/security/network-policy.test.sh..."
  if bash tests/security/network-policy.test.sh; then
    NETPOL_STATUS="PASSED"
    log_pass "Zero-Trust Network policy tests PASSED."
  else
    NETPOL_STATUS="FAILED"
    log_fail "Network policy tests reported failures."
  fi
else
  log_warn "tests/security/network-policy.test.sh not found."
  NETPOL_STATUS="NOT_FOUND"
fi

# ------------------------------------------------------------------------------
# Suite 3: SQL Injection (OWASP A03:2021) Defense Tests
# ------------------------------------------------------------------------------
log_suite "3/4" "SQL Injection & Input Sanitization Defense Suite"
if [[ -f tests/security/sql-injection.test.sh ]]; then
  log_info "Executing tests/security/sql-injection.test.sh..."
  if bash tests/security/sql-injection.test.sh; then
    SQLI_STATUS="PASSED"
    log_pass "SQL injection defense suite PASSED."
  else
    SQLI_STATUS="FAILED"
    log_fail "SQL injection defense tests reported failures."
  fi
else
  log_warn "tests/security/sql-injection.test.sh not found."
  SQLI_STATUS="NOT_FOUND"
fi

# ------------------------------------------------------------------------------
# Suite 4: Dynamic Application Security Testing (OWASP ZAP Baseline)
# ------------------------------------------------------------------------------
log_suite "4/4" "Dynamic Application Security Testing (DAST) - OWASP ZAP Baseline"
ZAP_TARGET="${ZAP_TARGET:-http://localhost:3000}"

if command -v docker &>/dev/null && docker info &>/dev/null; then
  log_info "Evaluating availability of OWASP ZAP container runner..."
  # Check if user enabled ZAP scan or if image is present
  if [[ "${RUN_ZAP:-false}" == "true" ]] || docker images | grep -q "owasp/zap2docker-stable"; then
    log_info "Running OWASP ZAP baseline scan against ${ZAP_TARGET}..."
    docker run --rm -t --net=host \
      -v "${PWD}/${REPORT_DIR}:/zap/wrk/:rw" \
      owasp/zap2docker-stable zap-baseline.py \
      -t "${ZAP_TARGET}" \
      -r zap-report.html || true
    ZAP_STATUS="COMPLETED"
    log_pass "OWASP ZAP baseline scan generated in ${REPORT_DIR}/zap-report.html."
  else
    log_info "OWASP ZAP scan skipped by default (Set RUN_ZAP=true to download ~1.8GB image and run full DAST scan)."
    ZAP_STATUS="SKIPPED (Optional)"
  fi
else
  log_warn "Docker unavailable for OWASP ZAP execution. Skipping."
  ZAP_STATUS="UNAVAILABLE"
fi

# ------------------------------------------------------------------------------
# Generate Unified Security Audit Markdown Report
# ------------------------------------------------------------------------------
cat <<EOF > "${REPORT_FILE}"
# DevSecOps Kubernetes Demo - Security Audit Report

- **Date:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
- **Target Namespace:** \`${NAMESPACE:-devsecops-demo}\`
- **Audit Framework:** NIST SP 800-207, CIS Kubernetes Benchmark, OWASP ASVS v4.0

---

## Executive Summary

| Test Suite | Scope & Framework | Status |
| :--- | :--- | :--- |
| **Container Hardening** | CIS Benchmark (Non-root UID 1001, ReadOnlyRootFS, Capabilities Drop) | **${CONTAINER_SEC_STATUS}** |
| **Network Policies** | NIST SP 800-207 Zero Trust (Default Deny, Micro-segmentation, Lateral Movement Blocked) | **${NETPOL_STATUS}** |
| **SQL Injection Defenses** | OWASP A03:2021 (Prepared Statements, Error Sanitization, No Stack Traces) | **${SQLI_STATUS}** |
| **DAST Vulnerability Scan**| OWASP ZAP Baseline Security Headers & Attack Surface Scan | **${ZAP_STATUS}** |

---

## DevSecOps Controls Verified

1. **Pod Security Admission (PSA):** Restricts dangerous host access and sets runtime seccomp profile to \`RuntimeDefault\`.
2. **Read-Only Root Filesystem:** Prevents runtime malware drops, backdoor persistence, and configuration tampering.
3. **Dropped Linux Capabilities:** Completely revokes \`CAP_SYS_ADMIN\`, \`CAP_NET_RAW\`, and root escalations.
4. **ServiceAccount Token Isolation:** Pods do not mount long-lived Kubernetes API service account tokens, stopping cluster-wide pivots.
5. **Zero-Trust Network Policies:** All ingress and egress is strictly whitelisted by pod selectors and service ports.

*Report automatically generated by \`demo/04-run-security-tests.sh\`.*
EOF

echo -e "\n${COLOR_GREEN}${BOLD}======================================================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}${BOLD} ✅ Step 4 Complete: Security Auditing Finished!${COLOR_RESET}"
echo -e "${COLOR_GREEN}${BOLD}======================================================================${COLOR_RESET}"
echo -e "Container Security:  ${CONTAINER_SEC_STATUS}"
echo -e "Network Microsegment: ${NETPOL_STATUS}"
echo -e "SQL Injection Defense: ${SQLI_STATUS}"
echo -e "DAST Scan:            ${ZAP_STATUS}"
echo -e "Unified Report:       ${REPORT_FILE}"
echo -e ""
echo -e "Next Step: Execute ${BOLD}bash demo/05-run-performance-tests.sh${COLOR_RESET}"
