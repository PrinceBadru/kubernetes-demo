#!/usr/bin/env bash
# ==============================================================================
# DevSecOps Demo - SQL Injection (SQLi) Defense Verification Test Suite
# ==============================================================================
# Standards:
#   - OWASP Top 10: A03:2021 - Injection
#   - OWASP ASVS v4.0: V5.3 - Parameterized Queries & Data Layer Security
#   - CWE-89: Improper Neutralization of Special Elements used in an SQL Command
#
# Principles:
#   - Parameterized Queries: All database drivers must utilize prepared statements
#     with placeholder variables ($1, $2, or ?) to strictly separate SQL logic from data.
#   - Strict Input Validation: Strong typing, length checking, and regex allowlists
#     (e.g., Zod, Joi) must sanitize inputs before they reach the persistence layer.
#   - Secure Error Handling (A05:2021): Internal database syntax errors (PostgreSQL,
#     SQLSTATE codes, schema tables) must never leak to API clients in stack traces.
#   - Least Privilege DB Accounts: The application connects via a restricted user
#     ('app') without DDL or administrative execution permissions.
# ==============================================================================

set -euo pipefail

# Configuration
API_URL="${API_URL:-http://localhost:3000}"
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

echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN} Starting SQL Injection Defense Verification Suite${COLOR_RESET}"
echo -e "${COLOR_CYAN} Target API URL: ${API_URL}${COLOR_RESET}"
echo -e "${COLOR_CYAN} OWASP Category: A03:2021 - Injection (CWE-89)${COLOR_RESET}"
echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"

# Verify API is reachable before starting test suite
if ! curl -s --max-time "${TIMEOUT_SEC}" "${API_URL}/healthz" >/dev/null 2>&1 && \
   ! curl -s --max-time "${TIMEOUT_SEC}" "${API_URL}/" >/dev/null 2>&1; then
  echo -e "${COLOR_RED}[FATAL] API is not responding at ${API_URL}. Ensure application is running.${COLOR_RESET}"
  exit 1
fi

log_info "API health check passed. Executing security assertion vectors..."

# List of forbidden patterns that indicate raw database error leakage
SQL_LEAK_PATTERNS=(
  "syntax error at or near"
  "unterminated quoted string"
  "pg_catalog"
  "information_schema"
  "pg_class"
  "SQLSTATE"
  "PostgreSQL query failed"
  "server closed the connection unexpectedly"
  "PSQLException"
  "SequelizeDatabaseError"
  "QueryFailedError"
  "xp_cmdshell"
)

# Helper function to assert safe handling of SQLi payload
# Arguments:
#   $1: Test ID
#   $2: Test Name / Description
#   $3: HTTP Method (GET or POST)
#   $4: Relative Endpoint
#   $5: Payload string
#   $6: Parameter location ("query" or "json_body")
assert_sqli_defense() {
  local test_id="$1"
  local test_name="$2"
  local method="$3"
  local endpoint="$4"
  local payload="$5"
  local location="$6"

  local response_file
  response_file=$(mktemp)
  local http_code=0

  if [[ "$location" == "query" ]]; then
    # URL encode payload for query parameter
    local encoded_payload
    encoded_payload=$(node -e "console.log(encodeURIComponent(process.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
    http_code=$(curl -s -o "${response_file}" -w "%{http_code}" --max-time "${TIMEOUT_SEC}" \
      -X "${method}" "${API_URL}${endpoint}?id=${encoded_payload}&search=${encoded_payload}" || echo "000")
  else
    # JSON body payload
    local json_body
    json_body=$(node -e "console.log(JSON.stringify({ query: process.argv[1], id: process.argv[1], username: process.argv[1] }))" "$payload" 2>/dev/null || \
      echo "{\"query\":\"${payload}\",\"id\":\"${payload}\"}")
    http_code=$(curl -s -o "${response_file}" -w "%{http_code}" --max-time "${TIMEOUT_SEC}" \
      -X "${method}" "${API_URL}${endpoint}" \
      -H "Content-Type: application/json" \
      -d "${json_body}" || echo "000")
  fi

  local body_content
  body_content=$(cat "${response_file}" 2>/dev/null || true)
  rm -f "${response_file}"

  # Verification Criteria:
  # 1. Body must NOT contain internal database leak strings / stack traces.
  # 2. HTTP status code must not indicate unhandled server crash (e.g. unhandled 500 with SQL leak).
  # 3. Payload must not return unauthorized table dumps (information_schema contents).

  local leak_detected=""
  for pattern in "${SQL_LEAK_PATTERNS[@]}"; do
    if echo "${body_content}" | grep -qi "${pattern}"; then
      leak_detected="Detected sensitive database string leakage: '${pattern}'"
      break
    fi
  done

  if [[ -n "${leak_detected}" ]]; then
    test_result "${test_id}" "${test_name}" "FAIL" "${leak_detected} | Status: ${http_code}"
  elif [[ "${http_code}" == "500" ]] && echo "${body_content}" | grep -qi "database"; then
    test_result "${test_id}" "${test_name}" "FAIL" "Unhandled 500 error returned database exception | Response: ${body_content:0:100}"
  else
    test_result "${test_id}" "${test_name}" "PASS" "Payload sanitized or safely handled (HTTP ${http_code}, no SQL dialect leaks)"
  fi
}

# ------------------------------------------------------------------------------
# Test 1: Tautology / Boolean-based Authentication Bypass
# Payload: ' OR '1'='1
# Target: Authentication & Query Filter logic
# ------------------------------------------------------------------------------
assert_sqli_defense \
  "SQLI-01" \
  "Tautology condition (' OR '1'='1)" \
  "GET" \
  "/api/search" \
  "' OR '1'='1" \
  "query"

# ------------------------------------------------------------------------------
# Test 2: Stacked Query Execution (DDL / Destructive query injection)
# Payload: '; DROP TABLE users;--
# Target: Any parameter that might concatenate user input into SQL
# ------------------------------------------------------------------------------
assert_sqli_defense \
  "SQLI-02" \
  "Stacked query injection ('; DROP TABLE users;--)" \
  "POST" \
  "/api/audit" \
  "'; DROP TABLE users;--" \
  "json_body"

# ------------------------------------------------------------------------------
# Test 3: Union-Based Information Disclosure (Extracting schema tables)
# Payload: ' UNION SELECT * FROM information_schema.tables--
# Target: Relational select endpoints
# ------------------------------------------------------------------------------
assert_sqli_defense \
  "SQLI-03" \
  "UNION SELECT schema extraction (' UNION SELECT * FROM information_schema.tables--)" \
  "GET" \
  "/api/records" \
  "' UNION SELECT * FROM information_schema.tables--" \
  "query"

# ------------------------------------------------------------------------------
# Test 4: Database Shell Command Execution (Command Injection via DB engine)
# Payload: 1; EXEC xp_cmdshell('whoami')
# Target: PostgreSQL / Relational command execution checks
# ------------------------------------------------------------------------------
assert_sqli_defense \
  "SQLI-04" \
  "Command execution payload (1; EXEC xp_cmdshell('whoami'))" \
  "POST" \
  "/api/execute" \
  "1; EXEC xp_cmdshell('whoami')" \
  "json_body"

# ------------------------------------------------------------------------------
# Test 5: Blind / Time-Based Injection (pg_sleep)
# Payload: 1' AND (SELECT 1 FROM (SELECT(PG_SLEEP(5)))a)--
# Rationale: Verifies the database does not pause execution for injected functions
# ------------------------------------------------------------------------------
START_TIME=$(date +%s)
assert_sqli_defense \
  "SQLI-05" \
  "Time-based blind injection (PG_SLEEP check)" \
  "GET" \
  "/api/lookup" \
  "1' AND (SELECT 1 FROM (SELECT(PG_SLEEP(5)))a)--" \
  "query"
ELAPSED=$(( $(date +%s) - START_TIME ))

if [[ ${ELAPSED} -ge 5 ]]; then
  test_result "SQLI-05-TIME" "Blind SQLi response timing check" "FAIL" "Query took ${ELAPSED}s (suspected PG_SLEEP execution)"
else
  test_result "SQLI-05-TIME" "Blind SQLi response timing check" "PASS" "Query returned promptly in ${ELAPSED}s (< 5s sleep threshold)"
fi

# ------------------------------------------------------------------------------
# Execution Summary
# ------------------------------------------------------------------------------
echo -e "\n${COLOR_CYAN}=================================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN} SQL Injection Defense Verification Summary${COLOR_RESET}"
echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"
echo -e " Total Tests:  ${TOTAL}"
echo -e " Passed Tests: ${COLOR_GREEN}${PASSED}${COLOR_RESET}"
echo -e " Failed Tests: ${COLOR_RED}${FAILED}${COLOR_RESET}"

if [[ ${FAILED} -eq 0 ]]; then
  echo -e "\n${COLOR_GREEN}✓ All SQL injection defense verification tests PASSED.${COLOR_RESET}"
  exit 0
else
  echo -e "\n${COLOR_RED}✗ Some SQL injection defense tests FAILED.${COLOR_RESET}"
  exit 1
fi
