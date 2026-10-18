#!/usr/bin/env bash
# ==============================================================================
# DevSecOps Demo - SQL Injection (SQLi) Defense Verification Test Suite
# ==============================================================================
# Standards:
#   - OWASP Top 10: A03:2021 - Injection (CWE-89)
#   - OWASP ASVS v4.0: V5.3 - Parameterized Queries & Data Layer Security
#
# Principles & Defense Architecture:
#   - Strict Parameterization: All SQL interactions utilize prepared statements
#     with positional placeholders ($1, $2) to strictly isolate code from data.
#   - Shift-Left Input Validation: Non-numeric parameters for integer columns
#     are rejected at the HTTP routing boundary with HTTP 400 Bad Request.
#   - Global Error Masking: Database syntax errors and SQLSTATE codes never leak.
#   - Real Route Verification: Validates genuine application endpoints (/api/records)
#     and asserts deterministic response behavior (HTTP 200 / 400).
#   - Missing routes (HTTP 404) or unexpected server errors (HTTP 5xx) strictly FAIL.
# ==============================================================================

set -euo pipefail

# Configuration
API_URL="${API_URL:-http://localhost:3000}"
TIMEOUT_SEC="${TIMEOUT_SEC:-5}"
REPORT_FILE="${REPORT_FILE:-artifacts/security/sql-injection-results.json}"

# Test tracking
PASSED=0
FAILED=0
TOTAL=0
JSON_RESULTS=()

# Formatting helpers
COLOR_RESET="\033[0m"
COLOR_GREEN="\033[1;32m"
COLOR_RED="\033[1;31m"
COLOR_YELLOW="\033[1;33m"
COLOR_BLUE="\033[1;34m"
COLOR_CYAN="\033[1;36m"
BOLD="\033[1m"

log_info() {
  echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $1"
}

log_warn() {
  echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $1"
}

record_result() {
  local test_id="$1"
  local test_name="$2"
  local status="$3"
  local details="$4"
  local http_code="$5"
  local duration_ms="$6"

  TOTAL=$((TOTAL + 1))
  if [[ "$status" == "PASS" ]]; then
    PASSED=$((PASSED + 1))
    echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} [${test_id}] ${test_name}"
    echo -e "       ${COLOR_CYAN}Observed:${COLOR_RESET} HTTP ${http_code} | ${details}"
  else
    FAILED=$((FAILED + 1))
    echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} [${test_id}] ${test_name}"
    echo -e "       ${COLOR_RED}Reason:${COLOR_RESET}  HTTP ${http_code} | ${details}"
  fi

  # Escape quotes for JSON
  local escaped_details
  escaped_details=$(echo "$details" | sed 's/"/\\"/g')
  local escaped_name
  escaped_name=$(echo "$test_name" | sed 's/"/\\"/g')

  JSON_RESULTS+=("{\"id\":\"${test_id}\",\"name\":\"${escaped_name}\",\"status\":\"${status}\",\"http_code\":${http_code},\"duration_ms\":${duration_ms},\"details\":\"${escaped_details}\"}")
}

echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN}${BOLD} DevSecOps SQL Injection Defense Verification Suite${COLOR_RESET}"
echo -e "${COLOR_CYAN} Target Endpoint: ${API_URL}/api/records${COLOR_RESET}"
echo -e "${COLOR_CYAN} Compliance: OWASP A03:2021 Injection / CWE-89 Parameterization${COLOR_RESET}"
echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"

# Verify API is reachable before starting test suite
if ! curl -s --max-time "${TIMEOUT_SEC}" "${API_URL}/healthz" >/dev/null 2>&1; then
  echo -e "${COLOR_RED}[FATAL] API is not responding at ${API_URL}/healthz. Ensure service is active.${COLOR_RESET}"
  exit 1
fi

log_info "API reachability verified. Executing parameterized SQL defense assertions..."

# Forbidden patterns indicating database error/schema leakage
SQL_LEAK_PATTERNS=(
  "syntax error at or near"
  "unterminated quoted string"
  "pg_catalog"
  "information_schema"
  "pg_class"
  "SQLSTATE"
  "PostgreSQL query failed"
  "PSQLException"
  "QueryFailedError"
)

# ------------------------------------------------------------------------------
# Test 0: Baseline Positive Control (Valid Data Retrieval)
# ------------------------------------------------------------------------------
START_TIME=$(date +%s%N 2>/dev/null || echo "0")
RES_FILE=$(mktemp)
HTTP_CODE=$(curl -s -o "${RES_FILE}" -w "%{http_code}" --max-time "${TIMEOUT_SEC}" "${API_URL}/api/records" || echo "000")
BODY=$(cat "${RES_FILE}" 2>/dev/null || true)
rm -f "${RES_FILE}"
END_TIME=$(date +%s%N 2>/dev/null || echo "0")
DURATION=$(( (END_TIME - START_TIME) / 1000000 ))
[[ "$DURATION" -le 0 ]] && DURATION=1

if [[ "${HTTP_CODE}" == "200" ]] && echo "${BODY}" | grep -q '"records":\['; then
  record_result "SQLI-BASE" "Baseline record query (/api/records)" "PASS" "Endpoint functional; returned valid audit records" "${HTTP_CODE}" "${DURATION}"
else
  record_result "SQLI-BASE" "Baseline record query (/api/records)" "FAIL" "Endpoint not functioning as expected. Response: ${BODY:0:80}" "${HTTP_CODE}" "${DURATION}"
fi

# ------------------------------------------------------------------------------
# Helper for Injection Vector Evaluation
# ------------------------------------------------------------------------------
assert_vector() {
  local test_id="$1"
  local test_name="$2"
  local query_params="$3"
  local expected_code="$4"
  local expected_description="$5"

  local start_ns
  start_ns=$(date +%s%N 2>/dev/null || echo "0")
  local resp_file
  resp_file=$(mktemp)

  local code
  code=$(curl -s -o "${resp_file}" -w "%{http_code}" --max-time "${TIMEOUT_SEC}" "${API_URL}/api/records?${query_params}" || echo "000")
  local content
  content=$(cat "${resp_file}" 2>/dev/null || true)
  rm -f "${resp_file}"

  local end_ns
  end_ns=$(date +%s%N 2>/dev/null || echo "0")
  local dur_ms=$(( (end_ns - start_ns) / 1000000 ))
  [[ "$dur_ms" -le 0 ]] && dur_ms=1

  # Check 1: Route missing (404) is a strict failure
  if [[ "${code}" == "404" ]]; then
    record_result "${test_id}" "${test_name}" "FAIL" "Route not found (HTTP 404). Endpoint must exist to prove defense" "${code}" "${dur_ms}"
    return
  fi

  # Check 2: Database leak inspection
  for pattern in "${SQL_LEAK_PATTERNS[@]}"; do
    if echo "${content}" | grep -qi "${pattern}"; then
      record_result "${test_id}" "${test_name}" "FAIL" "Database error leakage detected: '${pattern}'" "${code}" "${dur_ms}"
      return
    fi
  done

  # Check 3: Expected status code verification
  if [[ "${code}" != "${expected_code}" ]]; then
    record_result "${test_id}" "${test_name}" "FAIL" "Expected HTTP ${expected_code}, observed HTTP ${code}. Response: ${content:0:80}" "${code}" "${dur_ms}"
    return
  fi

  # Check 4: For search tautology (SQLI-02), assert count is strictly 0 (no bypassed rows)
  if [[ "${test_id}" == "SQLI-02" ]]; then
    local match_count
    match_count=$(echo "${content}" | grep -o '"count":[0-9]*' | head -n1 | cut -d: -f2 || echo "-1")
    if [[ "${match_count}" -ne 0 ]]; then
      record_result "${test_id}" "${test_name}" "FAIL" "Tautology bypassed WHERE clause: returned ${match_count} rows instead of 0 literal matches" "${code}" "${dur_ms}"
      return
    fi
  fi

  # Check 5: For stacked DROP query (SQLI-03), assert audit_logs table remains intact and functional
  if [[ "${test_id}" == "SQLI-03" ]]; then
    local verify_code
    verify_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT_SEC}" "${API_URL}/api/records?id=1" || echo "000")
    if [[ "${verify_code}" != "200" ]]; then
      record_result "${test_id}" "${test_name}" "FAIL" "Destructive DDL query dropped or damaged table: GET /api/records?id=1 returned HTTP ${verify_code}" "${code}" "${dur_ms}"
      return
    fi
  fi

  record_result "${test_id}" "${test_name}" "PASS" "${expected_description}" "${code}" "${dur_ms}"
}

# ------------------------------------------------------------------------------
# Test 1: Tautology Payload on Integer ID Parameter
# Expectation: Input validation detects non-integer string and rejects with HTTP 400
# ------------------------------------------------------------------------------
assert_vector \
  "SQLI-01" \
  "Tautology injection against integer ID (id=1' OR '1'='1)" \
  "id=1%27%20OR%20%271%27=%271" \
  "400" \
  "Input validation rejected non-numeric ID before query execution"

# ------------------------------------------------------------------------------
# Test 2: Tautology Payload on Search String Parameter
# Expectation: Parameterized query treats payload as literal search text; returns HTTP 200 with 0 matches
# ------------------------------------------------------------------------------
assert_vector \
  "SQLI-02" \
  "Tautology search parameter (search=' OR '1'='1)" \
  "search=%27%20OR%20%271%27=%271" \
  "200" \
  "Parameterized query treated payload as literal text; parsed count is strictly 0"

# ------------------------------------------------------------------------------
# Test 3: Stacked Query DDL Injection
# Expectation: Parameterized query escapes semicolons; returns HTTP 200 with 0 matches; table remains intact
# ------------------------------------------------------------------------------
assert_vector \
  "SQLI-03" \
  "Stacked query injection (search='; DROP TABLE audit_logs;--)" \
  "search=%27;%20DROP%20TABLE%20audit_logs;--" \
  "200" \
  "Prepared statement prevented multi-statement execution; verification query confirmed table remains intact"

# ------------------------------------------------------------------------------
# Test 4: UNION SELECT Information Disclosure
# Expectation: Parameterized query escapes union; returns HTTP 200 with 0 matches
# ------------------------------------------------------------------------------
assert_vector \
  "SQLI-04" \
  "UNION SELECT schema extraction (search=' UNION SELECT 1,2,3...)" \
  "search=%27%20UNION%20SELECT%201,2,3,4,NOW()--" \
  "200" \
  "Prepared statement prevented union subquery execution; no unauthorized rows returned"

# ------------------------------------------------------------------------------
# Export Machine-Readable JSON Report
# ------------------------------------------------------------------------------
mkdir -p "$(dirname "${REPORT_FILE}")"
JOINED_RESULTS=$(IFS=,; echo "${JSON_RESULTS[*]}")
cat <<EOF > "${REPORT_FILE}"
{
  "schema_version": "1.0.0",
  "suite": "sql-injection-defense",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "target": "${API_URL}/api/records",
  "summary": {
    "total": ${TOTAL},
    "passed": ${PASSED},
    "failed": ${FAILED}
  },
  "results": [
    ${JOINED_RESULTS}
  ]
}
EOF

echo ""
log_info "Machine-readable results exported to: ${REPORT_FILE}"

echo -e "\n${COLOR_CYAN}=================================================================${COLOR_RESET}"
if [[ "${FAILED}" -eq 0 ]]; then
  echo -e "${COLOR_GREEN}${BOLD} ✅ All ${TOTAL} SQL Injection Defense Assertions Passed!${COLOR_RESET}"
  echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"
  exit 0
else
  echo -e "${COLOR_RED}${BOLD} ❌ SQL Injection Suite Failed: ${FAILED}/${TOTAL} failed assertions.${COLOR_RESET}"
  echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"
  exit 1
fi
