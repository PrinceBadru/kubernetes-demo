#!/usr/bin/env bash
# ==============================================================================
# DevSecOps Demo - Shared Preflight & Environment Safety Verification
# ==============================================================================
# Purpose:
#   Provides strict safeguards for demo and security scripts:
#   1. Verifies required tool binaries (kubectl, curl).
#   2. Validates cluster reachability.
#   3. Enforces disposable-context safety gates to prevent accidental execution
#      against production or staging environments.
#   4. Displays target cluster context and namespace before mutating workloads.
#   5. Provides interactive confirmation gates for destructive actions.
# ==============================================================================

COLOR_RESET="\033[0m"
COLOR_GREEN="\033[1;32m"
COLOR_RED="\033[1;31m"
COLOR_YELLOW="\033[1;33m"
COLOR_BLUE="\033[1;34m"
COLOR_CYAN="\033[1;36m"
BOLD="\033[1m"

# Safe disposable local development cluster patterns (regex)
DISPOSABLE_CONTEXT_REGEX="^(minikube.*|kind-.*|k3d-.*|docker-desktop|docker-for-desktop|colima|orbstack|microk8s.*|custom-demo.*)$"

check_required_binaries() {
  local missing=()
  for bin in "$@"; do
    if ! command -v "${bin}" &>/dev/null; then
      missing+=("${bin}")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "${COLOR_RED}[PREFLIGHT ERROR] Missing required executable(s): ${missing[*]}${COLOR_RESET}"
    echo -e "Please install missing dependencies before running this demo."
    exit 1
  fi
}

check_cluster_reachability() {
  if ! kubectl cluster-info &>/dev/null; then
    echo -e "${COLOR_RED}[PREFLIGHT ERROR] Kubernetes API server is unreachable.${COLOR_RESET}"
    echo -e "Ensure your cluster is running and your current kubeconfig is valid."
    exit 1
  fi
}

check_context_safety() {
  local current_ctx
  current_ctx=$(kubectl config current-context 2>/dev/null || echo "none")

  if [[ "${current_ctx}" == "none" ]]; then
    echo -e "${COLOR_RED}[PREFLIGHT ERROR] No active Kubernetes context found in kubeconfig.${COLOR_RESET}"
    exit 1
  fi

  if [[ -n "${DEMO_OVERRIDE_CONTEXT:-}" && "${DEMO_OVERRIDE_CONTEXT}" == "true" ]]; then
    echo -e "${COLOR_YELLOW}[PREFLIGHT WARN] DEMO_OVERRIDE_CONTEXT=true: Bypassing context safety gate.${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Proceeding on context: ${BOLD}${current_ctx}${COLOR_RESET}"
    return 0
  fi

  if [[ ! "${current_ctx}" =~ ${DISPOSABLE_CONTEXT_REGEX} ]]; then
    echo -e "${COLOR_RED}======================================================================${COLOR_RESET}"
    echo -e "${COLOR_RED}${BOLD} [PREFLIGHT REFUSAL] UNRECOGNIZED CLUSTER CONTEXT!${COLOR_RESET}"
    echo -e "${COLOR_RED}======================================================================${COLOR_RESET}"
    echo -e "Current Context: ${BOLD}${current_ctx}${COLOR_RESET}"
    echo -e "This demo modifies, stresses, and deletes workloads and services."
    echo -e "For security, execution is restricted to recognized disposable demo contexts:"
    echo -e "  - kind-*, minikube*, k3d-*, docker-desktop, colima, orbstack, microk8s"
    echo -e ""
    echo -e "If you are intentionally executing in a test/sandbox cluster,"
    echo -e "rerun with: ${BOLD}DEMO_OVERRIDE_CONTEXT=true bash $0 $*${COLOR_RESET}"
    echo -e "${COLOR_RED}======================================================================${COLOR_RESET}"
    exit 1
  fi
}

display_target_env() {
  local target_ns="${1:-devsecops-demo}"
  local current_ctx
  current_ctx=$(kubectl config current-context 2>/dev/null || echo "none")

  echo -e "${COLOR_CYAN}----------------------------------------------------------------------${COLOR_RESET}"
  echo -e "  ${BOLD}Kubernetes Context:${COLOR_RESET}   ${COLOR_GREEN}${current_ctx}${COLOR_RESET}"
  echo -e "  ${BOLD}Target Namespace:${COLOR_RESET}     ${COLOR_GREEN}${target_ns}${COLOR_RESET}"
  echo -e "  ${BOLD}Execution Safety:${COLOR_RESET}     Disposable sandbox validated"
  echo -e "${COLOR_CYAN}----------------------------------------------------------------------${COLOR_RESET}"
}

confirm_destructive_action() {
  local action_desc="${1:-destructive modification}"

  # Auto-confirm in non-interactive environments
  if [[ "${CI:-false}" == "true" || "${NON_INTERACTIVE:-false}" == "true" || "${DEMO_AUTO_CONFIRM:-false}" == "true" ]]; then
    return 0
  fi

  # Check command-line flags
  for arg in "$@"; do
    if [[ "${arg}" == "--yes" || "${arg}" == "-y" ]]; then
      return 0
    fi
  done

  echo -e "\n${COLOR_YELLOW}${BOLD}[CONFIRMATION REQUIRED]${COLOR_RESET}"
  echo -e "About to execute: ${BOLD}${action_desc}${COLOR_RESET}"
  read -r -p "Are you sure you want to proceed? [y/N]: " response
  case "${response}" in
    [yY][eE][sS]|[yY])
      return 0
      ;;
    *)
      echo -e "${COLOR_YELLOW}[ABORTED] Operation canceled by user.${COLOR_RESET}"
      exit 0
      ;;
  esac
}

run_standard_preflight() {
  local target_ns="${1:-devsecops-demo}"
  check_required_binaries kubectl curl
  check_cluster_reachability
  check_context_safety
  display_target_env "${target_ns}"
}
