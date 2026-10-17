#!/usr/bin/env bash
# ==============================================================================
# Cluster Security Test Runner with Preflight Verification
# ==============================================================================
set -euo pipefail

NAMESPACE="${NAMESPACE:-devsecops-demo}"

COLOR_RESET="\033[0m"
COLOR_YELLOW="\033[1;33m"
COLOR_GREEN="\033[1;32m"
COLOR_CYAN="\033[1;36m"
BOLD="\033[1m"

echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN}${BOLD} DevSecOps Cluster Security Test Runner${COLOR_RESET}"
echo -e "${COLOR_CYAN} Target Namespace: ${NAMESPACE}${COLOR_RESET}"
echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"

# Preflight 1: Check kubectl binary
if ! command -v kubectl >/dev/null 2>&1; then
  echo -e "${COLOR_YELLOW}[SKIPPED] 'kubectl' client binary is not installed in PATH.${COLOR_RESET}"
  echo -e "          Cluster tests require kubectl and a running demo cluster."
  echo -e "          Run 'npm test' for offline application unit and routing tests."
  exit 0
fi

# Preflight 2: Check cluster connectivity
if ! kubectl cluster-info >/dev/null 2>&1; then
  echo -e "${COLOR_YELLOW}[SKIPPED] No reachable Kubernetes cluster found on current kubeconfig.${COLOR_RESET}"
  echo -e "          Cluster tests require an active cluster (e.g. minikube, kind, k3d)."
  echo -e "          To spin up the demo cluster, execute: bash demo/01-setup-cluster.sh"
  exit 0
fi

# Preflight 3: Check target namespace
if ! kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1; then
  echo -e "${COLOR_YELLOW}[SKIPPED] Namespace '${NAMESPACE}' is not present in cluster.${COLOR_RESET}"
  echo -e "          To deploy the stack, execute: bash demo/02-deploy-full-stack.sh"
  exit 0
fi

echo -e "${COLOR_GREEN}[PREFLIGHT OK] Connected to cluster context: $(kubectl config current-context)${COLOR_RESET}"
echo ""

echo -e "${COLOR_CYAN}--> Executing Container Security Validation Suite...${COLOR_RESET}"
bash tests/security/container-security.test.sh

echo ""
echo -e "${COLOR_CYAN}--> Executing Zero-Trust Network Policy Suite...${COLOR_RESET}"
bash tests/security/network-policy.test.sh

echo ""
echo -e "${COLOR_GREEN}=================================================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}${BOLD} ✅ All Cluster Security Suites Completed!${COLOR_RESET}"
echo -e "${COLOR_GREEN}=================================================================${COLOR_RESET}"
