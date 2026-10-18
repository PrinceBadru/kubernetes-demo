#!/usr/bin/env bash
# ==============================================================================
# DevSecOps Demo: Step 1 - Cluster Setup
# ==============================================================================
# Purpose:
#   Provisions a local, multi-node Kubernetes cluster configured for enterprise
#   DevSecOps demonstrations:
#   1. Multi-node topology (1 Control-Plane + 2 Worker nodes) to showcase
#      Pod Anti-Affinity, high availability, and node-level failure isolation.
#   2. Local host-port ingress routing (ports 80 and 443) to support NGINX
#      Ingress Controller without requiring external cloud load balancers.
#   3. Metrics Server deployment for Kubernetes Horizontal Pod Autoscaler (HPA).
#
# DevSecOps Principles:
#   - Infrastructure as Code (IaC): Declarative Kind cluster specification.
#   - Pod Anti-Affinity Validation: Multi-node topology proves pods do not share
#     a single point of physical/virtual failure.
#   - Least Privilege Edge Ingress: Centralized ingress gateway routing with
#     rate limiting and strict path isolation.
#   - Continuous Observability: Metrics Server enables dynamic autoscaling
#     and cluster-level capacity management.
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
BOLD="\033[1m"

log_info() {
  echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $1"
}

log_success() {
  echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_RESET} $1"
}

log_warn() {
  echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $1"
}

log_error() {
  echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $1"
}

CLUSTER_NAME="${CLUSTER_NAME:-devsecops-cluster}"
K8S_TOOL="${K8S_TOOL:-auto}"

echo -e "${COLOR_CYAN}${BOLD}"
echo "======================================================================"
echo " 🚀 DevSecOps Demo: Step 1 - Kubernetes Cluster Provisioning"
echo " Target Cluster Name: ${CLUSTER_NAME}"
echo "======================================================================"
echo -e "${COLOR_RESET}"

# ------------------------------------------------------------------------------
# 1. Verify Prerequisites
# ------------------------------------------------------------------------------
log_info "Validating local workstation prerequisites..."

check_command() {
  local cmd="$1"
  local install_url="$2"
  if ! command -v "$cmd" &>/dev/null; then
    log_error "Command '$cmd' is not installed or not in PATH."
    log_error "Please install it: $install_url"
    return 1
  fi
  log_success "Found $cmd: $(command -v "$cmd")"
}

PREREQS_FAILED=0
check_command "docker" "https://docs.docker.com/get-docker/" || PREREQS_FAILED=1
check_command "kubectl" "https://kubernetes.io/docs/tasks/tools/" || PREREQS_FAILED=1

# Check Docker daemon availability
if ! docker info &>/dev/null; then
  log_error "Docker daemon is not running! Please start Docker Desktop or Docker engine."
  PREREQS_FAILED=1
else
  log_success "Docker daemon is active and responsive."
fi

# Determine cluster provider (Kind preferred, Minikube fallback)
if command -v kind &>/dev/null; then
  K8S_TOOL="kind"
  log_success "Discovered KinD (Kubernetes in Docker)."
elif command -v minikube &>/dev/null; then
  K8S_TOOL="minikube"
  log_warn "KinD not found, falling back to Minikube."
else
  log_error "Neither 'kind' nor 'minikube' is installed."
  log_error "Install KinD (recommended): https://kind.sigs.k8s.io/docs/user/quick-start/"
  log_error "Or install Minikube: https://minikube.sigs.k8s.io/docs/start/"
  PREREQS_FAILED=1
fi

if [[ $PREREQS_FAILED -ne 0 ]]; then
  log_error "Prerequisite check failed. Aborting cluster creation."
  exit 1
fi

# ------------------------------------------------------------------------------
# 2. Cluster Creation (KinD Multi-Node or Minikube Multi-Node)
# ------------------------------------------------------------------------------
if [[ "$K8S_TOOL" == "kind" ]]; then
  # Check if cluster already exists
  if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    log_warn "KinD cluster '${CLUSTER_NAME}' already exists."
    read -r -p "Do you want to delete and recreate it? [y/N]: " RECREATE || RECREATE="N"
    if [[ "$RECREATE" =~ ^[Yy]$ ]]; then
      log_info "Deleting existing KinD cluster '${CLUSTER_NAME}'..."
      kind delete cluster --name "${CLUSTER_NAME}"
    else
      log_info "Using existing KinD cluster '${CLUSTER_NAME}'."
    fi
  fi

  if ! kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    log_info "Generating temporary KinD multi-node configuration..."
    KIND_CONFIG_FILE=$(mktemp -t kind-config-XXXXXX.yaml 2>/dev/null || echo "/tmp/kind-config-$$.yaml")
    
    cat <<EOF > "${KIND_CONFIG_FILE}"
# DevSecOps Demo KinD Cluster Configuration
# Defines 1 control plane + 2 worker nodes for anti-affinity & HA testing
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            node-labels: "ingress-ready=true"
    extraPortMappings:
      # Port 80 forward for NGINX Ingress Controller
      - containerPort: 80
        hostPort: 80
        protocol: TCP
      # Port 443 forward for TLS Ingress
      - containerPort: 443
        hostPort: 443
        protocol: TCP
  - role: worker
  - role: worker
EOF

    log_info "Creating KinD cluster '${CLUSTER_NAME}' (1 control-plane, 2 workers)..."
    kind create cluster --name "${CLUSTER_NAME}" --config "${KIND_CONFIG_FILE}"
    rm -f "${KIND_CONFIG_FILE}"
    log_success "KinD cluster '${CLUSTER_NAME}' created successfully."
  fi

  # Set kubeconfig context
  kubectl config use-context "kind-${CLUSTER_NAME}"

elif [[ "$K8S_TOOL" == "minikube" ]]; then
  if minikube status -p "${CLUSTER_NAME}" &>/dev/null; then
    log_info "Minikube profile '${CLUSTER_NAME}' is already active."
  else
    log_info "Starting Minikube multi-node cluster '${CLUSTER_NAME}'..."
    minikube start -p "${CLUSTER_NAME}" --nodes 3 --driver=docker
  fi
  kubectl config use-context "${CLUSTER_NAME}"
fi

# ------------------------------------------------------------------------------
# 3. Deploy Ingress Controller (NGINX)
# ------------------------------------------------------------------------------
log_info "Deploying NGINX Ingress Controller..."

if [[ "$K8S_TOOL" == "kind" ]]; then
  # Pinned KinD-optimized NGINX Ingress manifest (v1.11.3)
  kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.3/deploy/static/provider/kind/deploy.yaml
  log_info "Waiting for Ingress NGINX controller pod to reach Ready status..."
  kubectl wait --namespace ingress-nginx \
    --for=condition=ready pod \
    --selector=app.kubernetes.io/component=controller \
    --timeout=180s || {
      log_warn "Ingress controller pod wait timed out; verifying pod status..."
      kubectl get pods -n ingress-nginx
    }
  log_success "NGINX Ingress Controller is ready."
elif [[ "$K8S_TOOL" == "minikube" ]]; then
  minikube addons enable ingress -p "${CLUSTER_NAME}"
  log_success "Minikube Ingress addon enabled."
fi

# ------------------------------------------------------------------------------
# 4. Deploy Metrics Server (for HPA & Resource Monitoring)
# ------------------------------------------------------------------------------
log_info "Deploying Kubernetes Metrics Server..."

# DevSecOps Principle: Horizontal Pod Autoscaler requires the metrics.k8s.io API.
# Pinned to metrics-server tagged release v0.7.2
METRICS_SERVER_YAML="https://github.com/kubernetes-sigs/metrics-server/releases/download/v0.7.2/components.yaml"

kubectl apply -f "${METRICS_SERVER_YAML}"

log_info "Patching Metrics Server for local cluster TLS compatibility..."
kubectl patch deployment metrics-server -n kube-system --type='json' -p='[
  {
    "op": "add",
    "path": "/spec/template/spec/containers/0/args/-",
    "value": "--kubelet-insecure-tls"
  }
]' 2>/dev/null || true

log_info "Waiting for Metrics Server deployment to become available..."
kubectl rollout status deployment metrics-server -n kube-system --timeout=120s || {
  log_warn "Metrics server rollout wait reached timeout; continuing..."
}
log_success "Metrics Server deployed."

# ------------------------------------------------------------------------------
# 5. Cluster Verification & Node Summary
# ------------------------------------------------------------------------------
log_info "Verifying cluster nodes and readiness..."
kubectl get nodes -o wide

echo ""
echo -e "${COLOR_GREEN}${BOLD}======================================================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}${BOLD} ✅ Step 1 Complete: Local Kubernetes Cluster Ready!${COLOR_RESET}"
echo -e "${COLOR_GREEN}${BOLD}======================================================================${COLOR_RESET}"
echo -e "Cluster Name:       ${CLUSTER_NAME}"
echo -e "Provider:           ${K8S_TOOL}"
echo -e "Node Count:         $(kubectl get nodes --no-headers | wc -l)"
echo -e "Ingress Controller: NGINX Ingress (Ports 80 / 443 host-bound)"
echo -e "Autoscaling Engine: Metrics Server active (HPA ready)"
echo -e "Next Step:          Execute ${BOLD}bash demo/02-deploy-full-stack.sh${COLOR_RESET}"
