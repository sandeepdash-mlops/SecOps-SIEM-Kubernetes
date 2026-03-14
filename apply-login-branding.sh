#!/bin/bash
# ============================================================================
# iSIEM Branding Script — Production Grade, Fully Dynamic
# Auto-discovers everything from the cluster. Only branding choices in config.
# Phases: Discover → Pre-flight → Backup → Apply → Post-verify → Keep/Rollback
#
# Usage: bash apply-login-branding.sh [branding.conf] [namespace]
#
# FIX vs previous version:
#   REMOVED: opensearchDashboards.defaultAppTitle
#     → Not a valid key in the legacy Joi config schema used by this version
#       of Wazuh Dashboard. Caused fatal ValidationError crash on startup.
#   ADDED: opensearchDashboards.branding.applicationTitle  (tab title)
#          opensearchDashboards.branding.faviconUrl         (favicon)
#     → These are the correct keys registered in the branding sub-schema
#       introduced in OSD 1.2 and present in all Wazuh Dashboard builds.
#   ADDED: Phase 4.7 — favicon HTTP reachability check
#   ADDED: Poison-key guard in Phase 4.3 (fails if defaultAppTitle is present)
#   ADDED: Idempotent OSD config strip (safe to re-run without duplicate keys)
# ============================================================================
set -euo pipefail

# ======================== Load Config ========================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_FILE="${1:-${SCRIPT_DIR}/branding.conf}"

if [[ ! -f "${CONFIG_FILE}" ]]; then
  echo "[✗] Config file not found: ${CONFIG_FILE}"
  echo "    Usage: bash apply-login-branding.sh [path/to/branding.conf]"
  exit 1
fi

# shellcheck source=branding.conf
source "${CONFIG_FILE}"

# Derived local paths
LOGOS_DIR="${SCRIPT_DIR}/../logos"
GENERATED_DIR="${SCRIPT_DIR}/generated/login-branding"
BACKUP_DIR="${SCRIPT_DIR}/generated/backup-$(date +%Y%m%d-%H%M%S)"

# Derived patterns from PREFIX
ALERTS_PATTERN="${PREFIX}-alerts-*"
MONITORING_PATTERN="${PREFIX}-monitoring-*"
SAMPLE_ALERTS_PREFIX="${PREFIX}-alerts-4.x-"

# The HTTP-served path for the favicon.
# The volume mount places the file at ${LOGIN_ASSETS_PATH}/favicons/favicon.svg
# which OSD serves under /ui/favicons/favicon.svg
FAVICON_HTTP_PATH="/ui/favicons/favicon.svg"

# ======================== Colors / Helpers ========================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'

PASS="${GREEN}[✓]${NC}"; FAIL="${RED}[✗]${NC}"
WARN="${YELLOW}[!]${NC}"; INFO="${CYAN}[i]${NC}"
ERRORS=0

pass()   { echo -e "${PASS} $1"; }
fail()   { echo -e "${FAIL} $1"; ERRORS=$((ERRORS + 1)); }
warn()   { echo -e "${WARN} $1"; }
info()   { echo -e "${INFO} $1"; }
header() {
  echo ""
  echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  $1${NC}"
  echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
}

# ================================================================
#  PHASE 0: AUTO-DISCOVERY
# ================================================================
header "PHASE 0 / 6 — AUTO-DISCOVERY"

echo ""
info "Config loaded: ${CONFIG_FILE}"
info "Brand: ${BRAND_NAME} — ${BRAND_SUBTITLE}"
echo ""

# 0.1 — kubectl check (needed for everything else)
if ! command -v kubectl &>/dev/null; then
  echo -e "${FAIL} kubectl not found in PATH. Cannot proceed."
  exit 1
fi
if ! kubectl cluster-info &>/dev/null; then
  echo -e "${FAIL} Cannot connect to Kubernetes cluster. Cannot proceed."
  exit 1
fi
pass "Cluster connected"

# 0.2 — Namespace (from config, CLI second arg, or auto-discover)
echo ""
echo -e "${BOLD}Discovering namespace...${NC}"
# Priority: CLI $2 > branding.conf NAMESPACE > auto-discover
NAMESPACE="${2:-${NAMESPACE:-}}"
if [[ -n "${NAMESPACE}" ]]; then
  # Validate provided namespace exists in the cluster
  if kubectl get namespace "${NAMESPACE}" &>/dev/null; then
    pass "Namespace (provided): ${NAMESPACE}"
  else
    fail "Namespace '${NAMESPACE}' does not exist in the cluster"
    echo "  Hint: kubectl get namespaces"
    exit 1
  fi
else
  for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    if kubectl get deploy -n "${ns}" -l app=wazuh-dashboard -o name 2>/dev/null | grep -q "deployment"; then
      NAMESPACE="${ns}"
      break
    fi
  done
  # Fallback: search by deployment name containing "dashboard" in common wazuh namespaces
  if [[ -z "${NAMESPACE}" ]]; then
    for ns in wazuh wazuh-system security siem; do
      if kubectl get deploy -n "${ns}" 2>/dev/null | grep -qi "dashboard"; then
        NAMESPACE="${ns}"
        break
      fi
    done
  fi
  if [[ -z "${NAMESPACE}" ]]; then
    fail "Could not auto-discover namespace with wazuh-dashboard"
    echo "  Hint: Is the Wazuh deployment running? Check: kubectl get deploy -A"
    exit 1
  fi
  pass "Namespace (discovered): ${NAMESPACE}"
fi

# 0.3 — Discover deployment name
echo ""
echo -e "${BOLD}Discovering dashboard deployment...${NC}"
DASHBOARD_DEPLOY=""
# Try label selector first
DASHBOARD_DEPLOY=$(kubectl get deploy -n "${NAMESPACE}" -l app=wazuh-dashboard -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
# Fallback: look for "dashboard" in deployment names
if [[ -z "${DASHBOARD_DEPLOY}" ]]; then
  DASHBOARD_DEPLOY=$(kubectl get deploy -n "${NAMESPACE}" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | tr ' ' '\n' | grep -i "dashboard" | head -1 || echo "")
fi
if [[ -z "${DASHBOARD_DEPLOY}" ]]; then
  fail "Could not find dashboard deployment in namespace '${NAMESPACE}'"
  exit 1
fi
pass "Deployment: ${DASHBOARD_DEPLOY}"

# 0.4 — Discover container name
echo ""
echo -e "${BOLD}Discovering container name...${NC}"
DASHBOARD_CONTAINER=$(kubectl get deploy "${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" \
  -o jsonpath='{.spec.template.spec.containers[0].name}' 2>/dev/null || echo "")
if [[ -z "${DASHBOARD_CONTAINER}" ]]; then
  fail "Could not discover container name"
  exit 1
fi
pass "Container: ${DASHBOARD_CONTAINER}"

# 0.5 — Discover image version
IMAGE=$(kubectl get deploy "${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" \
  -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || echo "unknown")
pass "Image: ${IMAGE}"

# 0.6 — Discover paths inside container
echo ""
echo -e "${BOLD}Discovering paths inside container...${NC}"

# OSD config path — find opensearch_dashboards.yml
OSD_CONFIG_PATH=$(kubectl get deploy "${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" \
  -o jsonpath='{range .spec.template.spec.containers[0].volumeMounts[*]}{.mountPath}{"\n"}{end}' 2>/dev/null | \
  grep "opensearch_dashboards.yml" | head -1 || echo "")
if [[ -z "${OSD_CONFIG_PATH}" ]]; then
  # Fallback: search in pod
  OSD_CONFIG_PATH=$(kubectl exec deploy/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -- \
    find /usr/share/wazuh-dashboard/config -name "opensearch_dashboards.yml" -type f 2>/dev/null | head -1 || echo "")
fi
if [[ -z "${OSD_CONFIG_PATH}" ]]; then
  OSD_CONFIG_PATH="/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml"
  warn "OSD config path fallback: ${OSD_CONFIG_PATH}"
else
  pass "OSD config: ${OSD_CONFIG_PATH}"
fi

# Base install dir (derive from OSD config path)
INSTALL_DIR=$(echo "${OSD_CONFIG_PATH}" | sed 's|/config/opensearch_dashboards.yml||')
CERTS_PATH="${INSTALL_DIR}/certs"
CORE_LOGOS_PATH="${INSTALL_DIR}/src/core/server/core_app/assets/logos"
LOGIN_ASSETS_PATH="${INSTALL_DIR}/src/core/server/core_app/assets"
PLUGIN_ASSETS_PATH="${INSTALL_DIR}/plugins/wazuh/public/assets"
WAZUH_CONFIG_PATH="${INSTALL_DIR}/data/wazuh/config/wazuh.yaml"

pass "Install dir: ${INSTALL_DIR}"
info "  Certs: ${CERTS_PATH}"
info "  Core logos: ${CORE_LOGOS_PATH}"
info "  Plugin assets: ${PLUGIN_ASSETS_PATH}"
info "  Login assets: ${LOGIN_ASSETS_PATH}"

# 0.7 — Discover API credentials from secrets
echo ""
echo -e "${BOLD}Discovering API credentials...${NC}"

# Find the API cred secret
API_SECRET_NAME=$(kubectl get secrets -n "${NAMESPACE}" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | \
  tr ' ' '\n' | grep -i "wazuh-api-cred\|api-cred" | head -1 || echo "")
if [[ -n "${API_SECRET_NAME}" ]]; then
  API_USERNAME=$(kubectl get secret "${API_SECRET_NAME}" -n "${NAMESPACE}" -o jsonpath='{.data.username}' 2>/dev/null | base64 -d 2>/dev/null || echo "wazuh-wui")
  API_PASSWORD=$(kubectl get secret "${API_SECRET_NAME}" -n "${NAMESPACE}" -o jsonpath='{.data.password}' 2>/dev/null | base64 -d 2>/dev/null || echo "")
  pass "API secret: ${API_SECRET_NAME} (user: ${API_USERNAME})"
else
  warn "Could not find API cred secret — using defaults"
  API_USERNAME="wazuh-wui"
  API_PASSWORD=""
fi

# Discover API host from deployment env vars
API_HOST=$(kubectl get deploy "${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" \
  -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}' 2>/dev/null | \
  grep "^WAZUH_API_URL=" | head -1 | sed 's|^WAZUH_API_URL=https\?://||' || echo "")
if [[ -z "${API_HOST}" ]]; then
  # Fallback: try common service names
  API_HOST="wazuh-manager-master-0.wazuh-cluster"
  warn "API host fallback: ${API_HOST}"
else
  pass "API host: ${API_HOST}"
fi
API_PORT="55000"

# 0.8 — Discover cert file names from volume mounts
echo ""
echo -e "${BOLD}Discovering certificate mounts...${NC}"
CERT_FILES=()
while IFS= read -r mp; do
  [[ -z "${mp}" ]] && continue
  BASENAME=$(basename "${mp}")
  if [[ "${mp}" == "${CERTS_PATH}/"* ]] && [[ "${BASENAME}" == *.pem ]]; then
    CERT_FILES+=("${BASENAME}")
  fi
done < <(kubectl get deploy "${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" \
  -o jsonpath='{range .spec.template.spec.containers[0].volumeMounts[*]}{.mountPath}{"\n"}{end}' 2>/dev/null)
# Fallback: check common cert names in pod
if [[ ${#CERT_FILES[@]} -eq 0 ]]; then
  for cf in cert.pem key.pem root-ca.pem; do
    if kubectl exec deploy/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -- test -f "${CERTS_PATH}/${cf}" 2>/dev/null; then
      CERT_FILES+=("${cf}")
    fi
  done
fi
if [[ ${#CERT_FILES[@]} -gt 0 ]]; then
  pass "Certificates found: ${CERT_FILES[*]}"
else
  warn "No certificate files discovered"
fi

# 0.9 — Discover required logo files
echo ""
echo -e "${BOLD}Discovering local logo files...${NC}"
REQUIRED_LOGOS=()
for f in "${LOGOS_DIR}"/*; do
  [[ -f "${f}" ]] && REQUIRED_LOGOS+=("$(basename "${f}")")
done
if [[ ${#REQUIRED_LOGOS[@]} -gt 0 ]]; then
  pass "Found ${#REQUIRED_LOGOS[@]} logo files in ${LOGOS_DIR}/"
  for logo in "${REQUIRED_LOGOS[@]}"; do
    info "  - ${logo}"
  done
else
  warn "No logo files found in ${LOGOS_DIR}/"
fi

# 0.10 — Discover favicon file
echo ""
echo -e "${BOLD}Discovering favicon file...${NC}"
FAVICON_FILE=$(find "${LOGOS_DIR}" -maxdepth 1 -name "${BRAND_FAVICON_FILE}" 2>/dev/null | head -1 || echo "")
if [[ -n "${FAVICON_FILE}" ]]; then
  pass "Favicon: $(basename "${FAVICON_FILE}")"
else
  warn "Favicon file '${BRAND_FAVICON_FILE}' not found in ${LOGOS_DIR}/ — tab icon will not be customised"
fi

# ---- Discovery summary ----
echo ""
echo -e "${BOLD}─────────────────────────────────────────────────────────${NC}"
echo -e "${BOLD}  AUTO-DISCOVERY COMPLETE${NC}"
echo -e "${DIM}  Namespace:  ${NAMESPACE}${NC}"
echo -e "${DIM}  Deployment: ${DASHBOARD_DEPLOY} (${DASHBOARD_CONTAINER})${NC}"
echo -e "${DIM}  Image:      ${IMAGE}${NC}"
echo -e "${DIM}  API:        ${API_USERNAME}@${API_HOST}:${API_PORT}${NC}"
echo -e "${DIM}  Install:    ${INSTALL_DIR}${NC}"
echo -e "${DIM}  Tab title:  ${BRAND_TAB_TITLE}${NC}"
echo -e "${DIM}  Favicon:    ${FAVICON_HTTP_PATH}${NC}"
echo -e "${BOLD}─────────────────────────────────────────────────────────${NC}"

# ================================================================
#  PHASE 1: PRE-FLIGHT CHECKS
# ================================================================
header "PHASE 1 / 6 — PRE-FLIGHT CHECKS"

# 1.1 — Deployment health
echo ""
echo -e "${BOLD}1.1 Deployment health${NC}"
READY=$(kubectl get deploy "${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -o jsonpath='{.status.readyReplicas}' 2>/dev/null)
DESIRED=$(kubectl get deploy "${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -o jsonpath='{.spec.replicas}' 2>/dev/null)
if [[ "${READY}" == "${DESIRED}" ]] && [[ "${READY}" -gt 0 ]]; then
  pass "Healthy (${READY}/${DESIRED} ready)"
else
  fail "NOT healthy (${READY:-0}/${DESIRED:-?} ready)"
fi

# 1.2 — OSD config readable
echo ""
echo -e "${BOLD}1.2 Dashboard config${NC}"
OSD_CONTENT=""
if OSD_CONTENT=$(kubectl exec deploy/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -- cat "${OSD_CONFIG_PATH}" 2>/dev/null); then
  pass "opensearch_dashboards.yml readable ($(echo "${OSD_CONTENT}" | wc -l) lines)"
else
  fail "Cannot read OSD config from pod"
fi

# 1.2a — Poison key check: fail fast if the broken key is already in config
echo ""
echo -e "${BOLD}1.2a Poison key check${NC}"
if echo "${OSD_CONTENT}" | grep -q "^opensearchDashboards\.defaultAppTitle"; then
  fail "  opensearchDashboards.defaultAppTitle found in live config — this WILL crash the pod!"
  warn "  This script will strip it during Apply. Proceeding is safe."
else
  pass "  No invalid defaultAppTitle key in current config"
fi

# 1.3 — Critical config keys
echo ""
echo -e "${BOLD}1.3 Critical config entries${NC}"
CRITICAL_KEYS=()
for key in server.host server.port opensearch.hosts server.ssl.enabled server.ssl.key server.ssl.certificate opensearch.ssl.certificateAuthorities; do
  if echo "${OSD_CONTENT}" | grep -q "^${key}:"; then
    CRITICAL_KEYS+=("${key}")
    pass "  ${key}"
  else
    warn "  ${key} — not in config (may be set via env)"
  fi
done

# 1.4 — Certificates
echo ""
echo -e "${BOLD}1.4 Certificates${NC}"
for cf in "${CERT_FILES[@]}"; do
  if kubectl exec deploy/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -- test -f "${CERTS_PATH}/${cf}" 2>/dev/null; then
    pass "  ${cf}"
  else
    fail "  ${cf} — MISSING"
  fi
done

# 1.5 — Required logo files
echo ""
echo -e "${BOLD}1.5 Required logo files${NC}"
HAS_REPORTS_PNG=false; HAS_LOGIN_LOGO=false; HAS_LOGIN_BG=false
for logo in "${REQUIRED_LOGOS[@]}"; do
  case "${logo}" in
    *reports*.png) HAS_REPORTS_PNG=true; pass "  ${logo} (PDF reports)" ;;
    *login-logo*|*login_logo*) HAS_LOGIN_LOGO=true; pass "  ${logo} (login logo)" ;;
    *login-bg*|*login_bg*) HAS_LOGIN_BG=true; pass "  ${logo} (login background)" ;;
    *) pass "  ${logo}" ;;
  esac
done
${HAS_REPORTS_PNG} || fail "  Missing: PNG reports logo (*reports*.png)"
${HAS_LOGIN_LOGO}  || fail "  Missing: Login logo (*login-logo*.svg)"
${HAS_LOGIN_BG}    || fail "  Missing: Login background (*login-bg*.svg)"

# Find the actual filenames for login assets
LOGIN_LOGO_FILE=$(find "${LOGOS_DIR}" -maxdepth 1 -name "*login-logo*" -o -name "*login_logo*" 2>/dev/null | head -1 || echo "")
LOGIN_BG_FILE=$(find "${LOGOS_DIR}" -maxdepth 1 -name "*login-bg*" -o -name "*login_bg*" 2>/dev/null | head -1 || echo "")
REPORTS_PNG_FILE=$(find "${LOGOS_DIR}" -maxdepth 1 -name "*reports*.png" 2>/dev/null | head -1 || echo "")

# 1.6 — API password not empty
echo ""
echo -e "${BOLD}1.6 API credentials${NC}"
if [[ -n "${API_PASSWORD}" ]]; then
  pass "API password discovered from secret"
else
  fail "API password is empty — check secret '${API_SECRET_NAME:-not found}'"
fi

# 1.7 — Existing branding ConfigMaps
echo ""
echo -e "${BOLD}1.7 Existing branding ConfigMaps${NC}"
BRANDING_CMS=("isiem-core-logos" "isiem-dashboard-logos" "isiem-login-branding"
  "isiem-theme-logos" "isiem-theme-logos-dark" "isiem-dashboard-osd-config" "isiem-dashboard-config"
  "isiem-favicon" "isiem-patched-constants" "isiem-patched-printer")
EXISTING_COUNT=0
for cm in "${BRANDING_CMS[@]}"; do
  if kubectl get configmap "${cm}" -n "${NAMESPACE}" &>/dev/null; then
    warn "  ${cm} — exists (will be updated)"
    EXISTING_COUNT=$((EXISTING_COUNT + 1))
  else
    info "  ${cm} — will be created"
  fi
done
[[ ${EXISTING_COUNT} -gt 0 ]] && warn "Re-run: ${EXISTING_COUNT} ConfigMap(s) will be updated."

# ---- Verdict ----
echo ""
echo -e "${BOLD}─────────────────────────────────────────────────────────${NC}"
if [[ ${ERRORS} -gt 0 ]]; then
  echo -e "${RED}${BOLD}  PRE-FLIGHT FAILED: ${ERRORS} error(s)${NC}"
  echo -e "${BOLD}─────────────────────────────────────────────────────────${NC}"
  exit 1
fi
echo -e "${GREEN}${BOLD}  PRE-FLIGHT PASSED${NC}"
echo -e "${BOLD}─────────────────────────────────────────────────────────${NC}"
echo ""
read -rp "$(echo -e "${CYAN}Proceed with ${BRAND_NAME} branding? (yes/no): ${NC}")" CONFIRM
[[ "${CONFIRM}" != "yes" ]] && { echo "Aborted."; exit 0; }

# ================================================================
#  PHASE 2: BACKUP
# ================================================================
header "PHASE 2 / 6 — BACKUP"

mkdir -p "${BACKUP_DIR}"
kubectl get deploy "${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -o yaml > "${BACKUP_DIR}/deployment.yaml"
pass "Deployment spec"
echo "${OSD_CONTENT}" > "${BACKUP_DIR}/opensearch_dashboards.yml"
pass "opensearch_dashboards.yml"
kubectl get configmap -n "${NAMESPACE}" -o yaml > "${BACKUP_DIR}/all-configmaps.yaml"
pass "All ConfigMaps"

# Cert checksums
CERT_CHECKSUMS=""
for cf in "${CERT_FILES[@]}"; do
  CKSUM=$(kubectl exec deploy/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -- md5sum "${CERTS_PATH}/${cf}" 2>/dev/null | awk '{print $1}' || echo "n/a")
  CERT_CHECKSUMS="${CERT_CHECKSUMS}${cf}:${CKSUM}\n"
done
echo -e "${CERT_CHECKSUMS}" > "${BACKUP_DIR}/cert-checksums.txt"
pass "Certificate checksums"
info "Backup: ${BACKUP_DIR}"

# ================================================================
#  PHASE 3: APPLY
# ================================================================
header "PHASE 3 / 6 — APPLY (${BRAND_NAME})"

mkdir -p "${GENERATED_DIR}"

# ---- SVG Helper Functions ----
gen_full_logo() {
  local file="$1" stroke="$2" fill_text="$3" fill_sub="$4"
  cat > "${file}" << SVGEOF
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 300 70" width="300" height="70">
  <g transform="translate(35, 35)">
    <path d="M 0,-25 L 15,-25 L 15,-5 Q 15,10 0,15 Q -15,10 -15,-5 L -15,-25 Z" fill="none" stroke="${stroke}" stroke-width="2.5" stroke-linejoin="round"/>
    <path d="M -8,-8 Q -10,-4 -10,0 Q -10,6 -6,10" fill="none" stroke="${stroke}" stroke-width="1.5" stroke-linecap="round" opacity="0.8"/>
    <path d="M -4,-10 Q -7,-5 -7,0 Q -7,7 -2,12" fill="none" stroke="${stroke}" stroke-width="1.5" stroke-linecap="round" opacity="0.8"/>
    <path d="M 0,-12 Q -4,-6 -4,0 Q -4,8 2,13" fill="none" stroke="${stroke}" stroke-width="1.5" stroke-linecap="round" opacity="0.8"/>
    <path d="M 4,-10 Q 0,-5 0,0 Q 0,7 6,12" fill="none" stroke="${stroke}" stroke-width="1.5" stroke-linecap="round" opacity="0.8"/>
    <path d="M 8,-8 Q 3,-4 3,0 Q 3,6 10,10" fill="none" stroke="${stroke}" stroke-width="1.5" stroke-linecap="round" opacity="0.8"/>
    <circle cx="0" cy="8" r="2.5" fill="none" stroke="${stroke}" stroke-width="1.5"/>
    <path d="M -1.5,8 L -1.5,5.5 Q -1.5,4 0,4 Q 1.5,4 1.5,5.5 L 1.5,8" fill="none" stroke="${stroke}" stroke-width="1.5"/>
  </g>
  <text x="70" y="38" font-family="${FONT_FAMILY}" font-size="28" font-weight="600" fill="${fill_text}" letter-spacing="1">${BRAND_NAME}</text>
  <text x="70" y="50" font-family="${FONT_FAMILY}" font-size="9" font-weight="400" fill="${fill_sub}" letter-spacing="2">${BRAND_SUBTITLE}</text>
</svg>
SVGEOF
}

gen_mark() {
  local file="$1" stroke="$2"
  cat > "${file}" << SVGEOF
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 80" width="80" height="80">
  <g transform="translate(40, 40)">
    <path d="M 0,-30 L 18,-30 L 18,-6 Q 18,12 0,18 Q -18,12 -18,-6 L -18,-30 Z" fill="none" stroke="${stroke}" stroke-width="3" stroke-linejoin="round"/>
    <path d="M -10,-10 Q -12,-5 -12,0 Q -12,7 -7,12" fill="none" stroke="${stroke}" stroke-width="2" stroke-linecap="round" opacity="0.8"/>
    <path d="M -5,-12 Q -8,-6 -8,0 Q -8,8 -3,14" fill="none" stroke="${stroke}" stroke-width="2" stroke-linecap="round" opacity="0.8"/>
    <path d="M 0,-14 Q -5,-7 -5,0 Q -5,9 2,15" fill="none" stroke="${stroke}" stroke-width="2" stroke-linecap="round" opacity="0.8"/>
    <path d="M 5,-12 Q 0,-6 0,0 Q 0,8 7,14" fill="none" stroke="${stroke}" stroke-width="2" stroke-linecap="round" opacity="0.8"/>
    <path d="M 10,-10 Q 4,-5 4,0 Q 4,7 12,12" fill="none" stroke="${stroke}" stroke-width="2" stroke-linecap="round" opacity="0.8"/>
    <circle cx="0" cy="9" r="3" fill="none" stroke="${stroke}" stroke-width="2"/>
    <path d="M -2,9 L -2,6 Q -2,4 0,4 Q 2,4 2,6 L 2,9" fill="none" stroke="${stroke}" stroke-width="2"/>
  </g>
</svg>
SVGEOF
}

gen_spinner() {
  local file="$1" stroke="$2"
  cat > "${file}" << SVGEOF
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100" height="100">
  <g transform="translate(50, 50)">
    <path d="M 0,-30 L 18,-30 L 18,-6 Q 18,12 0,18 Q -18,12 -18,-6 L -18,-30 Z" fill="none" stroke="${stroke}" stroke-width="2.5" stroke-linejoin="round" opacity="0.3"/>
    <path d="M 0,-30 L 18,-30 L 18,-6" fill="none" stroke="${COLOR_ACCENT}" stroke-width="2.5" stroke-linecap="round">
      <animateTransform attributeName="transform" type="rotate" values="0;360" dur="1.5s" repeatCount="indefinite"/>
    </path>
  </g>
</svg>
SVGEOF
}

gen_dashboards_logo() {
  local file="$1" stroke="$2" fill_text="$3" fill_sub="$4"
  cat > "${file}" << SVGEOF
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 70" width="400" height="70">
  <g transform="translate(35, 35)">
    <path d="M 0,-25 L 15,-25 L 15,-5 Q 15,10 0,15 Q -15,10 -15,-5 L -15,-25 Z" fill="none" stroke="${stroke}" stroke-width="2.5" stroke-linejoin="round"/>
    <path d="M -8,-8 Q -10,-4 -10,0 Q -10,6 -6,10" fill="none" stroke="${stroke}" stroke-width="1.5" stroke-linecap="round" opacity="0.8"/>
    <path d="M 0,-12 Q -4,-6 -4,0 Q -4,8 2,13" fill="none" stroke="${stroke}" stroke-width="1.5" stroke-linecap="round" opacity="0.8"/>
    <path d="M 8,-8 Q 3,-4 3,0 Q 3,6 10,10" fill="none" stroke="${stroke}" stroke-width="1.5" stroke-linecap="round" opacity="0.8"/>
  </g>
  <text x="70" y="32" font-family="${FONT_FAMILY}" font-size="24" font-weight="600" fill="${fill_text}" letter-spacing="1">${BRAND_NAME}</text>
  <text x="70" y="50" font-family="${FONT_FAMILY}" font-size="14" font-weight="400" fill="${fill_sub}" letter-spacing="1">${BRAND_DASHBOARDS_LABEL}</text>
</svg>
SVGEOF
}

gen_theme_logo() {
  local file="$1" stroke="$2" fill_text="$3" fill_sub="$4"
  cat > "${file}" << SVGEOF
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 305 72.7" width="305" height="72.7">
  <g transform="translate(36, 36)">
    <path d="M 0,-26 L 16,-26 L 16,-5 Q 16,11 0,16 Q -16,11 -16,-5 L -16,-26 Z" fill="none" stroke="${stroke}" stroke-width="2.5" stroke-linejoin="round"/>
    <path d="M -8,-9 Q -11,-4 -11,0 Q -11,7 -6,11" fill="none" stroke="${stroke}" stroke-width="1.5" stroke-linecap="round" opacity="0.8"/>
    <path d="M -4,-11 Q -7,-5 -7,0 Q -7,8 -2,13" fill="none" stroke="${stroke}" stroke-width="1.5" stroke-linecap="round" opacity="0.8"/>
    <path d="M 0,-13 Q -4,-6 -4,0 Q -4,9 2,14" fill="none" stroke="${stroke}" stroke-width="1.5" stroke-linecap="round" opacity="0.8"/>
    <path d="M 4,-11 Q 0,-5 0,0 Q 0,8 6,13" fill="none" stroke="${stroke}" stroke-width="1.5" stroke-linecap="round" opacity="0.8"/>
    <path d="M 8,-9 Q 3,-4 3,0 Q 3,7 10,11" fill="none" stroke="${stroke}" stroke-width="1.5" stroke-linecap="round" opacity="0.8"/>
    <circle cx="0" cy="9" r="2.5" fill="none" stroke="${stroke}" stroke-width="1.5"/>
    <path d="M -1.5,9 L -1.5,6.5 Q -1.5,5 0,5 Q 1.5,5 1.5,6.5 L 1.5,9" fill="none" stroke="${stroke}" stroke-width="1.5"/>
  </g>
  <text x="75" y="42" font-family="${FONT_FAMILY}" font-size="30" font-weight="600" fill="${fill_text}" letter-spacing="1">${BRAND_NAME}</text>
  <text x="75" y="56" font-family="${FONT_FAMILY}" font-size="10" font-weight="400" fill="${fill_sub}" letter-spacing="2">${BRAND_SUBTITLE}</text>
  <circle cx="296" cy="59.2" r="7.5" fill="${COLOR_ACCENT}"/>
</svg>
SVGEOF
}

# ---- Generate all variants ----
info "Generating SVGs..."
gen_full_logo "${GENERATED_DIR}/logo-dark.svg"  "${COLOR_DARK}" "${COLOR_DARK}" "${COLOR_DARK_SECONDARY}"
gen_full_logo "${GENERATED_DIR}/logo-light.svg" "${COLOR_LIGHT}" "${COLOR_LIGHT}" "${COLOR_LIGHT_SECONDARY}"
gen_mark      "${GENERATED_DIR}/mark-dark.svg"  "${COLOR_DARK}"
gen_mark      "${GENERATED_DIR}/mark-light.svg" "${COLOR_LIGHT}"
gen_spinner   "${GENERATED_DIR}/spinner-dark.svg"  "${COLOR_DARK}"
gen_spinner   "${GENERATED_DIR}/spinner-light.svg" "${COLOR_LIGHT}"
gen_dashboards_logo "${GENERATED_DIR}/dashboards-dark.svg"  "${COLOR_DARK}" "${COLOR_DARK}" "${COLOR_DARK_SECONDARY}"
gen_dashboards_logo "${GENERATED_DIR}/dashboards-light.svg" "${COLOR_LIGHT}" "${COLOR_LIGHT}" "${COLOR_LIGHT_SECONDARY}"
gen_theme_logo "${GENERATED_DIR}/theme-light.svg" "${COLOR_DARK}" "${COLOR_DARK}" "${COLOR_DARK_SECONDARY}"
gen_theme_logo "${GENERATED_DIR}/theme-dark.svg"  "${COLOR_LIGHT}" "${COLOR_LIGHT}" "${COLOR_LIGHT_SECONDARY}"
pass "Generated 10 SVG variants"

cp "${REPORTS_PNG_FILE}" "${GENERATED_DIR}/reports-logo.png"
pass "Copied reports PNG"

# ---- Create ConfigMaps ----
info "Creating ConfigMaps..."

kubectl create configmap isiem-core-logos \
  --from-file=wazuh.svg="${GENERATED_DIR}/logo-dark.svg" \
  --from-file=wazuh_on_dark.svg="${GENERATED_DIR}/logo-light.svg" \
  --from-file=wazuh_on_light.svg="${GENERATED_DIR}/logo-dark.svg" \
  --from-file=wazuh_mark.svg="${GENERATED_DIR}/mark-dark.svg" \
  --from-file=wazuh_mark_on_dark.svg="${GENERATED_DIR}/mark-light.svg" \
  --from-file=wazuh_mark_on_light.svg="${GENERATED_DIR}/mark-dark.svg" \
  --from-file=wazuh_center_mark.svg="${GENERATED_DIR}/mark-dark.svg" \
  --from-file=wazuh_center_mark_on_dark.svg="${GENERATED_DIR}/mark-light.svg" \
  --from-file=wazuh_center_mark_on_light.svg="${GENERATED_DIR}/mark-dark.svg" \
  --from-file=wazuh_dashboards.svg="${GENERATED_DIR}/dashboards-dark.svg" \
  --from-file=wazuh_dashboards_on_dark.svg="${GENERATED_DIR}/dashboards-light.svg" \
  --from-file=wazuh_dashboards_on_light.svg="${GENERATED_DIR}/dashboards-dark.svg" \
  --from-file=spinner_on_dark.svg="${GENERATED_DIR}/spinner-light.svg" \
  --from-file=spinner_on_light.svg="${GENERATED_DIR}/spinner-dark.svg" \
  --from-file=icon_dark.svg="${GENERATED_DIR}/mark-light.svg" \
  --from-file=icon_light.svg="${GENERATED_DIR}/mark-dark.svg" \
  -n "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
pass "isiem-core-logos (16 mappings)"

kubectl create configmap isiem-dashboard-logos \
  --from-file=isiem-logo-app.svg="${GENERATED_DIR}/logo-dark.svg" \
  --from-file=isiem-logo-healthcheck.svg="${GENERATED_DIR}/logo-dark.svg" \
  --from-file=isiem-logo-sidebar.svg="${GENERATED_DIR}/mark-dark.svg" \
  --from-file=isiem-logo-reports.png="${GENERATED_DIR}/reports-logo.png" \
  -n "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
pass "isiem-dashboard-logos (4 assets)"

kubectl create configmap isiem-login-branding \
  --from-file=wazuh_logo.svg="${LOGIN_LOGO_FILE}" \
  --from-file=wazuh_login_bg.svg="${LOGIN_BG_FILE}" \
  -n "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
pass "isiem-login-branding"

# Favicon ConfigMap (only if the favicon file exists)
if [[ -n "${FAVICON_FILE}" ]]; then
  kubectl create configmap isiem-favicon \
    --from-file=favicon.svg="${FAVICON_FILE}" \
    -n "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
  pass "isiem-favicon"
else
  warn "Skipping isiem-favicon ConfigMap — no favicon file found"
fi

kubectl create configmap isiem-theme-logos \
  --from-file=logo.svg="${GENERATED_DIR}/theme-light.svg" \
  -n "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
kubectl create configmap isiem-theme-logos-dark \
  --from-file=logo.svg="${GENERATED_DIR}/theme-dark.svg" \
  -n "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
pass "isiem-theme-logos + dark"

# ---- OSD config ----
# ================================================================
# KEY FIX: Tab title and favicon use opensearchDashboards.branding.*
#
# The flat key opensearchDashboards.defaultAppTitle is NOT registered
# in the legacy Joi schema (src/legacy/server/config/config.js) used
# by this version of Wazuh Dashboard. Providing it causes a fatal
# ValidationError on startup — the pod crash-loops immediately.
#
# The correct keys, valid since OSD 1.2, are:
#   opensearchDashboards.branding:
#     applicationTitle: "..."   → sets the browser tab title
#     faviconUrl: "..."         → HTTP-served path (not filesystem path)
#
# faviconUrl must be the URL path as seen by the browser:
#   Volume mount:  ${LOGIN_ASSETS_PATH}/favicons/favicon.svg  (filesystem)
#   Served at:     /ui/favicons/favicon.svg                   (HTTP path)
# ================================================================
info "Updating OSD config..."
OSD_CONFIG_FILE="${GENERATED_DIR}/opensearch_dashboards.yml"

# Strip all previously injected branding lines — makes re-runs idempotent
kubectl exec deploy/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -- cat "${OSD_CONFIG_PATH}" | \
  grep -v "^opensearch_security\.ui\.basicauth\.login\." | \
  grep -v "^# .*Login Page Branding" | \
  grep -v "^# .*Browser Tab Title" | \
  grep -v "^# .*Custom Branding" | \
  grep -v "^# .*NOTE:.*branding" | \
  grep -v "^opensearchDashboards\.defaultAppTitle" | \
  grep -v "^opensearchDashboards\.branding:" | \
  grep -v "^  applicationTitle:" | \
  grep -v "^  faviconUrl:" > "${OSD_CONFIG_FILE}"

cat >> "${OSD_CONFIG_FILE}" << EOF
# ======================== Custom Branding ========================
# opensearchDashboards.branding is the valid schema key for tab
# title and favicon in this Wazuh Dashboard version.
# Do NOT use opensearchDashboards.defaultAppTitle — it is not in
# the legacy Joi schema and will cause a fatal crash on startup.
opensearchDashboards.branding:
  applicationTitle: "${BRAND_TAB_TITLE}"
  faviconUrl: "${FAVICON_HTTP_PATH}"
# ======================== Login Page Branding ========================
opensearch_security.ui.basicauth.login.showbrandimage: true
opensearch_security.ui.basicauth.login.brandimage: "/plugins/wazuh/assets/custom/images/isiem-logo-app.svg"
opensearch_security.ui.basicauth.login.title: ""
opensearch_security.ui.basicauth.login.subtitle: ""
EOF

kubectl create configmap isiem-dashboard-osd-config \
  --from-file=opensearch_dashboards.yml="${OSD_CONFIG_FILE}" \
  -n "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
pass "isiem-dashboard-osd-config (tab: '${BRAND_TAB_TITLE}' | favicon: '${FAVICON_HTTP_PATH}')"

# ---- Wazuh app config ----
info "Creating wazuh.yaml..."
WAZUH_YAML_FILE="${GENERATED_DIR}/wazuh.yaml"
cat > "${WAZUH_YAML_FILE}" << EOF
---
# ${BRAND_NAME} Dashboard - Auto-generated from branding.conf
pattern: ${ALERTS_PATTERN}
checks.pattern: true
checks.template: true
checks.api: true
checks.setup: true
checks.fields: true
checks.metaFields: true
checks.maxBuckets: true
checks.timeFilter: true
extensions.pci: true
extensions.gdpr: true
extensions.hipaa: true
extensions.nist: true
extensions.tsc: true
extensions.audit: true
extensions.oscap: false
extensions.ciscat: false
extensions.aws: false
extensions.gcp: true
extensions.virustotal: false
extensions.osquery: false
extensions.docker: true
timeout: 20000
api.selector: true
ip.selector: true
ip.ignore: []
wazuh.monitoring.enabled: true
wazuh.monitoring.frequency: 900
wazuh.monitoring.shards: 1
wazuh.monitoring.replicas: 0
wazuh.monitoring.creation: w
wazuh.monitoring.pattern: ${MONITORING_PATTERN}
cron.prefix: ${PREFIX}
cron.statistics.status: true
cron.statistics.apis: []
cron.statistics.interval: 0 */5 * * * *
cron.statistics.index.name: statistics
cron.statistics.index.creation: w
cron.statistics.index.shards: 1
cron.statistics.index.replicas: 0
admin: true
hideManagerAlerts: false
logs.level: info
enrollment.dns: '${ENROLLMENT_DNS}'
alerts.sample.prefix: ${SAMPLE_ALERTS_PREFIX}
reports.csv.maxRows: 10000
wazuh.updates.disabled: false
customization.enabled: true
customization.logo.app: custom/images/isiem-logo-app.svg
customization.logo.healthcheck: custom/images/isiem-logo-healthcheck.svg
customization.logo.reports: custom/images/isiem-logo-reports.png
customization.logo.sidebar: custom/images/isiem-logo-sidebar.svg
customization.reports.header: '${REPORT_HEADER}'
customization.reports.footer: '${REPORT_FOOTER}'
hosts:
  - ${PREFIX}-api:
      url: https://${API_HOST}
      port: ${API_PORT}
      username: ${API_USERNAME}
      password: ${API_PASSWORD}
      run_as: false
EOF

kubectl create configmap isiem-dashboard-config \
  --from-file=wazuh.yaml="${WAZUH_YAML_FILE}" \
  -n "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
pass "isiem-dashboard-config"

# ---- Report branding: patch constants.js and printer.js via ConfigMaps ----
info "Extracting and patching report branding files..."

REPORT_CONSTANTS_FILE="${GENERATED_DIR}/constants.js"
REPORT_PRINTER_FILE="${GENERATED_DIR}/printer.js"

# Extract constants.js from current container
kubectl exec deploy/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -- \
  cat /usr/share/wazuh-dashboard/plugins/wazuh/common/constants.js > "${REPORT_CONSTANTS_FILE}"

# Patch constants.js: logo path, footer, email, URL
sed -i "s|'images/logo_reports.png'|'custom/images/isiem-logo-reports.png'|g" "${REPORT_CONSTANTS_FILE}"
sed -i "s|Copyright © Wazuh, Inc.|${REPORT_COPYRIGHT}|g" "${REPORT_CONSTANTS_FILE}"
sed -i "s|info@wazuh.com|${REPORT_EMAIL}|g; s|https://wazuh.com|${REPORT_URL}|g" "${REPORT_CONSTANTS_FILE}"

# Verify constants.js patch
if grep -q "${REPORT_EMAIL}" "${REPORT_CONSTANTS_FILE}" && \
   grep -q "${REPORT_COPYRIGHT}" "${REPORT_CONSTANTS_FILE}"; then
  pass "constants.js patched (email: ${REPORT_EMAIL}, copyright: ${REPORT_COPYRIGHT})"
else
  fail "constants.js patching FAILED — check generated file"
fi

# Extract printer.js from current container
kubectl exec deploy/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -- \
  cat /usr/share/wazuh-dashboard/plugins/wazuh/server/lib/reporting/printer.js > "${REPORT_PRINTER_FILE}"

# Patch printer.js: replace the getCustomizationSetting destructuring
# with hardcoded iSIEM values so reports bypass the buggy config system.
# Uses line-number-based head/tail approach (reliable across Wazuh versions).
LOGO_LINE=$(grep -n "'customization.logo.reports': pathToLogo" "${REPORT_PRINTER_FILE}" 2>/dev/null | head -1 | cut -d: -f1 || true)

if [[ -n "${LOGO_LINE}" ]]; then
  # const { is 1 line before the logo line, } = configuration; is 3 lines after
  BLOCK_START=$((LOGO_LINE - 1))
  BLOCK_END=$((LOGO_LINE + 3))

  head -$((BLOCK_START - 1)) "${REPORT_PRINTER_FILE}" > "${REPORT_PRINTER_FILE}.tmp"
  cat >> "${REPORT_PRINTER_FILE}.tmp" << JSPATCH
          const pathToLogo = 'custom/images/isiem-logo-reports.png';
          const pageHeader = '${REPORT_HEADER}';
          const pageFooter = '${REPORT_FOOTER}';
JSPATCH
  tail -n +$((BLOCK_END + 1)) "${REPORT_PRINTER_FILE}" >> "${REPORT_PRINTER_FILE}.tmp"
  mv "${REPORT_PRINTER_FILE}.tmp" "${REPORT_PRINTER_FILE}"
  info "Replaced destructuring block (lines ${BLOCK_START}-${BLOCK_END}) with hardcoded values"
else
  warn "Destructuring block not found — printer.js may already be patched or format changed"
fi

# Verify printer.js patch
if grep -q "${REPORT_HEADER}" "${REPORT_PRINTER_FILE}"; then
  pass "printer.js patched (hardcoded iSIEM report values)"
else
  fail "printer.js patching FAILED — check generated file at ${REPORT_PRINTER_FILE}"
fi

# Create ConfigMaps from patched files
kubectl create configmap isiem-patched-constants \
  --from-file=constants.js="${REPORT_CONSTANTS_FILE}" \
  -n "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
pass "isiem-patched-constants ConfigMap"

kubectl create configmap isiem-patched-printer \
  --from-file=printer.js="${REPORT_PRINTER_FILE}" \
  -n "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
pass "isiem-patched-printer ConfigMap"

# ---- Patch deployment ----
info "Patching deployment..."
kubectl patch deployment "${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" --type=strategic -p '
spec:
  template:
    spec:
      containers:
        - name: '"${DASHBOARD_CONTAINER}"'
          volumeMounts:
            - name: isiem-core-logos
              mountPath: '"${CORE_LOGOS_PATH}"'
              readOnly: true
            - name: isiem-login-branding
              mountPath: '"${LOGIN_ASSETS_PATH}"'/wazuh_logo.svg
              subPath: wazuh_logo.svg
              readOnly: true
            - name: isiem-login-branding
              mountPath: '"${LOGIN_ASSETS_PATH}"'/wazuh_login_bg.svg
              subPath: wazuh_login_bg.svg
              readOnly: true
            - name: isiem-dashboard-logos
              mountPath: '"${PLUGIN_ASSETS_PATH}"'/custom/images
              readOnly: true
            - name: isiem-favicon
              mountPath: '"${LOGIN_ASSETS_PATH}"'/favicons/favicon.svg
              subPath: favicon.svg
              readOnly: true
            - name: isiem-dashboard-config
              mountPath: '"${WAZUH_CONFIG_PATH}"'
              subPath: wazuh.yaml
              readOnly: true
            - name: isiem-dashboard-osd-config
              mountPath: '"${OSD_CONFIG_PATH}"'
              subPath: opensearch_dashboards.yml
              readOnly: true
            - name: isiem-patched-constants
              mountPath: /usr/share/wazuh-dashboard/plugins/wazuh/common/constants.js
              subPath: constants.js
              readOnly: true
            - name: isiem-patched-printer
              mountPath: /usr/share/wazuh-dashboard/plugins/wazuh/server/lib/reporting/printer.js
              subPath: printer.js
              readOnly: true
            - name: isiem-theme-logos
              mountPath: '"${PLUGIN_ASSETS_PATH}"'/images/themes/light/logo.svg
              subPath: logo.svg
              readOnly: true
            - name: isiem-theme-logos-dark
              mountPath: '"${PLUGIN_ASSETS_PATH}"'/images/themes/dark/logo.svg
              subPath: logo.svg
              readOnly: true
      volumes:
        - name: isiem-core-logos
          configMap:
            name: isiem-core-logos
        - name: isiem-login-branding
          configMap:
            name: isiem-login-branding
        - name: isiem-dashboard-logos
          configMap:
            name: isiem-dashboard-logos
        - name: isiem-dashboard-config
          configMap:
            name: isiem-dashboard-config
        - name: isiem-dashboard-osd-config
          configMap:
            name: isiem-dashboard-osd-config
        - name: isiem-theme-logos
          configMap:
            name: isiem-theme-logos
        - name: isiem-theme-logos-dark
          configMap:
            name: isiem-theme-logos-dark
        - name: isiem-favicon
          configMap:
            name: isiem-favicon
        - name: isiem-patched-constants
          configMap:
            name: isiem-patched-constants
        - name: isiem-patched-printer
          configMap:
            name: isiem-patched-printer
'
pass "Deployment patched"

# ---- Restart ----
info "Rolling restart..."
kubectl rollout restart deployment/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}"
if kubectl rollout status deployment/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" --timeout=180s; then
  pass "Rollout completed"
else
  fail "Rollout timed out — check: kubectl get pods -n ${NAMESPACE}"
  warn "Rollback: kubectl rollout undo deploy/${DASHBOARD_DEPLOY} -n ${NAMESPACE}"
  exit 1
fi

# ================================================================
#  PHASE 4: POST-VERIFICATION
# ================================================================
header "PHASE 4 / 6 — POST-VERIFICATION"

POST_ERRORS=0
post_pass() { echo -e "${PASS} $1"; }
post_fail() { echo -e "${FAIL} $1"; POST_ERRORS=$((POST_ERRORS + 1)); }

# 4.1 — Pod health
echo ""
echo -e "${BOLD}4.1 Pod health${NC}"
NR=$(kubectl get deploy "${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -o jsonpath='{.status.readyReplicas}' 2>/dev/null)
ND=$(kubectl get deploy "${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -o jsonpath='{.spec.replicas}' 2>/dev/null)
[[ "${NR}" == "${ND}" ]] && [[ "${NR}" -gt 0 ]] && post_pass "Running (${NR}/${ND})" || post_fail "Not healthy (${NR:-0}/${ND:-?})"

# 4.2 — ConfigMaps
echo ""
echo -e "${BOLD}4.2 ConfigMaps${NC}"
for cm in "${BRANDING_CMS[@]}"; do
  kubectl get configmap "${cm}" -n "${NAMESPACE}" &>/dev/null && post_pass "  ${cm}" || post_fail "  ${cm} — MISSING"
done

# 4.3 — OSD config integrity
echo ""
echo -e "${BOLD}4.3 OSD config integrity${NC}"
NEW_OSD=$(kubectl exec deploy/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -- cat "${OSD_CONFIG_PATH}" 2>/dev/null || echo "")
if [[ -n "${NEW_OSD}" ]]; then
  for key in "${CRITICAL_KEYS[@]}"; do
    echo "${NEW_OSD}" | grep -q "^${key}:" && post_pass "  ${key}" || post_fail "  ${key} — MISSING!"
  done
  # Verify correct branding block is present
  echo "${NEW_OSD}" | grep -q "^opensearchDashboards\.branding:" \
    && post_pass "  opensearchDashboards.branding block present" \
    || post_fail "  opensearchDashboards.branding — MISSING"
  echo "${NEW_OSD}" | grep -q "applicationTitle:" \
    && post_pass "  applicationTitle set → tab title: '${BRAND_TAB_TITLE}'" \
    || post_fail "  applicationTitle — MISSING (tab title will not change)"
  echo "${NEW_OSD}" | grep -q "faviconUrl:" \
    && post_pass "  faviconUrl set → ${FAVICON_HTTP_PATH}" \
    || post_fail "  faviconUrl — MISSING (favicon will not change)"
  # Poison key guard — if this key is present the pod WILL crash
  if echo "${NEW_OSD}" | grep -q "^opensearchDashboards\.defaultAppTitle"; then
    post_fail "  DANGER: opensearchDashboards.defaultAppTitle still present — pod will crash!"
  else
    post_pass "  Poison key absent (opensearchDashboards.defaultAppTitle not present — safe)"
  fi
  echo "${NEW_OSD}" | grep -q "opensearch_security.ui.basicauth.login.showbrandimage" \
    && post_pass "  Login branding added" || post_fail "  Login branding NOT added"
else
  post_fail "Cannot read OSD config"
fi

# 4.4 — Certificate integrity
echo ""
echo -e "${BOLD}4.4 Certificates${NC}"
while IFS=: read -r fname old_cksum; do
  [[ -z "${fname}" ]] && continue
  new_cksum=$(kubectl exec deploy/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -- md5sum "${CERTS_PATH}/${fname}" 2>/dev/null | awk '{print $1}' || echo "n/a")
  if [[ "${old_cksum}" == "${new_cksum}" ]]; then
    post_pass "  ${fname} — unchanged"
  elif [[ "${new_cksum}" == "n/a" ]]; then
    post_fail "  ${fname} — MISSING!"
  else
    post_fail "  ${fname} — CHANGED!"
  fi
done < "${BACKUP_DIR}/cert-checksums.txt"

# 4.5 — HTTP
echo ""
echo -e "${BOLD}4.5 Dashboard HTTP${NC}"
HTTP_CODE=$(kubectl exec deploy/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -- \
  curl -sk -o /dev/null -w "%{http_code}" "https://localhost:5601/app/login" 2>/dev/null || echo "000")
if [[ "${HTTP_CODE}" == "200" ]] || [[ "${HTTP_CODE}" == "302" ]]; then
  post_pass "HTTP ${HTTP_CODE}"
else
  info "HTTP ${HTTP_CODE} — retrying in 15s..."
  sleep 15
  HTTP_CODE=$(kubectl exec deploy/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -- \
    curl -sk -o /dev/null -w "%{http_code}" "https://localhost:5601/app/login" 2>/dev/null || echo "000")
  [[ "${HTTP_CODE}" == "200" ]] || [[ "${HTTP_CODE}" == "302" ]] \
    && post_pass "HTTP ${HTTP_CODE} (after retry)" || post_fail "HTTP ${HTTP_CODE}"
fi

# 4.6 — Branding files
echo ""
echo -e "${BOLD}4.6 Branding files in pod${NC}"
MOUNT_CHECKS=(
  "${CORE_LOGOS_PATH}/wazuh.svg"
  "${LOGIN_ASSETS_PATH}/wazuh_logo.svg"
  "${LOGIN_ASSETS_PATH}/wazuh_login_bg.svg"
  "${LOGIN_ASSETS_PATH}/favicons/favicon.svg"
  "${PLUGIN_ASSETS_PATH}/custom/images/isiem-logo-app.svg"
  "${PLUGIN_ASSETS_PATH}/images/themes/light/logo.svg"
  "${PLUGIN_ASSETS_PATH}/images/themes/dark/logo.svg"
)
for fpath in "${MOUNT_CHECKS[@]}"; do
  kubectl exec deploy/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -- test -f "${fpath}" 2>/dev/null \
    && post_pass "  $(basename "${fpath}")" || post_fail "  $(basename "${fpath}") — NOT found"
done

# 4.7 — Favicon HTTP reachable
echo ""
echo -e "${BOLD}4.7 Favicon HTTP check${NC}"
FAV_CODE=$(kubectl exec deploy/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -- \
  curl -sk -o /dev/null -w "%{http_code}" "https://localhost:5601${FAVICON_HTTP_PATH}" 2>/dev/null || echo "000")
if [[ "${FAV_CODE}" == "200" ]]; then
  post_pass "Favicon HTTP 200 at ${FAVICON_HTTP_PATH}"
else
  post_fail "Favicon not reachable at ${FAVICON_HTTP_PATH} (HTTP ${FAV_CODE})"
fi

# 4.8 — Report branding
echo ""
echo -e "${BOLD}4.8 Report branding${NC}"
REPORT_CONST=$(kubectl exec deploy/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -- \
  cat /usr/share/wazuh-dashboard/plugins/wazuh/common/constants.js 2>/dev/null || echo "")
if [[ -n "${REPORT_CONST}" ]]; then
  echo "${REPORT_CONST}" | grep -q "${REPORT_EMAIL}" \
    && post_pass "  Report header email: ${REPORT_EMAIL}" \
    || post_fail "  Report header email NOT patched"
  echo "${REPORT_CONST}" | grep -q "${REPORT_COPYRIGHT}" \
    && post_pass "  Report footer: ${REPORT_COPYRIGHT}" \
    || post_fail "  Report footer NOT patched"
  echo "${REPORT_CONST}" | grep -q "custom/images/isiem-logo-reports.png" \
    && post_pass "  Report logo path: custom/images/isiem-logo-reports.png" \
    || post_fail "  Report logo path NOT patched"
else
  post_fail "  Cannot read constants.js from pod"
fi

REPORT_PRINTER=$(kubectl exec deploy/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" -- \
  grep -c "${REPORT_HEADER}" /usr/share/wazuh-dashboard/plugins/wazuh/server/lib/reporting/printer.js 2>/dev/null || echo "0")
if [[ "${REPORT_PRINTER}" -gt 0 ]]; then
  post_pass "  printer.js: hardcoded iSIEM report values"
else
  post_fail "  printer.js: iSIEM values NOT found (report may show Wazuh defaults)"
fi

# ---- Verdict ----
echo ""
echo -e "${BOLD}─────────────────────────────────────────────────────────${NC}"
if [[ ${POST_ERRORS} -gt 0 ]]; then
  echo -e "${RED}${BOLD}  POST-VERIFY: ${POST_ERRORS} issue(s)${NC}"
else
  echo -e "${GREEN}${BOLD}  POST-VERIFY: All PASSED${NC}"
fi
echo -e "${BOLD}─────────────────────────────────────────────────────────${NC}"

# ================================================================
#  PHASE 5: KEEP OR ROLLBACK
# ================================================================
header "PHASE 5 / 6 — KEEP OR ROLLBACK"

echo ""
echo -e "  Brand:      ${BOLD}${BRAND_NAME}${NC}"
echo -e "  Tab title:  ${BRAND_TAB_TITLE}"
echo -e "  Favicon:    ${FAVICON_HTTP_PATH}"
echo -e "  Namespace:  ${NAMESPACE}"
echo -e "  Deployment: ${DASHBOARD_DEPLOY}"
echo -e "  ConfigMaps: ${#BRANDING_CMS[@]}"
echo -e "  Errors:     ${POST_ERRORS}"
echo -e "  Backup:     ${BACKUP_DIR}"
echo ""
[[ ${POST_ERRORS} -gt 0 ]] && echo -e "${RED}  ⚠  Issues detected — rollback recommended.${NC}" && echo ""

echo -e "  ${GREEN}keep${NC}     — Keep branding"
echo -e "  ${RED}rollback${NC} — Undo everything"
echo ""
read -rp "$(echo -e "${CYAN}  Choice (keep/rollback): ${NC}")" CHOICE

case "${CHOICE}" in
  keep)
    echo ""
    echo -e "${GREEN}${BOLD}  ✓ ${BRAND_NAME} branding KEPT${NC}"
    echo ""
    echo "    [✓] Login page logo + background"
    echo "    [✓] Core UI logos (16 files)"
    echo "    [✓] Plugin app/sidebar/healthcheck"
    echo "    [✓] Health check page (light + dark)"
    echo "    [✓] Loading spinners"
    echo "    [✓] Tab title: ${BRAND_TAB_TITLE}"
    echo "    [✓] Favicon: ${FAVICON_HTTP_PATH}"
    echo "    [✓] OSD login branding config"
    echo "    [✓] App config (${ALERTS_PATTERN})"
    echo "    [✓] Report header: ${REPORT_EMAIL}"
    echo "    [✓] Report footer: ${REPORT_COPYRIGHT}"
    echo "    [✓] Report logo: custom/images/isiem-logo-reports.png"
    echo "    [✓] printer.js: hardcoded iSIEM values"
    echo ""
    echo -e "  ${BOLD}Hard refresh your browser: Ctrl+Shift+R${NC}"
    ;;
  rollback)
    echo ""
    info "Rolling back deployment..."
    kubectl rollout undo deployment/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}"
    kubectl rollout status deployment/"${DASHBOARD_DEPLOY}" -n "${NAMESPACE}" --timeout=120s
    info "Deleting branding ConfigMaps..."
    for cm in "${BRANDING_CMS[@]}"; do
      kubectl delete configmap "${cm}" -n "${NAMESPACE}" --ignore-not-found=true 2>/dev/null
    done
    echo ""
    echo -e "${YELLOW}${BOLD}  ✓ Rollback complete${NC}"
    echo "    Backup: ${BACKUP_DIR}"
    ;;
  *)
    warn "Invalid choice. No action taken."
    echo "  Rollback later: kubectl rollout undo deploy/${DASHBOARD_DEPLOY} -n ${NAMESPACE}"
    ;;
esac

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  ${BRAND_NAME} Branding Script — Complete${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
