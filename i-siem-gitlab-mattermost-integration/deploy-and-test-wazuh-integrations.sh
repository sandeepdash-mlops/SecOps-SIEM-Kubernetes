#!/usr/bin/env bash
# =============================================================================
# deploy-and-test-wazuh-integrations.sh
#
# Deploys custom-gitlab.py and custom-mattermost.py into the Wazuh manager
# master pod, then fires synthetic test alerts to validate both integrations.
#
# Usage:
#   chmod +x deploy-and-test-wazuh-integrations.sh
#   ./deploy-and-test-wazuh-integrations.sh
#
# Prerequisites: kubectl configured and pointed at your cluster,
#                script files in the same directory.
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
NAMESPACE="isiem"
MANAGER_POD="isiem-manager-master-0"
INTEGRATION_DIR="/var/ossec/integrations"
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colours for output
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()     { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Helpers ───────────────────────────────────────────────────────────────────
kexec() {
  kubectl exec -n "$NAMESPACE" "$MANAGER_POD" -- bash -c "$*"
}

kcopy() {   # src_local  dest_in_pod
  kubectl cp "$1" "${NAMESPACE}/${MANAGER_POD}:$2"
}

# ── 1. Verify pod is running ──────────────────────────────────────────────────
info "Checking Wazuh manager pod …"
kubectl get pod "$MANAGER_POD" -n "$NAMESPACE" -o jsonpath='{.status.phase}' \
  | grep -q Running || err "Pod $MANAGER_POD is not Running"
info "Pod is Running ✔"

# ── 2. Copy integration scripts ───────────────────────────────────────────────
info "Copying integration scripts to pod …"
for script in custom-gitlab.py custom-mattermost.py; do
  [[ -f "${SCRIPTS_DIR}/${script}" ]] || err "Missing script: ${SCRIPTS_DIR}/${script}"
  kcopy "${SCRIPTS_DIR}/${script}" "${INTEGRATION_DIR}/${script}"
  kexec "chmod 750 ${INTEGRATION_DIR}/${script} && chown root:wazuh ${INTEGRATION_DIR}/${script}"
  info "  ✔ ${script}"
done

# ── 3. Patch ossec.conf ───────────────────────────────────────────────────────
info "Patching ossec.conf with integration stanzas …"
kexec "
  # Idempotent – only add if not already present
  grep -q 'custom-gitlab' /var/ossec/etc/ossec.conf && {
    echo 'custom-gitlab block already present – skipping patch'
    exit 0
  }

  # Insert before closing </ossec_config>
  sed -i 's|</ossec_config>|
  <!-- GitLab: CRITICAL level > 15 -->
  <integration>
    <n>custom-gitlab</n>
    <level>7</level>
    <alert_format>json</alert_format>
  </integration>

  <!-- Mattermost: HIGH level 12-15 -->
  <integration>
    <n>custom-mattermost</n>
    <level>7</level>
    <max_level>17</max_level>
    <alert_format>json</alert_format>
  </integration>

</ossec_config>|' /var/ossec/etc/ossec.conf
  echo 'ossec.conf patched'
"

# ── 4. Restart Wazuh manager ──────────────────────────────────────────────────
info "Restarting Wazuh manager …"
kexec "/var/ossec/bin/wazuh-control restart" || warn "Restart returned non-zero – check logs"
sleep 5
info "Manager restarted ✔"

# ── 5. Generate synthetic test alerts ────────────────────────────────────────
info "Injecting synthetic test alerts …"

# Build a minimal valid alert JSON
make_alert() {
  local id="$1" level="$2" rule_id="$3" desc="$4"
  cat <<EOF
{
  "id": "${id}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)",
  "rule": {
    "id": "${rule_id}",
    "level": ${level},
    "description": "${desc}",
    "groups": ["test", "wazuh"],
    "mitre": { "id": ["T1059"] }
  },
  "agent": {
    "id": "001",
    "name": "test-agent",
    "ip": "192.168.1.10"
  },
  "manager": { "name": "${MANAGER_POD}" },
  "data": {
    "srcip": "198.51.100.42",
    "dstport": "22",
    "extra": "synthetic test alert – safe to close"
  },
  "location": "synthetic"
}
EOF
}

# Write test payloads into the pod and call scripts directly
# ---- CRITICAL (level 17) → should create GitLab issue ----
info "  → Testing GitLab integration (level 17) …"
kexec "
  cat > /tmp/test_critical.json << 'ENDJSON'
$(make_alert "test-critical-001" 17 "100001" "TEST: Critical brute-force detected")
ENDJSON
  python3 ${INTEGRATION_DIR}/custom-gitlab.py /tmp/test_critical.json
  echo 'custom-gitlab.py exited: '$?
"

# ---- HIGH (level 13) → should send Mattermost message ----
info "  → Testing Mattermost integration (level 13) …"
kexec "
  cat > /tmp/test_high.json << 'ENDJSON'
$(make_alert "test-high-001" 13 "100002" "TEST: Suspicious privilege escalation attempt")
ENDJSON
  python3 ${INTEGRATION_DIR}/custom-mattermost.py /tmp/test_high.json
  echo 'custom-mattermost.py exited: '$?
"

# ── 6. Check integration log ──────────────────────────────────────────────────
info "Integration log (last 30 lines) …"
echo "────────────────────────────────────────────────────────"
kexec "tail -30 /var/ossec/logs/integrations.log 2>/dev/null || echo '(log file not yet created)'"
echo "────────────────────────────────────────────────────────"

info "Done! Check:"
echo "  • GitLab project issues for a new CRITICAL ticket"
echo "  • Mattermost #${MATTERMOST_CHANNEL:-security-alerts} channel for the HIGH alert card"
echo "  • Pod log: kubectl exec -n ${NAMESPACE} ${MANAGER_POD} -- tail -f /var/ossec/logs/integrations.log"
