#!/usr/bin/env python3
# =============================================================================
# Wazuh → Mattermost Integration
# Triggers: severity >= 12 (HIGH) and < 16 (below critical, which goes to GitLab)
# Deploy path (inside manager pod): /var/ossec/integrations/custom-mattermost.py
# =============================================================================

import sys
import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ── Logging ──────────────────────────────────────────────────────────────────
LOG_FILE = "/var/ossec/logs/integrations.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [custom-mattermost] %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# ── Mattermost configuration – edit these ────────────────────────────────────
MATTERMOST_WEBHOOK_URL = "https://mattermost.example.in/hooks/j6cdtkp8mp818rgim8c69jp6yr"
MATTERMOST_CHANNEL    = "isiem-alerts"      # override channel (optional, "" = webhook default)
MATTERMOST_USERNAME   = "isiem-alerts"
MATTERMOST_ICON_URL   = "https://wazuh.com/brand-resources/Isotipo_Wazuh_Color.png"

SEVERITY_MIN = 7     # alert if level >= this
SEVERITY_MAX = 99     # no upper cap for mattermost (critical also notifies here if desired)
                      # set SEVERITY_MAX = 15 to only send HIGH (not CRITICAL) to Mattermost

# Colour sidebar per severity band
COLOUR_MAP = {
    (12, 13): "#FFC107",   # amber  – high
    (14, 15): "#FF5722",   # deep orange
    (16, 99): "#D32F2F",   # red – critical (if you want both channels)
}


def get_colour(level: int) -> str:
    for (lo, hi), colour in COLOUR_MAP.items():
        if lo <= level <= hi:
            return colour
    return "#D32F2F"


def get_severity_label(level: int) -> str:
    if level >= 16:
        return "🔴 CRITICAL"
    if level >= 12:
        return "🟠 HIGH"
    return "🟡 MEDIUM"


def build_attachment(alert: dict) -> dict:
    rule      = alert.get("rule", {})
    agent     = alert.get("agent", {})
    timestamp = alert.get("timestamp", datetime.now(timezone.utc).isoformat())
    level     = int(rule.get("level", 0))

    mitre_ids = rule.get("mitre", {}).get("id", [])
    mitre_str = ", ".join(mitre_ids) if mitre_ids else "N/A"
    groups    = ", ".join(rule.get("groups", [])) or "N/A"

    fields = [
        {"short": True,  "title": "Severity Level", "value": f"`{level}` — {get_severity_label(level)}"},
        {"short": True,  "title": "Rule ID",         "value": f"`{rule.get('id', 'N/A')}`"},
        {"short": True,  "title": "Agent Name",      "value": agent.get("name", "N/A")},
        {"short": True,  "title": "Agent IP",        "value": agent.get("ip", "N/A")},
        {"short": True,  "title": "Groups",          "value": groups},
        {"short": True,  "title": "MITRE ATT&CK",    "value": mitre_str},
        {"short": False, "title": "Description",     "value": rule.get("description", "N/A")},
    ]

    # Include a snippet of the raw data if present
    raw_data = alert.get("data", {})
    if raw_data:
        snippet = json.dumps(raw_data, indent=2)[:800]   # cap at 800 chars
        fields.append({"short": False, "title": "Raw Data (truncated)", "value": f"```\n{snippet}\n```"})

    return {
        "fallback":    f"[{get_severity_label(level)}] {rule.get('description', 'Alert')} on {agent.get('name', '?')}",
        "color":       get_colour(level),
        "title":       f"Wazuh Alert — {rule.get('description', 'Security Event')}",
        "title_link":  "",                  # optionally link to Wazuh dashboard
        "text":        f"**Agent:** {agent.get('name', 'N/A')}  |  **Time:** {timestamp}",
        "fields":      fields,
        "footer":      "Wazuh SIEM",
        "footer_icon": MATTERMOST_ICON_URL,
        "ts":          int(datetime.now(timezone.utc).timestamp()),
    }


def send_mattermost(alert: dict):
    rule  = alert.get("rule", {})
    level = int(rule.get("level", 0))

    if level < SEVERITY_MIN or level > SEVERITY_MAX:
        logger.info("Alert level %d outside range [%d-%d] — skipped", level, SEVERITY_MIN, SEVERITY_MAX)
        return

    attachment = build_attachment(alert)
    payload: dict = {
        "username":    MATTERMOST_USERNAME,
        "icon_url":    MATTERMOST_ICON_URL,
        "attachments": [attachment],
    }
    if MATTERMOST_CHANNEL:
        payload["channel"] = MATTERMOST_CHANNEL

    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        MATTERMOST_WEBHOOK_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            logger.info("Mattermost response: %s", resp.read().decode())
    except urllib.error.HTTPError as exc:
        logger.error("Mattermost HTTP %s: %s", exc.code, exc.read().decode())
        sys.exit(1)
    except Exception as exc:
        logger.error("Mattermost request failed: %s", exc)
        sys.exit(1)


# ── Entry-point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        logger.error("Usage: custom-mattermost.py <alert_json_file>")
        sys.exit(1)

    alert_file = sys.argv[1]
    try:
        with open(alert_file, "r") as fh:
            alert_data = json.load(fh)
    except Exception as exc:
        logger.error("Cannot read alert file %s: %s", alert_file, exc)
        sys.exit(1)

    logger.info("Processing alert id=%s level=%s",
                alert_data.get("id"), alert_data.get("rule", {}).get("level"))
    send_mattermost(alert_data)
