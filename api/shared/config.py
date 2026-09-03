"""
Central configuration.

STRICT RULE honoured here:
  * No PII, tenant IDs, hostnames or secrets in code.
  * Everything tunable lives in App Settings (environment variables,
    ideally Key Vault references) or in the runtime config blob
    (config/portal-config.json in the storage account), so behaviour
    changes never require a code change.
"""
import json
import os
from functools import lru_cache

def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)

def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default

def env_bool(name: str, default: bool = False) -> bool:
    return str(os.environ.get(name, str(default))).strip().lower() in ("1", "true", "yes", "on")

def env_list(name: str, default: str = "") -> list[str]:
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


# ----- storage -------------------------------------------------------------
STORAGE_CONNECTION = lambda: env("STORAGE_CONNECTION_STRING")          # or use managed identity:
STORAGE_ACCOUNT_URL = lambda: env("STORAGE_ACCOUNT_URL")               # https://<acct>.blob.core.windows.net
IOC_CONTAINER       = lambda: env("IOC_CONTAINER", "iocstore")
IOC_BLOB            = lambda: env("IOC_BLOB", "iocs.csv")
ADVISORY_CONTAINER  = lambda: env("ADVISORY_CONTAINER", "advisories")
CONFIG_CONTAINER    = lambda: env("CONFIG_CONTAINER", "config")
CONFIG_BLOB         = lambda: env("CONFIG_BLOB", "portal-config.json")
INTERNAL_ASSETS_BLOB = lambda: env("INTERNAL_ASSETS_BLOB", "internal-assets.json")
# Two CSV blobs, each one column pair: location_name, ip_range (CIDR or a
# bare IP). Any submitted IP falling inside a listed range is blocked by
# the internal-asset guard, same as the JSON-defined cidrs list — these
# are just a second, CSV-editable source feeding the same check.
NAMED_LOCATIONS_BLOB = lambda: env("NAMED_LOCATIONS_BLOB", "named-locations.csv")
ZIA_LOCATIONS_BLOB   = lambda: env("ZIA_LOCATIONS_BLOB", "zia-locations.csv")
STATE_BLOB          = lambda: env("STATE_BLOB", "teams-poll-state.json")
CA_STATE_BLOB       = lambda: env("CA_STATE_BLOB", "ca-watch-state.json")

# ----- roles (group-based permissions) -------------------------------------
# ROLE_GROUP_MAP example: "ioc-admin=<groupObjectId>;ioc-operator=<groupObjectId>"
# (Set on the App Service, not here — this Function App only receives the
#  resolved role names via the x-portal-roles header from the proxy.)
def role_group_map() -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in env("ROLE_GROUP_MAP").split(";"):
        if "=" in pair:
            role, gid = pair.split("=", 1)
            out[role.strip()] = gid.strip()
    return out

# Admin notification webhook (secret URL from Key Vault) — e.g. a Logic App
# HTTP trigger that emails the admin group. CA watch cadence is the
# CA_WATCH_CRON app setting used directly by the timer trigger.
WEBHOOK_URL = lambda: env("WEBHOOK_URL")

# ----- Microsoft Graph (roles lookup + Teams channel) ----------------------
GRAPH_TENANT_ID     = lambda: env("GRAPH_TENANT_ID")
GRAPH_CLIENT_ID     = lambda: env("GRAPH_CLIENT_ID")
GRAPH_CLIENT_SECRET = lambda: env("GRAPH_CLIENT_SECRET")
TEAMS_TEAM_ID       = lambda: env("TEAMS_TEAM_ID")
TEAMS_CHANNEL_ID    = lambda: env("TEAMS_CHANNEL_ID")
TEAMS_FETCH_TOP     = lambda: env_int("TEAMS_FETCH_TOP", 30)
ADVISORY_RETENTION_DAYS = lambda: env_int("ADVISORY_RETENTION_DAYS", 60)
# Poll cadence is an app setting used directly by the timer trigger:
#   TEAMS_POLL_CRON, e.g. "0 */5 * * * *"  (every 5 minutes)

# ----- extraction ----------------------------------------------------------
EXTRACT_FETCH_LINKS   = lambda: env_bool("EXTRACT_FETCH_LINKS", False)
EXTRACT_LINK_ALLOWLIST = lambda: env_list("EXTRACT_LINK_ALLOWLIST")     # domains allowed for link fetching
EXTRACT_MAX_BYTES     = lambda: env_int("EXTRACT_MAX_BYTES", 2_000_000)
# Extra benign/vendor domains to ignore during extraction (extends built-in defaults)
EXTRACT_NOISE_DOMAINS = lambda: env_list("EXTRACT_NOISE_DOMAINS")

# ----- portal connectors ---------------------------------------------------
CROWDSTRIKE_ENABLED   = lambda: env_bool("CROWDSTRIKE_ENABLED", True)
FALCON_BASE_URL       = lambda: env("FALCON_BASE_URL", "https://api.crowdstrike.com")
FALCON_CLIENT_ID      = lambda: env("FALCON_CLIENT_ID")
FALCON_CLIENT_SECRET  = lambda: env("FALCON_CLIENT_SECRET")
# FALCON_ACTION         = lambda: env("FALCON_ACTION", "detect")          # non-hash types
# FALCON_ACTION_HASH    = lambda: env("FALCON_ACTION_HASH", "prevent")    # md5/sha256
# CrowdStrike's Custom IOC API does not support the same action set for
# every indicator type — confirmed by testing (a "prevent" submission for
# an IP returned HTTP 400). IP and domain indicators only support "detect"
# at the platform level; only hash indicators (md5/sha256) can be blocked.
# So the action is type-conditional, not a single flat choice:
#   ip / domain -> always "detect", no analyst choice, no dropdown shown
#   hash        -> analyst picks one of three real Falcon action values
# Hash options are still env-list driven so the offered set can change
# without a code deploy, but the DEFAULT set matches Falcon's actual
# supported hash actions — do not add ip/domain-only values here.
FALCON_HASH_ACTION_VALUES = lambda: env_list(
    "FALCON_HASH_ACTION_VALUES", "prevent,detect,prevent_no_ui")
FALCON_NON_HASH_ACTION    = lambda: env("FALCON_NON_HASH_ACTION", "detect")
FALCON_PLATFORMS      = lambda: env_list("FALCON_PLATFORMS", "windows,mac,linux")
FALCON_SEVERITY       = lambda: env("FALCON_SEVERITY", "high")

SENTINEL_ENABLED      = lambda: env_bool("SENTINEL_ENABLED", True)
# Management-API createIndicator flow (managed identity), matching the proven
# runbook: /subscriptions/.../workspaces/<ws> is the ONLY org-specific value.
SENTINEL_WORKSPACE_RESOURCE_ID = lambda: env("SENTINEL_WORKSPACE_RESOURCE_ID")
SENTINEL_API_VERSION  = lambda: env("SENTINEL_API_VERSION", "2025-03-01")
SENTINEL_SCOPE        = lambda: env("SENTINEL_SCOPE", "https://management.azure.com/.default")
SENTINEL_SOURCE       = lambda: env("SENTINEL_SOURCE", "IOC Distribution Portal")
SENTINEL_CONFIDENCE   = lambda: env_int("SENTINEL_CONFIDENCE", 80)
SENTINEL_THREAT_TYPES = lambda: env_list("SENTINEL_THREAT_TYPES", "malicious-activity")

PROOFPOINT_ENABLED    = lambda: env_bool("PROOFPOINT_ENABLED", True)
# Threat Protection orgBlockList flow (matches the proven runbook):
PROOFPOINT_TOKEN_URL  = lambda: env("PROOFPOINT_TOKEN_URL", "https://auth.proofpoint.com/v1/token")
PROOFPOINT_API_BASE   = lambda: env("PROOFPOINT_API_BASE", "https://threatprotection-api.proofpoint.com")
PROOFPOINT_CLUSTER_ID = lambda: env("PROOFPOINT_CLUSTER_ID")            # e.g. <org>_hosted
PROOFPOINT_CLIENT_ID  = lambda: env("PROOFPOINT_CLIENT_ID")             # Key Vault reference
PROOFPOINT_CLIENT_SECRET = lambda: env("PROOFPOINT_CLIENT_SECRET")      # Key Vault reference
PROOFPOINT_TYPES      = lambda: env_list("PROOFPOINT_TYPES", "email,domain,ip")
PROOFPOINT_DELETE_ACTION = lambda: env("PROOFPOINT_DELETE_ACTION")
PROOFPOINT_EMAIL_LIST_ID = lambda: env("PROOFPOINT_EMAIL_LIST_ID")
PROOFPOINT_IP_LIST_ID    = lambda: env("PROOFPOINT_IP_LIST_ID")

ZSCALER_ENABLED       = lambda: env_bool("ZSCALER_ENABLED", True)
ZSCALER_BASE_URL      = lambda: env("ZSCALER_BASE_URL")                 # e.g. https://zsapi.<cloud>.net/api/v1
ZSCALER_USERNAME      = lambda: env("ZSCALER_USERNAME")
ZSCALER_PASSWORD      = lambda: env("ZSCALER_PASSWORD")
ZSCALER_API_KEY       = lambda: env("ZSCALER_API_KEY")
ZSCALER_LIST_PATH     = lambda: env("ZSCALER_LIST_PATH", "/cyberThreatProtection/maliciousUrls")
ZSCALER_ACTIVATE      = lambda: env_bool("ZSCALER_ACTIVATE", True)
ZSCALER_TYPES         = lambda: env_list("ZSCALER_TYPES", "url,domain,ip")
ZSCALER_BLOCKLIST_PATH = lambda: env("ZSCALER_BLOCKLIST_PATH", "/cyberThreatProtection/maliciousUrls")
ZSCALER_LIST_FIELD    = lambda: env("ZSCALER_LIST_FIELD", "maliciousUrls")

IOC_EXPIRATION_DAYS   = lambda: env_int("IOC_EXPIRATION_DAYS", 90)      # applied where platforms support expiry
FALCON_TYPES          = lambda: env_list("FALCON_TYPES", "hash,ip,domain")
SENTINEL_TYPES        = lambda: env_list("SENTINEL_TYPES", "ip,domain,hash,url,email")
HTTP_TIMEOUT          = lambda: env_int("HTTP_TIMEOUT_SECONDS", 30)

# ----- submission notifications -------------------------------------------
# Off by default: set NOTIFY_ON_SUBMIT=true, SOC_NOTIFY_EMAILS, and exactly
# ONE of EMAIL_USING_WEBHOOK / EMAIL_USING_GRAPH to enable.
NOTIFY_ON_SUBMIT      = lambda: env_bool("NOTIFY_ON_SUBMIT", False)
SOC_NOTIFY_EMAILS     = lambda: env_list("SOC_NOTIFY_EMAILS")

# Email delivery provider — exactly ONE of these two must be true. Neither
# provider is assumed by default: both flags default to False so a blank
# environment fails validation loudly instead of silently picking one.
#   EMAIL_USING_WEBHOOK=true   -> POST to EMAIL_WEBHOOK_URL (e.g. a Logic App)
#   EMAIL_USING_GRAPH=true     -> send directly via Microsoft Graph sendMail
EMAIL_USING_WEBHOOK   = lambda: env_bool("EMAIL_USING_WEBHOOK", False)
EMAIL_USING_GRAPH     = lambda: env_bool("EMAIL_USING_GRAPH", False)
EMAIL_WEBHOOK_URL     = lambda: env("EMAIL_WEBHOOK_URL")


# Email subject — shared by BOTH providers, read from config, never
# hard-coded. Validated as present and non-empty by validate_email_config().
EMAIL_SUBJECT         = lambda: env("EMAIL_SUBJECT")


def validate_email_config() -> None:
    """Fail fast and loudly on a genuinely broken email configuration,
    rather than silently sending nothing (webhook/Graph both false) or
    silently picking one (both true) — either is a real misconfiguration
    that should surface at startup, not as a quietly-missing notification
    days later. Only runs its checks if email notifications are actually
    enabled (NOTIFY_ON_SUBMIT) — an app that never sends email doesn't need
    a provider configured at all."""
    if not NOTIFY_ON_SUBMIT():
        return
    using_webhook, using_graph = EMAIL_USING_WEBHOOK(), EMAIL_USING_GRAPH()
    if using_webhook and using_graph:
        raise RuntimeError(
            "Invalid email configuration: EMAIL_USING_WEBHOOK and EMAIL_USING_GRAPH "
            "are both true. Exactly one email provider must be enabled.")
    if not using_webhook and not using_graph:
        raise RuntimeError(
            "Invalid email configuration: EMAIL_USING_WEBHOOK and EMAIL_USING_GRAPH "
            "are both false. Exactly one email provider must be enabled.")
    if not (EMAIL_SUBJECT() or "").strip():
        raise RuntimeError(
            "Invalid email configuration: EMAIL_SUBJECT is required and must not "
            "be empty when notifications are enabled (NOTIFY_ON_SUBMIT=true).")
    if using_webhook and not EMAIL_WEBHOOK_URL():
        raise RuntimeError(
            "Invalid email configuration: EMAIL_USING_WEBHOOK=true but "
            "EMAIL_WEBHOOK_URL is not set.")
    if using_graph and not (GRAPH_MAIL_TENANT_ID() and GRAPH_MAIL_CLIENT_ID()
                            and GRAPH_MAIL_CLIENT_SECRET() and MAIL_FROM_ADDRESS()):
        raise RuntimeError(
            "Invalid email configuration: EMAIL_USING_GRAPH=true but one or more "
            "of GRAPH_MAIL_TENANT_ID / GRAPH_MAIL_CLIENT_ID / "
            "GRAPH_MAIL_CLIENT_SECRET / MAIL_FROM_ADDRESS is not set.")

# Direct Microsoft Graph email sending — one of the two selectable delivery
# mechanisms above. Requires a DEDICATED Entra app registration
# (separate from any Teams/Groups-reading app — a mail-sending credential
# should never also be a credential that can read channels/groups):
#   API permission: Mail.Send (Application, admin-consented)
#   MAIL_FROM_ADDRESS must be a real mailbox the app is permitted to send as.
GRAPH_MAIL_TENANT_ID  = lambda: env("GRAPH_MAIL_TENANT_ID")
GRAPH_MAIL_CLIENT_ID  = lambda: env("GRAPH_MAIL_CLIENT_ID")
GRAPH_MAIL_CLIENT_SECRET = lambda: env("GRAPH_MAIL_CLIENT_SECRET")
MAIL_FROM_ADDRESS     = lambda: env("MAIL_FROM_ADDRESS")

# Reference field format. Default is strict alphanumeric; override the app
# setting to relax it (e.g. "^[A-Za-z0-9_-]+$" to also allow - and _).
REFERENCE_PATTERN     = lambda: env("REFERENCE_PATTERN", r"^[A-Za-z0-9]+$")
REFERENCE_REQUIRED    = lambda: env_bool("REFERENCE_REQUIRED", True)
PROOFPOINT_TIMEOUT    = lambda: env_int("PROOFPOINT_TIMEOUT_SECONDS", 60)
INVENTORY_PAGE_SIZE   = lambda: env_int("INVENTORY_PAGE_SIZE", 50)      # Inventory tab rows per page


# ----- runtime (blob) config surfaced to the UI ----------------------------
DEFAULT_RUNTIME_CONFIG = {
    "portals": [
        {"id": "crowdstrike", "label": "CrowdStrike"},
        {"id": "sentinel", "label": "Microsoft Sentinel"},
        {"id": "proofpoint", "label": "Proofpoint"},
        {"id": "zscaler", "label": "Zscaler"},
    ],
    "advisoryPollSeconds": 60,
    "profiles": {
        "CSSPZ": ["crowdstrike", "sentinel", "proofpoint", "zscaler"],
        "CSS": ["crowdstrike", "sentinel"],
        "PROOFPOINT": ["sentinel", "proofpoint"],
        "SZ": ["sentinel", "zscaler"],
    },
    "environmentTag": "TLP:AMBER",
    "desktopNotifications": True,
    "serviceCodes": {
        "CSSPZ": ["crowdstrike", "sentinel", "proofpoint", "zscaler"],
        "CSS": ["crowdstrike", "sentinel"],
        "PROOFPOINT": ["proofpoint"],
        "SZ": ["sentinel", "zscaler"],
    },
    "permissions": {
        "add": ["ioc-operator", "ioc-admin"],
        "delete": ["ioc-admin"],
        "export": ["ioc-admin"],
        "viewInventory": ["ioc-admin"],
        "viewAdvisories": ["ioc-admin"],
    },
}

def runtime_config(storage) -> dict:
    """Merge defaults with config/portal-config.json from the storage account.
    Editing that blob changes portal lists, poll cadence, UI tags etc. with no code change."""
    cfg = dict(DEFAULT_RUNTIME_CONFIG)
    cfg["platformTypes"] = {
        "crowdstrike": FALCON_TYPES(),
        "sentinel": SENTINEL_TYPES(),
        "proofpoint": PROOFPOINT_TYPES(),
        "zscaler": ZSCALER_TYPES(),
    }
    cfg["referenceRequired"] = REFERENCE_REQUIRED()
    # domain indicators are fixed to "detect" with no dropdown shown at all
    # (see FALCON_HASH_ACTION_VALUES / FALCON_NON_HASH_ACTION above). Labels
    # map to Falcon's actual API action values.
    _falcon_hash_labels = {
        "prevent": "Block",
        "detect": "Detect Only",
        "prevent_no_ui": "Block + Hide Detection",
    }
    cfg["falconHashActions"] = [
        {"id": v, "label": _falcon_hash_labels.get(v, v.replace("_", " ").title())}
        for v in FALCON_HASH_ACTION_VALUES()
    ]
    try:
        raw = storage.read_blob(CONFIG_CONTAINER(), CONFIG_BLOB())
        if raw:
            cfg.update(json.loads(raw))
    except Exception:
        pass
    return cfg
