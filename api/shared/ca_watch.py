"""Conditional Access exclusion watcher.

Reads CA policies via Graph (Policy.Read.All — read-only), compares each
policy's excluded users / groups / applications with the previously seen
state (a blob), and returns alert lines for anything newly excluded so
admins can be notified by email. First sight of a policy establishes the
baseline without alerting.
"""
from . import config as cfg


def _exclusions(policy: dict) -> dict:
    cond = policy.get("conditions") or {}
    users = cond.get("users") or {}
    apps = cond.get("applications") or {}
    return {
        "users": sorted(users.get("excludeUsers") or []),
        "groups": sorted(users.get("excludeGroups") or []),
        "apps": sorted(apps.get("excludeApplications") or []),
    }


def check_ca_exclusions(storage, graph) -> list[str]:
    policies = graph.graph_get("/identity/conditionalAccess/policies").get("value", [])
    state = storage.get_state(cfg.CA_STATE_BLOB())
    alerts: list[str] = []
    new_state: dict = {}
    for p in policies:
        pid = p.get("id")
        name = p.get("displayName", "policy")
        cur = _exclusions(p)
        new_state[pid] = cur
        prev = state.get(pid)
        if prev is None:
            continue  # baseline on first sight — no alert
        for kind, label in (("users", "user"), ("groups", "group"), ("apps", "application")):
            for added in sorted(set(cur[kind]) - set(prev.get(kind, []))):
                alerts.append(f"New {label} excluded in Conditional Access policy '{name}': {added}")
    storage.set_state(new_state, cfg.CA_STATE_BLOB())
    return alerts
