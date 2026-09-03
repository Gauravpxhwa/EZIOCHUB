"""Connector registry. Each connector implements add()/delete() and never
raises out — failures are reported per platform so one outage doesn't block
the others. Enable/disable each platform via app settings, no code change."""
import concurrent.futures
import logging

from .. import config as cfg

# Common wording across vendor APIs for "this already exists" rather than a
# real failure. Only Proofpoint's exact behavior here was confirmed against
# a tested runbook (409 / "conflict"); the others are reasonable heuristics
# based on common REST API conventions.
_CONFLICT_KEYWORDS = ("already exist", "duplicate", "conflict", "already present", "already in")


def looks_like_conflict(status_code: int, text: str) -> bool:
    """Heuristic: does this failed response actually mean 'already there',
    not a real error? If so, callers should treat it as success — an
    indicator already present on the platform IS the desired end state,
    not a failure to report."""
    if status_code == 409:
        return True
    t = (text or "").lower()
    return any(kw in t for kw in _CONFLICT_KEYWORDS)


def extract_error_detail(text: str, max_len: int = 400) -> str:
    """Pulls the actual reason out of a vendor's error response instead of
    blindly truncating raw text — a pretty-printed JSON body (CrowdStrike's
    included) can burn its entire character budget on whitespace and the
    "meta"/"trace_id" wrapper before ever reaching the real "message" field,
    which is exactly what happened here: a flat text[:200] cut the response
    off mid-sentence, before the actual reason was even visible.

    Tries a few common vendor JSON shapes (CrowdStrike's errors[].message,
    a flat "message" or "error" key); falls back to a longer raw-text
    truncation — collapsed to one line — if the body isn't JSON or doesn't
    match a known shape, so this never raises on an unexpected format."""
    import json as _json
    try:
        data = _json.loads(text)
        if isinstance(data, dict):
            errors = data.get("errors")
            if isinstance(errors, list) and errors:
                msgs = [e.get("message", "") for e in errors if isinstance(e, dict) and e.get("message")]
                if msgs:
                    return "; ".join(msgs)[:max_len]
            for key in ("message", "error", "detail"):
                if isinstance(data.get(key), str) and data[key]:
                    return data[key][:max_len]
    except (ValueError, TypeError):
        pass
    return " ".join((text or "").split())[:max_len]


class BaseConnector:
    id = "base"
    label = "Base"

    def enabled(self) -> bool:
        return False

    def add(self, items: list[dict], meta: dict) -> dict:
        """items: [{'type':..., 'value':...}]; meta: reference/date/added_by."""
        raise NotImplementedError

    def delete(self, items: list[dict], meta: dict) -> dict:
        raise NotImplementedError


def get_connectors() -> dict[str, "BaseConnector"]:
    from .crowdstrike import CrowdStrikeConnector
    from .sentinel import SentinelConnector
    from .proofpoint import ProofpointConnector
    from .zscaler import ZscalerConnector
    return {c.id: c for c in (
        CrowdStrikeConnector(), SentinelConnector(), ProofpointConnector(), ZscalerConnector())}


def dispatch(action: str, portals: list[str], items: list[dict], meta: dict) -> list[dict]:
    """Run add/delete against each requested portal CONCURRENTLY, not one
    after another — each platform has its own independent auth/session
    overhead (CrowdStrike/Proofpoint fetch a fresh token every call,
    Zscaler does a full login-work-logout cycle), so waiting for one
    platform before starting the next meant total latency was the SUM of
    every selected platform's response time. Now it's the slowest one.
    Result order still matches the order platforms were requested in."""
    connectors = get_connectors()

    def run_one(pid: str) -> dict:
        c = connectors.get(pid)
        if not c:
            return {"portal": pid, "ok": False, "detail": "unknown platform"}
        if not c.enabled():
            return {"portal": pid, "ok": False, "detail": "disabled in configuration"}
        try:
            r = c.add(items, meta) if action == "add" else c.delete(items, meta)
            return {"portal": pid, **r}
        except Exception as e:  # noqa: BLE001 — report, don't block other portals
            logging.exception("connector %s failed", pid)
            return {"portal": pid, "ok": False, "detail": str(e)[:300]}

    if not portals:
        return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(portals)) as executor:
        futures = [executor.submit(run_one, pid) for pid in portals]
        return [f.result() for f in futures]
