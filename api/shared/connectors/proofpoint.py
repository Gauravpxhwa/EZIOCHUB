"""Proofpoint — Lists API (replaces the earlier orgBlockList approach).

Confirmed working via a tested PowerShell script against the real API.
Two SEPARATE lists, one per indicator type — each list's type is fixed at
creation time on Proofpoint's side, so this connector must route each
value to the correct list, not send one mixed request:

  email -> PROOFPOINT_EMAIL_LIST_ID
  ip    -> PROOFPOINT_IP_LIST_ID

Domains are NOT supported here by explicit requirement — there is no
domain list, and none is created. A domain-type submission simply isn't
routed to Proofpoint at all (see PROOFPOINT_TYPES in config.py, which no
longer includes "domain").

Auth:   OAuth2 client credentials at PROOFPOINT_TOKEN_URL (unchanged from
        the prior implementation — same tenant, same credentials).
Add:    POST {PROOFPOINT_API_BASE}/api/v1/lists/{listId}/entries?clusterId=...
        Body: {"add": [...values...], "delete": []}
Delete: NOT IMPLEMENTED. This is an add-only integration by explicit
        requirement — delete() returns a clear "not supported" result
        rather than silently doing nothing or guessing at a delete
        endpoint that hasn't been tested.
"""
import requests

from .. import config as cfg
from . import BaseConnector, extract_error_detail

# Maps an IOC type to the config accessor for ITS OWN list ID — kept as a
# dict of functions (not resolved values) so each is read fresh at call
# time, consistent with how every other config value in this app is
# read live rather than cached at import time.
_LIST_ID_FOR_TYPE = {
    "email": cfg.PROOFPOINT_EMAIL_LIST_ID,
    "ip": cfg.PROOFPOINT_IP_LIST_ID,
}


class ProofpointConnector(BaseConnector):
    id = "proofpoint"
    label = "Proofpoint"

    def enabled(self):
        return (cfg.PROOFPOINT_ENABLED()
                and bool(cfg.PROOFPOINT_CLIENT_ID())
                and bool(cfg.PROOFPOINT_CLUSTER_ID()))

    def _token(self) -> str:
        r = requests.post(cfg.PROOFPOINT_TOKEN_URL(), data={
            "grant_type": "client_credentials",
            "client_id": cfg.PROOFPOINT_CLIENT_ID(),
            "client_secret": cfg.PROOFPOINT_CLIENT_SECRET(),
        }, headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=cfg.HTTP_TIMEOUT())
        r.raise_for_status()
        token = r.json().get("access_token")
        if not token:
            raise RuntimeError("Proofpoint token response was empty")
        return token

    def add(self, items, meta):
        by_list: dict[str, list[str]] = {}
        skipped = 0
        for it in items:
            list_id_fn = _LIST_ID_FOR_TYPE.get(it["type"])
            list_id = list_id_fn() if list_id_fn else None
            if not list_id:
                skipped += 1
                continue
            by_list.setdefault(list_id, []).append(it["value"])

        if not by_list:
            return {"ok": False, "detail": "no configured list for the submitted indicator "
                    "type(s) — Proofpoint only supports email and IP here"}

        try:
            headers = {"Authorization": f"Bearer {self._token()}",
                       "Content-Type": "application/json"}
        except requests.RequestException as e:
            return {"ok": False, "detail": f"Proofpoint auth failed: {e.__class__.__name__}"}
        except RuntimeError as e:
            return {"ok": False, "detail": str(e)}

        params = {"clusterId": cfg.PROOFPOINT_CLUSTER_ID()}
        added_total, errors = 0, []

        for list_id, values in by_list.items():
            url = f"{cfg.PROOFPOINT_API_BASE().rstrip('/')}/api/v1/lists/{list_id}/entries"
            body = {"add": values, "delete": []}
            try:
                r = requests.post(url, params=params, headers=headers, json=body,
                                  timeout=cfg.PROOFPOINT_TIMEOUT())
                if r.ok:
                    added_total += len(values)
                else:
                    errors.append(f"list {list_id}: HTTP {r.status_code} "
                                  f"{extract_error_detail(r.text)}")
            except requests.exceptions.Timeout:
                errors.append(f"list {list_id}: request timed out — entries may still "
                              f"have been accepted server-side")
            except requests.RequestException as e:
                errors.append(f"list {list_id}: {e.__class__.__name__}")

        if not added_total and errors:
            return {"ok": False, "detail": "; ".join(errors[:3])[:400]}

        note = f"{added_total} entr{'y' if added_total == 1 else 'ies'} added"
        if skipped:
            note += f", {skipped} skipped (type not supported — email/IP only)"
        if errors:
            note += f", {len(errors)} list(s) failed: " + "; ".join(errors[:2])
        return {"ok": True, "detail": note}

    def delete(self, items, meta):
        return {"ok": False, "detail": "Proofpoint delete is not supported by this "
                "integration (add-only, by design)"}
