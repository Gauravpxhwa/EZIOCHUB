from urllib.parse import urlparse

import requests

from .. import config as cfg
from ..validators import ip_version
from . import BaseConnector, extract_error_detail, looks_like_conflict


class CrowdStrikeConnector(BaseConnector):
    id = "crowdstrike"
    label = "CrowdStrike"

    def enabled(self):
        return cfg.CROWDSTRIKE_ENABLED() and bool(cfg.FALCON_CLIENT_ID())

    # ---- auth ----
    def _token(self) -> str:
        r = requests.post(f"{cfg.FALCON_BASE_URL()}/oauth2/token", data={
            "client_id": cfg.FALCON_CLIENT_ID(),
            "client_secret": cfg.FALCON_CLIENT_SECRET(),
        }, timeout=cfg.HTTP_TIMEOUT())
        r.raise_for_status()
        return r.json()["access_token"]

    def _map(self, item: dict) -> tuple[str, str] | None:
        t, v = item["type"], item["value"]
        if t == "ip":
            return ("ipv4" if ip_version(v) == 4 else "ipv6", v)
        if t == "domain":
            return ("domain", v)
        if t == "url":
            host = urlparse(v).hostname
            return ("domain", host) if host else None
        if t == "hash":
            if len(v) == 64:
                return ("sha256", v)
            if len(v) == 32:
                return ("md5", v)
        return None  # sha1 / email unsupported by Falcon custom IOCs

    def add(self, items, meta):
        mapped, skipped = [], 0
        for it in items:
            m = self._map(it)
            if not m:
                skipped += 1
                continue
            action = meta.get("falcon_action") or "detect"            
            mapped.append({
                "type": m[0], "value": m[1],
                "action": action,
                "severity": cfg.FALCON_SEVERITY(),
                "platforms": cfg.FALCON_PLATFORMS(),
                "applied_globally": True,
                "description": (meta.get("reference") or "IOC Distribution Portal")[:200],
                "source": "IOC Distribution Portal",
            })
        if not mapped:
            return {"ok": False, "detail": "no indicator types supported by this platform"}
        r = requests.post(
            f"{cfg.FALCON_BASE_URL()}/iocs/entities/indicators/v1",
            headers={"Authorization": f"Bearer {self._token()}"},
            json={"indicators": mapped},
            params={"ignore_warnings": "true"},
            timeout=cfg.HTTP_TIMEOUT())
        if r.status_code >= 400:
            return {"ok": False, "detail": f"HTTP {r.status_code}: {extract_error_detail(r.text)}"}
        note = f"{len(mapped)} indicator(s) added" + (f", {skipped} skipped (unsupported type)" if skipped else "")
        return {"ok": True, "detail": note}

    def delete(self, items, meta):
        token = self._token()
        ids = []
        for it in items:
            m = self._map(it)
            if not m:
                continue
            q = requests.get(
                f"{cfg.FALCON_BASE_URL()}/iocs/queries/indicators/v1",
                headers={"Authorization": f"Bearer {token}"},
                params={"filter": f"value:'{m[1]}'"},
                timeout=cfg.HTTP_TIMEOUT())
            if q.ok:
                ids += q.json().get("resources", [])
        if not ids:
            return {"ok": True, "detail": "nothing matching found on platform"}
        d = requests.delete(
            f"{cfg.FALCON_BASE_URL()}/iocs/entities/indicators/v1",
            headers={"Authorization": f"Bearer {token}"},
            params=[("ids", i) for i in ids],
            timeout=cfg.HTTP_TIMEOUT())
        if d.status_code >= 400:
            return {"ok": False, "detail": f"HTTP {d.status_code}: {extract_error_detail(d.text)}"}
        return {"ok": True, "detail": f"{len(ids)} indicator(s) removed"}
