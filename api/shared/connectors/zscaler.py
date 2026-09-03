"""Zscaler Internet Access — Cyber Threat Protection malicious-URL list,
matching the proven runbook approach.

Auth:   /authenticatedSession with the ZIA API-key timestamp obfuscation.
Add:    PUT {ZSCALER_LIST_PATH}?action=ADD_TO_LIST  {"maliciousUrls":[...]}
Delete: PUT {ZSCALER_LIST_PATH}?action=REMOVE_FROM_LIST
Then optional /status/activate and session logout.
ZIA rejects URLs with a scheme, so http(s):// is stripped. Cloud base URL,
credentials, list path, activation and routed types are all app settings.
"""
import time

import requests

from .. import config as cfg
from . import BaseConnector, extract_error_detail, looks_like_conflict


def _obfuscate(api_key: str, ts: str) -> str:
    high = ts[-6:]
    low = str(int(high) >> 1).zfill(6)
    out = "".join(api_key[int(c)] for c in high)
    out += "".join(api_key[int(c) + 2] for c in low)
    return out


class ZscalerConnector(BaseConnector):
    id = "zscaler"
    label = "Zscaler"

    def enabled(self):
        return cfg.ZSCALER_ENABLED() and bool(cfg.ZSCALER_BASE_URL())

    def _session(self) -> requests.Session:
        s = requests.Session()
        ts = str(int(time.time() * 1000))
        r = s.post(f"{cfg.ZSCALER_BASE_URL()}/authenticatedSession", json={
            "apiKey": _obfuscate(cfg.ZSCALER_API_KEY(), ts),
            "username": cfg.ZSCALER_USERNAME(),
            "password": cfg.ZSCALER_PASSWORD(),
            "timestamp": int(ts),
        }, timeout=cfg.HTTP_TIMEOUT())
        r.raise_for_status()
        return s

    @staticmethod
    def _values(items: list[dict]) -> tuple[list[str], int]:
        routed = cfg.ZSCALER_TYPES()
        vals, skipped = [], 0
        for i in items:
            if i["type"] in routed:
                v = i["value"]
                # ZIA strictly rejects entries containing the protocol
                vals.append(v.split("://", 1)[-1] if "://" in v else v)
            else:
                skipped += 1
        return vals, skipped

    def _apply(self, action: str, items, meta):
        vals, skipped = self._values(items)
        if not vals:
            return {"ok": False, "detail": "no indicator types routed to this platform"}
        s = self._session()
        try:
            r = s.put(f"{cfg.ZSCALER_BASE_URL()}{cfg.ZSCALER_LIST_PATH()}",
                      params={"action": action}, json={"maliciousUrls": vals},
                      timeout=cfg.HTTP_TIMEOUT())
            if r.status_code >= 400:
                return {"ok": False, "detail": f"HTTP {r.status_code}: {extract_error_detail(r.text)}"}
            note = f"{len(vals)} entr(ies) {'added' if action == 'ADD_TO_LIST' else 'removed'}"
            if skipped:
                note += f", {skipped} skipped (type not routed)"
            if cfg.ZSCALER_ACTIVATE():
                a = s.post(f"{cfg.ZSCALER_BASE_URL()}/status/activate",
                           timeout=cfg.HTTP_TIMEOUT())
                note += "; activated" if a.ok else "; activation pending (activate manually)"
            return {"ok": True, "detail": note}
        finally:
            try:
                s.delete(f"{cfg.ZSCALER_BASE_URL()}/authenticatedSession",
                         timeout=cfg.HTTP_TIMEOUT())
            except requests.RequestException:
                pass

    def add(self, items, meta):
        return self._apply("ADD_TO_LIST", items, meta)

    def delete(self, items, meta):
        return self._apply("REMOVE_FROM_LIST", items, meta)
