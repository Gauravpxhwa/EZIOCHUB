"""Microsoft Sentinel — Threat Intelligence via the SecurityInsights
management API (createIndicator), matching the proven runbook approach.

Add:    POST {workspaceResourceId}/providers/Microsoft.SecurityInsights/
             threatIntelligence/main/createIndicator?api-version=...
Delete: queryIndicators (keyword) then DELETE indicators/{name}.
Auth:   managed identity (DefaultAzureCredential) -> management.azure.com.
Workspace resource id + api-version are app settings — nothing org-specific
in code, and Microsoft api-version bumps are config-only."""
from datetime import datetime, timezone

import requests
from azure.identity import DefaultAzureCredential

from .. import config as cfg
from ..validators import ip_version
from . import BaseConnector

MGMT = "https://management.azure.com"


def _pattern(item: dict) -> str | None:
    t, v = item["type"], item["value"].replace("'", "")
    if t == "ip":
        return (f"[ipv4-addr:value = '{v}']" if ip_version(v) == 4
                else f"[ipv6-addr:value = '{v}']")
    if t == "url":
        return f"[url:value = '{v}']"
    if t == "domain":
        return f"[domain-name:value = '{v}']"
    if t == "email":
        return f"[email-addr:value = '{v}']"
    if t == "hash":
        key = {64: "'SHA-256'", 40: "'SHA-1'", 32: "MD5"}.get(len(v))
        return f"[file:hashes.{key} = '{v}']" if key else None
    return None


class SentinelConnector(BaseConnector):
    id = "sentinel"
    label = "Microsoft Sentinel"

    def enabled(self):
        return cfg.SENTINEL_ENABLED() and bool(cfg.SENTINEL_WORKSPACE_RESOURCE_ID())

    def _base(self) -> str:
        ws = cfg.SENTINEL_WORKSPACE_RESOURCE_ID().rstrip("/")
        return f"{MGMT}{ws}/providers/Microsoft.SecurityInsights/threatIntelligence/main"

    def _headers(self) -> dict:
        token = DefaultAzureCredential().get_token(f"{MGMT}/.default").token
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def add(self, items, meta):
        headers = self._headers()
        api = {"api-version": cfg.SENTINEL_API_VERSION()}
        now = datetime.now(timezone.utc)
        # valid_until = now + timedelta(days=cfg.IOC_EXPIRATION_DAYS())
        ok_count, skipped, errors = 0, 0, []
        for it in items:
            pattern = _pattern(it)
            if not pattern:
                skipped += 1
                continue
            body = {
                "kind": "indicator",
                "properties": {
                    "pattern": pattern,
                    "patternType": "stix",
                    "validFrom": now.strftime("%Y-%m-%dT%H:%M:%S.%f0Z"),
                    #"validUntil": valid_until.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "displayName": f"IOC Portal - {it['type']}: {it['value']}"[:100],
                    "description": (meta.get("reference") or "IOC Distribution Portal")[:256],
                    "threatTypes": ["malicious-activity"],
                    "confidence": cfg.SENTINEL_CONFIDENCE(),
                    "revoked": False,
                    "source": cfg.SENTINEL_SOURCE(),
                    "labels": ["ioc-distribution-portal"],
                },
            }
            r = requests.post(f"{self._base()}/createIndicator", params=api,
                              headers=headers, json=body, timeout=cfg.HTTP_TIMEOUT())
            if r.ok:
                ok_count += 1
            else:
                errors.append(f"{it['value']}: HTTP {r.status_code}")
        if not ok_count and errors:
            return {"ok": False, "detail": "; ".join(errors[:3])[:280]}
        note = f"{ok_count} indicator(s) created"
        if skipped:
            note += f", {skipped} skipped (unsupported type)"
        if errors:
            note += f", {len(errors)} failed"
        return {"ok": True, "detail": note}

    def delete(self, items, meta):
        headers = self._headers()
        api = {"api-version": cfg.SENTINEL_API_VERSION()}
        removed = 0
        for it in items:
            q = requests.post(f"{self._base()}/queryIndicators", params=api,
                              headers=headers,
                              json={"keywords": it["value"], "pageSize": 20},
                              timeout=cfg.HTTP_TIMEOUT())
            if not q.ok:
                continue
            for ind in q.json().get("value", []):
                name = ind.get("name")
                if name:
                    d = requests.delete(f"{self._base()}/indicators/{name}", params=api,
                                        headers=headers, timeout=cfg.HTTP_TIMEOUT())
                    if d.ok:
                        removed += 1
        return {"ok": True, "detail": f"{removed} indicator(s) removed"}
