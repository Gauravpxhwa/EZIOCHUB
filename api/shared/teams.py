"""Microsoft Graph access: role lookup (group-based permissions) and the
Teams advisory channel mirror.

App registration permissions needed (application, admin-consented, READ-ONLY):
  GroupMember.Read.All      - map users to portal roles
  ChannelMessage.Read.All   - read the advisory channel
  Files.Read.All            - download advisory attachments (SharePoint)
  Policy.Read.All           - Conditional Access exclusion watcher
All identifiers come from app settings, none from code.
"""
import base64
from datetime import datetime, timezone

import requests

from . import config as cfg

GRAPH = "https://graph.microsoft.com/v1.0"


class TeamsService:
    def __init__(self):
        self._token = None

    # ---- auth ----
    def token(self) -> str:
        if self._token:
            return self._token
        url = f"https://login.microsoftonline.com/{cfg.GRAPH_TENANT_ID()}/oauth2/v2.0/token"
        r = requests.post(url, data={
            "client_id": cfg.GRAPH_CLIENT_ID(),
            "client_secret": cfg.GRAPH_CLIENT_SECRET(),
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        }, timeout=cfg.HTTP_TIMEOUT())
        r.raise_for_status()
        self._token = r.json()["access_token"]
        return self._token

    def _get(self, url: str, **kw):
        r = requests.get(url, headers={"Authorization": f"Bearer {self.token()}"},
                         timeout=cfg.HTTP_TIMEOUT(), **kw)
        r.raise_for_status()
        return r

    # ---- roles: user's Entra groups -> portal roles ----
    def roles_for_user(self, user_object_id: str) -> list[str]:
        r = requests.post(
            f"{GRAPH}/users/{user_object_id}/checkMemberGroups",
            headers={"Authorization": f"Bearer {self.token()}"},
            json={"groupIds": list(cfg.role_group_map().values())[:20]},
            timeout=cfg.HTTP_TIMEOUT(),
        )
        r.raise_for_status()
        member_of = set(r.json().get("value", []))
        return [role for role, gid in cfg.role_group_map().items() if gid in member_of]

    def graph_get(self, path: str) -> dict:
        """Generic read-only Graph GET (used by the CA exclusion watcher)."""
        return self._get(f"{GRAPH}{path}").json()

    # ---- advisory channel ----
    def fetch_channel_messages(self) -> list[dict]:
        team, channel = cfg.TEAMS_TEAM_ID(), cfg.TEAMS_CHANNEL_ID()
        if not team or not channel:
            return []
        url = (f"{GRAPH}/teams/{team}/channels/{channel}/messages"
               f"?$top={cfg.TEAMS_FETCH_TOP()}")
        msgs = self._get(url).json().get("value", [])
        out = []
        for m in msgs:
            if m.get("messageType") not in (None, "message"):
                continue
            body = m.get("body") or {}
            html = body.get("content", "") if body.get("contentType") == "html" else ""
            text = body.get("content", "") if body.get("contentType") != "html" else ""
            frm = ((m.get("from") or {}).get("user") or {}).get("displayName") \
                  or ((m.get("from") or {}).get("application") or {}).get("displayName") or "channel"
            subject = m.get("subject") or _first_line(html or text) or "Advisory"
            out.append({
                "id": m["id"],
                "subject": subject[:180],
                "from": frm,
                "posted_at": (m.get("createdDateTime") or "")[:19],
                "preview": _first_line(html or text, 160),
                "body_html": html,
                "body_text": text,
                "attachments": [
                    {"name": a.get("name"), "contentUrl": a.get("contentUrl")}
                    for a in (m.get("attachments") or []) if a.get("contentUrl")
                ],
                "mirrored_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            })
        return out

    def download_attachment(self, content_url: str) -> bytes | None:
        """Teams attachments live in SharePoint; resolve via the shares API."""
        try:
            share_id = "u!" + base64.urlsafe_b64encode(content_url.encode()).decode().rstrip("=")
            r = self._get(f"{GRAPH}/shares/{share_id}/driveItem/content", stream=True)
            return r.raw.read(cfg.EXTRACT_MAX_BYTES(), decode_content=True)
        except Exception:
            return None


def _first_line(html_or_text: str, limit: int = 120) -> str:
    import re
    t = re.sub(r"<[^>]+>", " ", html_or_text or "")
    t = re.sub(r"\s+", " ", t).strip()
    return t[:limit]
