"""Storage account access.

- iocs.csv in the IOC container is the reference store (the CSV the
  delete dropdown reads from).
- advisories/<id>.json are mirrored Teams advisory posts.
- config/portal-config.json is the runtime-tunable configuration.

Auth: connection string OR managed identity (set STORAGE_ACCOUNT_URL and
grant the app 'Storage Blob Data Contributor'); nothing in code.
"""
import csv
import io
import json
import uuid
from datetime import datetime, timezone

from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.storage.blob import BlobServiceClient

from . import config as cfg

CSV_FIELDS = [
    "id", "ioc_type", "ioc_value", "added_by", "date", "reference",
    "portals", "status", "submitted_at", "deleted_by", "deleted_at",
]


class Storage:
    def __init__(self):
        conn = cfg.STORAGE_CONNECTION()
        if conn:
            self._svc = BlobServiceClient.from_connection_string(conn)
        else:
            from azure.identity import DefaultAzureCredential
            self._svc = BlobServiceClient(cfg.STORAGE_ACCOUNT_URL(), credential=DefaultAzureCredential())

    # ---------- generic ----------
    def _blob(self, container: str, name: str):
        return self._svc.get_blob_client(container, name)

    def ensure_containers(self):
        for c in (cfg.IOC_CONTAINER(), cfg.ADVISORY_CONTAINER(), cfg.CONFIG_CONTAINER()):
            try:
                self._svc.create_container(c)
            except ResourceExistsError:
                pass

    def read_blob(self, container: str, name: str) -> str | None:
        try:
            return self._blob(container, name).download_blob().readall().decode("utf-8")
        except ResourceNotFoundError:
            return None

    def write_blob(self, container: str, name: str, content: str, etag: str | None = None):
        kwargs = {"overwrite": True}
        if etag:
            from azure.core import MatchConditions
            kwargs.update(etag=etag, match_condition=MatchConditions.IfNotModified)
        self._blob(container, name).upload_blob(content.encode("utf-8"), **kwargs)

    # ---------- IOC CSV reference store ----------
    def _load_csv(self) -> tuple[list[dict], str | None]:
        blob = self._blob(cfg.IOC_CONTAINER(), cfg.IOC_BLOB())
        try:
            dl = blob.download_blob()
            rows = list(csv.DictReader(io.StringIO(dl.readall().decode("utf-8"))))
            return rows, dl.properties.etag
        except ResourceNotFoundError:
            return [], None

    def _save_csv(self, rows: list[dict], etag: str | None):
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
        if etag:
            self.write_blob(cfg.IOC_CONTAINER(), cfg.IOC_BLOB(), buf.getvalue(), etag)
        else:
            self.write_blob(cfg.IOC_CONTAINER(), cfg.IOC_BLOB(), buf.getvalue())

    def get_active_portals_bulk(self, items: list[dict]) -> dict[tuple, set[str]]:
        """Same lookup as get_active_portals(), but for a whole batch in ONE
        CSV read instead of one read per item. Submitting 10 IOCs previously
        meant 10 separate full downloads of the reference store before
        dispatch even started — this replaces that with exactly one."""
        rows, _ = self._load_csv()
        index: dict[tuple, set[str]] = {}
        for r in rows:
            if r.get("status") != "active":
                continue
            key = (r["ioc_type"], r["ioc_value"].strip().lower())
            index[key] = {p for p in (r.get("portals") or "").split("|") if p}
        result: dict[tuple, set[str]] = {}
        for it in items:
            key = (it["type"], it["value"].strip().lower())
            result[key] = index.get(key, set())
        return result

    def merge_portal_success(self, updates: list[dict]) -> None:
        """Record newly-confirmed platform successes against inventory.

        updates: [{'ioc_type','ioc_value','added_by','date','reference',
                    'succeeded_portals': [...]}] — one entry per value that
        had at least one platform succeed THIS submission.

        A value already active gets its portals list EXTENDED (union) with
        the newly-succeeded platforms — a platform already confirmed is
        never touched or re-recorded. A value not yet active gets a new
        row containing only the platforms that succeeded just now (not
        the full requested set — platforms that failed this round are
        simply not yet recorded, so a future retry targeting them is
        correctly treated as new work, not a duplicate).
        One read-modify-write cycle for the whole batch.
        """
        if not updates:
            return
        rows, etag = self._load_csv()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        index = {(r["ioc_type"], r["ioc_value"].strip().lower()): i
                 for i, r in enumerate(rows) if r.get("status") == "active"}
        for u in updates:
            key = (u["ioc_type"], u["ioc_value"].strip().lower())
            if key in index:
                r = rows[index[key]]
                cur = {p for p in (r.get("portals") or "").split("|") if p}
                cur |= set(u["succeeded_portals"])
                r["portals"] = "|".join(sorted(cur))
            else:
                rows.append({
                    "id": uuid.uuid4().hex[:12], "ioc_type": u["ioc_type"],
                    "ioc_value": u["ioc_value"], "added_by": u["added_by"],
                    "date": u["date"], "reference": u["reference"],
                    "portals": "|".join(sorted(u["succeeded_portals"])),
                    "status": "active", "submitted_at": now,
                    "deleted_by": "", "deleted_at": "",
                })
        self._save_csv(rows, etag)

    def list_iocs(self) -> list[dict]:
        rows, _ = self._load_csv()
        for r in rows:
            r["portals"] = [p for p in (r.get("portals") or "").split("|") if p]
        rows.sort(key=lambda r: r.get("submitted_at", ""), reverse=True)
        return rows

    def find_active_duplicates(self, items: list[dict]) -> list[dict]:
        """Check items ([{'type':..., 'value':...}]) against active inventory.
        Returns the subset that already exist and are active, so callers can
        reject them with a clear error BEFORE dispatching to any platform —
        an already-tracked indicator should never be silently re-distributed.

        EXACT MATCH ONLY: a hit requires the full type AND the full value
        (case-insensitive, whitespace-trimmed) to be identical to a stored
        row. This is tuple equality, not substring/contains — '203.0.113.4'
        never matches '203.0.113.45', and a domain never matches merely
        because it shares a suffix with a stored one (that's the SEPARATE,
        intentionally-fuzzy internal-asset check in internal_check.py, not
        this one)."""
        rows, _ = self._load_csv()
        active = {(r["ioc_type"], r["ioc_value"].strip().lower())
                  for r in rows if r.get("status") == "active"}
        hits = []
        for it in items:
            full_value = (it.get("value") or "").strip()
            key = (it.get("type", ""), full_value.lower())
            if key in active:  # exact tuple equality — see docstring
                hits.append({"value": it["value"], "reason": "already in inventory (active)"})
        return hits

    def add_iocs(self, ioc_type: str, values: list[str], added_by: str, date: str,
                 reference: str, portals: list[str]) -> list[dict]:
        rows, etag = self._load_csv()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        new = []
        existing_active = {(r["ioc_type"], r["ioc_value"].lower())
                           for r in rows if r.get("status") == "active"}
        for v in values:
            if (ioc_type, v.lower()) in existing_active:
                continue  # belt-and-suspenders: caller should already have
                          # rejected duplicates via find_active_duplicates()
            rec = {
                "id": uuid.uuid4().hex[:12],
                "ioc_type": ioc_type,
                "ioc_value": v,
                "added_by": added_by,
                "date": date,
                "reference": reference,
                "portals": "|".join(portals),
                "status": "active",
                "submitted_at": now,
                "deleted_by": "",
                "deleted_at": "",
            }
            rows.append(rec)
            new.append(rec)
        self._save_csv(rows, etag)
        return new

    def mark_deleted(self, ids: list[str], deleted_by: str) -> list[dict]:
        rows, etag = self._load_csv()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        hit = []
        for r in rows:
            if r["id"] in ids and r.get("status") == "active":
                r["status"] = "deleted"
                r["deleted_by"] = deleted_by
                r["deleted_at"] = now
                hit.append(r)
        self._save_csv(rows, etag)
        for r in hit:
            r["portals"] = [p for p in (r.get("portals") or "").split("|") if p]
        return hit

    # ---------- advisories ----------
    def save_advisory(self, adv: dict):
        name = f"{adv['id']}.json"
        try:
            self._blob(cfg.ADVISORY_CONTAINER(), name).upload_blob(
                json.dumps(adv).encode("utf-8"), overwrite=False)
        except ResourceExistsError:
            pass

    def update_advisory(self, adv: dict):
        self._blob(cfg.ADVISORY_CONTAINER(), f"{adv['id']}.json").upload_blob(
            json.dumps(adv).encode("utf-8"), overwrite=True)

    def list_advisories(self) -> list[dict]:
        container = self._svc.get_container_client(cfg.ADVISORY_CONTAINER())
        items = []
        try:
            for b in container.list_blobs():
                if not b.name.endswith(".json"):
                    continue
                raw = self.read_blob(cfg.ADVISORY_CONTAINER(), b.name)
                if raw:
                    a = json.loads(raw)
                    items.append({k: a.get(k) for k in
                                  ("id", "subject", "from", "preview", "posted_at", "attachments", "action_taken")})
        except ResourceNotFoundError:
            return []
        items.sort(key=lambda a: a.get("posted_at") or "", reverse=True)
        return items

    def get_advisory(self, adv_id: str) -> dict | None:
        raw = self.read_blob(cfg.ADVISORY_CONTAINER(), f"{adv_id}.json")
        return json.loads(raw) if raw else None

    # ---------- teams poll state ----------
    def get_state(self, blob_name: str | None = None) -> dict:
        raw = self.read_blob(cfg.CONFIG_CONTAINER(), blob_name or cfg.STATE_BLOB())
        return json.loads(raw) if raw else {}

    def set_state(self, state: dict, blob_name: str | None = None):
        self.write_blob(cfg.CONFIG_CONTAINER(), blob_name or cfg.STATE_BLOB(), json.dumps(state))
