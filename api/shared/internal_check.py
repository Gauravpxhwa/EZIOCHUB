"""Internal-environment guard.

Validates indicators against the organisation's own environment. If a value
matches an internal IP range, domain, URL, email, or file hash, the
submission is REJECTED with an error telling the analyst to remove it and
try again — internal assets can never reach a platform block list.

MATCHING IS DELIBERATELY EXACT AND EXPLICIT for the type-specific lists —
each IOC type is checked only against its own dedicated list in the
config, using plain equality (case-insensitive, whitespace-trimmed). There
is no subdomain inference, no URL parsing/hostname extraction, and no
cross-type derivation (an email's domain half is NOT checked against the
domains list) EXCEPT via the "exceptions" rule below, which is deliberately
broader by design.

The one exception to exact-matching is IPs: a CIDR range is itself an
explicit, literal value someone chose to list — checking whether an IP
falls inside it is the direct purpose of listing a range, not an inference.
This applies to three separate IP-range sources, all checked the same way
for "ip"-type submissions: the JSON blob's "cidrs" list, and two CSV blobs
(named locations, ZIA locations — see below).

For URLs specifically, scope is widened beyond exact match: a listed
domain appearing anywhere in the URL text (simple substring, not full
parsing) is also caught, on top of an exact "urls" list match.

EXCEPTIONS — checked FIRST, across EVERY IOC type: a submitted value
containing any listed "exceptions" substring is flagged as internal,
regardless of type or whether it also appears in a type-specific list.
This is a catch-all rule, not a bypass — use it for anything (a domain
fragment, a brand name, etc.) that should be blocked no matter which IOC
type it shows up as.

The definition of "internal" lives in a storage blob —
config/internal-assets.json (blob name itself is the INTERNAL_ASSETS_BLOB
setting) — editable at any time with no code change:

{
  "cidrs":      ["10.0.0.0/8", "fc00::/7", ...],
  "domains":    ["corp.example", ...],          # exact match, also checked as substring in URLs
  "urls":       ["https://intranet.corp.example/portal", ...],  # exact match
  "emails":     ["soc@corp.example", ...],      # exact match only
  "hashes":     [],
  "exceptions": ["corp.example"]  # substrings blocked across EVERY IOC type
}

Two ADDITIONAL IP-range sources, each a CSV blob (NAMED_LOCATIONS_BLOB /
ZIA_LOCATIONS_BLOB settings — default names named-locations.csv and
zia-locations.csv), one row per range, two columns:

  location_name,ip_range
  HQ-London,203.0.113.0/24
  DC-Frankfurt,198.51.100.5

A submitted "ip"-type value matching any range in either CSV is blocked
exactly like a "cidrs" match in the JSON blob — same guard, same
rejection behaviour, just a second and third editable source feeding it.
Editing either CSV takes effect immediately on the next request, same as
every other config source here — no code change, no redeploy.
"""
import csv
import io
import ipaddress
import json

from . import config as cfg


def _load_ip_range_csv(storage, blob_name: str) -> list[tuple[str, str]]:
    """Reads a two-column CSV (location_name, ip_range) into a list of
    (location_name, ip_range) tuples. Missing blob, empty blob, or a
    malformed row is handled quietly — a broken/missing CSV means this
    source contributes nothing, it does not break the rest of the guard.

    Strips a leading UTF-8 BOM and normalises header names (trimmed,
    lower/underscored) before matching — confirmed by testing that a BOM
    (very common when a CSV is saved from Excel or Windows Notepad's
    "UTF-8" mode) or a stray trailing space in the header row otherwise
    causes every row to be silently dropped, since the header key no
    longer matches "location_name"/"ip_range" exactly."""
    try:
        raw = storage.read_blob(cfg.CONFIG_CONTAINER(), blob_name)
        if not raw:
            return []
        raw = raw.lstrip("\ufeff")  # strip UTF-8 BOM if present
        rows = csv.DictReader(io.StringIO(raw))
        if rows.fieldnames:
            rows.fieldnames = [
                (f or "").strip().lower().replace(" ", "_") for f in rows.fieldnames
            ]
        out = []
        for row in rows:
            name = (row.get("location_name") or "").strip()
            ip_range = (row.get("ip_range") or "").strip()
            if name and ip_range:
                out.append((name, ip_range))
        return out
    except Exception:
        return []


def load_assets(storage) -> dict:
    try:
        raw = storage.read_blob(cfg.CONFIG_CONTAINER(), cfg.INTERNAL_ASSETS_BLOB())
        data = json.loads(raw) if raw else {}
    except Exception:
        data = {}
    return {
        "cidrs": [c for c in data.get("cidrs", []) if c],
        "domains": [str(d).strip().lower() for d in data.get("domains", []) if d],
        "urls": [str(u).strip().lower() for u in data.get("urls", []) if u],
        "emails": [str(e).strip().lower() for e in data.get("emails", []) if e],
        "hashes": [str(h).strip().lower() for h in data.get("hashes", []) if h],
        "exceptions": [str(x).strip().lower() for x in data.get("exceptions", []) if x],
        "named_locations": _load_ip_range_csv(storage, cfg.NAMED_LOCATIONS_BLOB()),
        "zia_locations": _load_ip_range_csv(storage, cfg.ZIA_LOCATIONS_BLOB()),
    }


def _ip_internal(value: str, cidrs: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if ip in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def _matched_location(value: str, locations: list[tuple[str, str]]) -> str | None:
    """Like _ip_internal, but for the (name, range) CSV sources — returns
    the matched location's NAME so the block reason can name it, e.g.
    'matched named location: HQ-London', rather than a generic message."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    for name, ip_range in locations:
        try:
            if ip in ipaddress.ip_network(ip_range, strict=False):
                return name
        except ValueError:
            continue
    return None


def internal_reason(assets: dict, ioc_type: str, value: str) -> str | None:
    v = value.strip()
    vl = v.lower()

    # Exceptions checked FIRST — a catch-all BLOCK rule across every IOC
    # type. Any value containing a listed substring is flagged here,
    # before the type-specific checks below even run.
    for ex in assets.get("exceptions", []):
        if ex in vl:
            return f"internal asset (matched exception rule: {ex})"

    if ioc_type == "ip":
        if _ip_internal(v, assets["cidrs"]):
            return "internal IP range"
        named = _matched_location(v, assets.get("named_locations", []))
        if named:
            return f"matched named location: {named}"
        zia = _matched_location(v, assets.get("zia_locations", []))
        if zia:
            return f"matched ZIA location: {zia}"
    if ioc_type == "domain" and vl in assets["domains"]:
        return "internal domain"
    if ioc_type == "url":
        if vl in assets["urls"]:
            return "internal URL"
        if any(d in vl for d in assets["domains"]):
            return "internal domain referenced in URL"
    if ioc_type == "email" and vl in assets["emails"]:
        return "internal email address"
    if ioc_type == "hash" and vl in assets["hashes"]:
        return "internal file hash"
    return None


def find_internal(storage, items: list[dict]) -> list[dict]:
    """Return [{'value':..., 'reason':...}] for every item that is internal."""
    assets = load_assets(storage)
    if not any(assets.values()):
        return []
    hits = []
    for it in items:
        reason = internal_reason(assets, it.get("type", ""), it.get("value", ""))
        if reason:
            hits.append({"value": it["value"], "reason": reason})
    return hits
