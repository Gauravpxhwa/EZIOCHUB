"""Server-side validation — the backend never trusts client validation."""
import ipaddress
import re
from urllib.parse import urlparse

RE_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(xn--)?[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", re.I)
RE_HASH = re.compile(r"^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)
RE_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")

VALID_TYPES = ("ip", "url", "domain", "hash", "email")


def ip_version(value: str) -> int | None:
    try:
        return ipaddress.ip_address(value).version
    except ValueError:
        return None


def has_internal_whitespace(value: str) -> bool:
    """True if the value contains whitespace anywhere other than the
    leading/trailing edges — e.g. "10.0.36 .1" or "https://x. xyz.com".
    A value like this is never a valid indicator of any type: it isn't
    one continuous token, so downstream systems (platform APIs, the
    internal-asset guard's exact-match checks) would either reject it
    outright or, worse, match it against nothing rather than the intended
    value. Checked BEFORE type-specific validation so the rejection reason
    is specific ("contains a space") rather than a generic "not valid"."""
    stripped = value.strip()
    return " " in stripped or "\t" in stripped or "\n" in stripped


def is_valid(ioc_type: str, value: str) -> bool:
    v = value.strip()
    if not v:
        return False
    if has_internal_whitespace(v):
        return False
    if ioc_type == "ip":
        return ip_version(v) in (4, 6)
    if ioc_type == "url":
        try:
            u = urlparse(v)
            return u.scheme in ("http", "https") and bool(u.netloc)
        except ValueError:
            return False
    if ioc_type == "domain":
        if not RE_DOMAIN.match(v):
            return False
        # An IP address is not a domain. The domain regex accepts all-numeric
        # labels, so "18.2.2.2" would otherwise pass as a domain — and would
        # then be checked against the WRONG internal-asset list (domains
        # instead of cidrs), silently bypassing the internal-IP guard.
        if ip_version(v) is not None:
            return False
        # No real TLD is numeric, so this also rejects near-misses that are
        # not parseable IPs, e.g. "1.2.3.4.5" or "999.999.999.999".
        if v.rsplit(".", 1)[-1].isdigit():
            return False
        return True
    if ioc_type == "hash":
        return bool(RE_HASH.match(v))
    if ioc_type == "email":
        return bool(RE_EMAIL.match(v))
    return False


def validate_batch(ioc_type: str, values: list[str]) -> tuple[list[str], list[str]]:
    """Return (valid, invalid) with whitespace stripped and duplicates removed."""
    seen, good, bad = set(), [], []
    for raw in values:
        v = raw.strip()
        if not v or v.lower() in seen:
            continue
        seen.add(v.lower())
        (good if is_valid(ioc_type, v) else bad).append(v)
    return good, bad
