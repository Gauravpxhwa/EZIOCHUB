"""Extract indicators from advisory text, HTML, linked pages and attachments.

Handles defanged notation commonly used in advisories:
  hxxp://x[.]y   198.51.100[.]7   user[@]example[.]com   (.) {.} [dot]
"""
import io
import re
from html.parser import HTMLParser

import requests

from . import config as cfg
from .validators import is_valid, ip_version

# ---- refang ---------------------------------------------------------------
_REFANG = [
    (re.compile(r"h[xX]{2}ps?://", re.I), lambda m: "https://" if "s" in m.group(0).lower().replace("x", "t") else "http://"),
    (re.compile(r"\[(\.|dot)\]|\((\.|dot)\)|\{(\.|dot)\}", re.I), lambda m: "."),
    (re.compile(r"\[@\]|\(@\)|\{@\}| at ", re.I), lambda m: "@"),
    (re.compile(r"\[:\]|\[://\]"), lambda m: "://"),
]

def refang(text: str) -> str:
    text = re.sub(r"hxxp", "http", text, flags=re.I)
    for rx, repl in _REFANG[1:]:
        text = rx.sub(repl, text)
    return text

# ---- patterns -------------------------------------------------------------
RX_URL = re.compile(r"\bhttps?://[^\s\"'<>\)\]]+", re.I)
RX_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
RX_IPV6 = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9:]{1,45}\b")
RX_HASH = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
RX_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RX_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)

# Common benign/vendor domains an advisory or a vendor blog mentions without
# them being IOCs. Extend per-org with the EXTRACT_NOISE_DOMAINS app setting.
_NOISE = {"w3.org", "schema.org", "microsoft.com", "office.com", "sharepoint.com",
          "windows.net", "teams.microsoft.com", "example.org",
          "kaspersky.com", "securelist.com", "mitre.org", "virustotal.com",
          "googletagmanager.com", "gstatic.com", "akismet.com",
          "twitter.com", "facebook.com", "linkedin.com", "youtube.com"}


def _all_noise() -> set[str]:
    return _NOISE | {d.lower().lstrip(".") for d in cfg.EXTRACT_NOISE_DOMAINS()}


class _TextFromHTML(HTMLParser):
    def __init__(self):
        super().__init__()
        self.chunks: list[str] = []
        self.links: list[str] = []

    def handle_data(self, d):
        self.chunks.append(d)

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.links.append(v)

    def text(self):
        return " ".join(self.chunks)


def html_to_text(html: str) -> tuple[str, list[str]]:
    p = _TextFromHTML()
    try:
        p.feed(html)
    except Exception:
        return html, []
    return p.text(), p.links


# Filenames like RegAsm.exe or install.res.1033.dll match the domain pattern;
# filter anything whose "TLD" is really a file extension. (Trade-off: rare
# real TLDs like .sh/.md/.py are filtered too — add such domains manually.)
_FILE_EXTS = {"exe", "dll", "ps1", "vbs", "bat", "cmd", "msi", "zip", "rar",
              "html", "htm", "php", "aspx", "js", "json", "xml", "csv", "txt",
              "doc", "docx", "xls", "xlsx", "pdf", "png", "jpg", "jpeg", "gif",
              "svg", "ico", "css", "cfg", "config", "ini", "log", "tmp", "dat",
              "bin", "sys", "py", "sh", "md", "yml", "yaml", "conf", "lnk"}


def _looks_like_filename(domain: str) -> bool:
    return domain.rsplit(".", 1)[-1].lower() in _FILE_EXTS


def _noise(domain: str) -> bool:
    d = domain.lower()
    return any(d == n or d.endswith("." + n) for n in _all_noise())


def extract_from_text(text: str, source: str) -> list[dict]:
    text = refang(text)
    found: dict[tuple[str, str], dict] = {}

    def add(t, v):
        v = v.strip().rstrip(".,;")
        if is_valid(t, v):
            found.setdefault((t, v.lower()), {"type": t, "value": v, "source": source})

    for m in RX_URL.findall(text):
        host = re.sub(r"^https?://", "", m, flags=re.I).split("/")[0].split(":")[0]
        if not _noise(host):
            add("url", m)
    for m in RX_HASH.findall(text):
        add("hash", m)
    for m in RX_EMAIL.findall(text):
        add("email", m)
    for m in RX_IPV4.findall(text):
        add("ip", m)
    for m in RX_IPV6.findall(text):
        if ip_version(m) == 6:
            add("ip", m)

    urls = {v["value"].lower() for v in found.values() if v["type"] == "url"}
    emails = {v["value"].lower() for v in found.values() if v["type"] == "email"}
    for m in RX_DOMAIN.findall(text):
        d = m.lower()
        if _noise(d) or _looks_like_filename(d):
            continue
        if any(d in u for u in urls) or any(d in e for e in emails):
            continue  # already represented by a URL/email indicator
        add("domain", m)

    return list(found.values())


def extract_from_advisory(adv: dict, teams=None) -> list[dict]:
    """adv: stored advisory blob. teams: TeamsService for attachment download."""
    items: list[dict] = []

    body_html = adv.get("body_html") or ""
    body_text = adv.get("body_text") or ""
    text, links = (html_to_text(body_html) if body_html else (body_text, []))
    items += extract_from_text(text, "message body")

    # Linked HTML pages (opt-in, allow-listed — configured, not coded)
    if cfg.EXTRACT_FETCH_LINKS():
        allow = cfg.EXTRACT_LINK_ALLOWLIST()
        for link in links[:10]:
            try:
                host = re.sub(r"^https?://", "", link, flags=re.I).split("/")[0].lower()
                if allow and not any(host == a or host.endswith("." + a) for a in allow):
                    continue
                r = requests.get(link, timeout=cfg.HTTP_TIMEOUT(),
                                 stream=True, headers={"User-Agent": "ioc-portal"})
                raw = r.raw.read(cfg.EXTRACT_MAX_BYTES(), decode_content=True)
                page_text, _ = html_to_text(raw.decode("utf-8", "ignore"))
                items += extract_from_text(page_text, f"linked page: {host}")
            except Exception:
                continue

    # Attachments (csv/txt/html/json parsed as text)
    for att in adv.get("attachments", []):
        try:
            content = None
            if teams and att.get("contentUrl"):
                content = teams.download_attachment(att["contentUrl"])
            if content is None:
                continue
            name = (att.get("name") or "attachment").lower()
            if name.endswith((".csv", ".txt", ".json", ".html", ".htm", ".md", ".xml")):
                body = content.decode("utf-8", "ignore")
                if name.endswith((".html", ".htm")):
                    body, _ = html_to_text(body)
                items += extract_from_text(body, f"attachment: {att.get('name')}")
        except Exception:
            continue

    # de-dupe across sources
    dedup: dict[tuple[str, str], dict] = {}
    for it in items:
        dedup.setdefault((it["type"], it["value"].lower()), it)
    return list(dedup.values())
