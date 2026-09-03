"""Email notifications — two selectable delivery providers, chosen by
EMAIL_USING_WEBHOOK / EMAIL_USING_GRAPH (see shared/config.py). Exactly one
must be enabled; validate_email_config() enforces this before any send.

Two callers:
  notify_admins()      - operational alerts (e.g. CA exclusion changes)
  notify_submission()  - per-submission summary to the submitter + SOC team

Neither ever raises. A notification failing must never fail the action that
triggered it — for a submission, the indicators are already distributed by
the time this runs, so an unsent email is a reporting problem, not a
security one. A configuration problem is logged as a clear error instead.
"""
import logging

import requests

from . import config as cfg

GRAPH = "https://graph.microsoft.com/v1.0"

# Cached for the lifetime of a warm worker — avoids a fresh OAuth round-trip
# on every single email when using the Graph provider.
_token_cache: dict[str, str | None] = {"token": None}


def _esc(v) -> str:
    """Minimal HTML-escape for values that end up inside the email body — an
    IOC value (a URL especially) can legitimately contain '<', '&', etc.,
    and those must not be interpreted as markup in the rendered email."""
    return (str(v) if v is not None else "").replace("&", "&amp;").replace(
        "<", "&lt;").replace(">", "&gt;")


def _defang(value: str, ioc_type: str) -> str:
    """Breaks a URL/domain/email's pattern so mail clients (Outlook in
    particular) do NOT auto-detect and auto-link it, independent of any
    HTML markup — auto-linking happens from plain text alone, so escaping
    HTML characters (_esc, above) has no effect on it. An accidental click
    on a live phishing URL emailed by the very tool meant to block it would
    defeat the purpose of the notification.

    Uses the same hxxp:// / [.] convention already used elsewhere in this
    app (see extractor.py's refang()) so anyone reading these emails
    recognises the format immediately. IP addresses and hashes are left
    untouched — neither is a clickable pattern mail clients auto-link.
    """
    if ioc_type not in ("url", "domain", "email"):
        return value
    v = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    v = v.replace(".", "[.]")
    if ioc_type == "email":
        v = v.replace("@", "[at]")
    return v


def _token() -> str | None:
    if _token_cache["token"]:
        return _token_cache["token"]
    tenant, client_id, secret = (cfg.GRAPH_MAIL_TENANT_ID(), cfg.GRAPH_MAIL_CLIENT_ID(),
                                  cfg.GRAPH_MAIL_CLIENT_SECRET())
    if not (tenant and client_id and secret):
        return None
    r = requests.post(
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        data={"client_id": client_id, "client_secret": secret,
              "scope": "https://graph.microsoft.com/.default",
              "grant_type": "client_credentials"},
        timeout=cfg.HTTP_TIMEOUT())
    r.raise_for_status()
    _token_cache["token"] = r.json()["access_token"]
    return _token_cache["token"]


def _render_subject(template: str, **fields) -> str:
    """Renders the configured EMAIL_SUBJECT. A plain fixed string (the
    example in the requirement, e.g. "IOC Distribution Notification")
    passes through completely unchanged — no placeholders required. If the
    operator DOES include known placeholders (count, ioc_type, reference,
    date), they're substituted; unknown/malformed placeholders are left
    literally in the string rather than raising, since a typo in a subject
    template must never block a real notification from being sent."""
    class _Safe(dict):
        def __missing__(self, key):
            return "{" + key + "}"
    try:
        return template.format_map(_Safe(**fields))
    except Exception:
        return template


def _recipients(addresses: list[str]) -> list[dict]:
    return [{"emailAddress": {"address": a}} for a in addresses if a]


def _send_via_graph(subject: str, html_body: str, to: list[str], cc: list[str] | None = None) -> bool:
    """Sends directly via Microsoft Graph. Only ever called when
    EMAIL_USING_GRAPH is true — the webhook path never reaches this
    function, and this function never falls through to the webhook."""
    from_addr = cfg.MAIL_FROM_ADDRESS()
    if not from_addr:
        logging.warning("MAIL_FROM_ADDRESS not configured — email skipped: %s", subject)
        return False
    token = _token()
    if not token:
        logging.warning("Graph mail credentials not configured — email skipped: %s", subject)
        return False

    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": html_body},
            "toRecipients": _recipients(to),
            "ccRecipients": _recipients(cc or []),
        },
        "saveToSentItems": True,
    }

    def _post(bearer: str):
        return requests.post(
            f"{GRAPH}/users/{from_addr}/sendMail",
            headers={"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"},
            json=payload, timeout=cfg.HTTP_TIMEOUT())

    try:
        r = _post(token)
        if r.status_code == 401:
            _token_cache["token"] = None
            fresh = _token()
            if not fresh:
                return False
            r = _post(fresh)
        if not r.ok:
            logging.warning("sendMail returned HTTP %s: %s", r.status_code, r.text[:300])
        return r.ok
    except requests.RequestException:
        logging.exception("email send failed (Graph): %s", subject)
        return False


def _send_via_webhook(subject: str, html_body: str, to: list[str], cc: list[str] | None = None) -> bool:
    """POSTs to EMAIL_WEBHOOK_URL — an Azure Automation runbook webhook that
    reads WebhookData.RequestBody and sends via Graph itself. Field names
    below match that runbook's exact expectations (MailFrom/MailTo/
    MailSubject/MailBody/CCRecipient) — the runbook does its own
    $MailTo -split "," parsing, so To/Cc are sent as comma-separated
    strings, not JSON arrays. Only ever called when EMAIL_USING_WEBHOOK is
    true — the Graph path never reaches this function, and this function
    never falls through to Graph."""
    url = cfg.EMAIL_WEBHOOK_URL()
    if not url:
        logging.warning("EMAIL_WEBHOOK_URL not configured — email skipped: %s", subject)
        return False
    from_addr = cfg.MAIL_FROM_ADDRESS()
    if not from_addr:
        logging.warning("MAIL_FROM_ADDRESS not configured — email skipped: %s", subject)
        return False
    try:
        r = requests.post(url, json={
            "MailFrom": from_addr,
            "MailTo": ",".join(to),
            "MailSubject": subject,
            "MailBody": html_body,
            "CCRecipient": ",".join(cc) if cc else None,
        }, timeout=cfg.HTTP_TIMEOUT())
        if not r.ok:
            logging.warning("webhook returned HTTP %s: %s", r.status_code, r.text[:300])
        return r.ok
    except requests.RequestException:
        logging.exception("email send failed (webhook): %s", subject)
        return False


def _send(subject: str, html_body: str, to: list[str], cc: list[str] | None = None) -> bool:
    """Provider dispatcher — sends via exactly ONE of webhook/Graph, never
    both, and never falls back from one to the other. Config validation
    (exactly one provider enabled, required fields present) is enforced
    here rather than left to crash mid-send. Deliberately never raises —
    same principle as every other function in this module: a notification
    problem must never fail the action that triggered it. A misconfiguration
    is logged as a clear error instead of a silent no-op or a crash."""
    try:
        cfg.validate_email_config()
    except RuntimeError as e:
        logging.error("email not sent — %s", e)
        return False

    if cfg.EMAIL_USING_WEBHOOK():
        return _send_via_webhook(subject, html_body, to, cc)
    return _send_via_graph(subject, html_body, to, cc)


def notify_admins(subject: str, lines: list[str]) -> bool:
    recipients = cfg.SOC_NOTIFY_EMAILS()
    if not recipients:
        logging.warning("no SOC_NOTIFY_EMAILS configured — admin notification skipped: %s", subject)
        return False
    html = "".join(f"<p>{_esc(line)}</p>" for line in lines)
    return _send(subject, html, to=recipients)


# Outcome banner: colour + wording driven by the ACTUAL result, not just
# "an email is being sent" — a partial success must not look identical to a
# full success, and a fully-failed batch (rare here, since this only fires
# when at least one value succeeded) still gets an honest amber/red state.
_STATUS_STYLE = {
    "all_ok":      ("#e8f5ee", "#cdebd9", "#1e7d43", "&#10003; Distribution confirmed", "all selected platforms succeeded"),
    "partial":     ("#fdf3e3", "#f3ddad", "#8a5a00", "&#9888; Partially distributed", "some platforms did not succeed — see status per value below"),
    "all_failed":  ("#fbe9e9", "#f3caca", "#a33131", "&#10007; Distribution failed", "no platform confirmed this submission"),
    "no_platforms": ("#fdf3e3", "#f3ddad", "#8a5a00", "&#9888; No platforms dispatched", "the submission was recorded but nothing was sent"),
}


def notify_submission(submitted_by: str, ioc_type: str, date: str, reference: str,
                      summary: dict, value_details: list[dict],
                      extra_cc: list[str] | None = None) -> bool:
    """Email a submission summary to the submitter and the SOC team.

    value_details: [{'value': str, 'portals': [platform ids that succeeded
    for this specific value]}] — per-value detail, not just the aggregate
    outcome, since a batch can partially succeed.

    extra_cc: optional analyst-supplied addresses (from the form's optional
    "Additional email" field) — added to Cc alongside the submitter, never
    replacing SOC_NOTIFY_EMAILS. Already validated as email-shaped by the
    caller; anything malformed is filtered out again here defensively.
    """
    if not cfg.NOTIFY_ON_SUBMIT():
        return False

    recipients = list(cfg.SOC_NOTIFY_EMAILS())
    # The submitter's identity comes from Entra ID via the proxy, so it is
    # normally their UPN (an address). Only treat it as a recipient if it
    # looks like one — a display name would just bounce.
    submitter_addr = submitted_by if submitted_by and "@" in submitted_by else None
    if not recipients and not submitter_addr:
        logging.warning("no notification recipients configured — submission email skipped")
        return False

    to = recipients if recipients else [submitter_addr]

    cc: list[str] = []
    if submitter_addr and submitter_addr not in to:
        cc.append(submitter_addr)
    for addr in (extra_cc or []):
        addr = (addr or "").strip()
        if addr and "@" in addr and addr not in to and addr not in cc:
            cc.append(addr)

    status = (summary or {}).get("status", "unknown")
    bg, border, text, headline, subtext = _STATUS_STYLE.get(
        status, ("#eef2f7", "#dde3e9", "#4a5560", "Submission recorded", ""))

    all_selected = sorted(set().union(*[v.get("portals_selected", []) for v in value_details]) or [])
    rows = "".join(
        f'<tr><td style="padding:9px 12px;font-family:Consolas,monospace;'
        f'font-size:12.5px;color:#1a2733;border-bottom:1px solid #eef1f4;">'
        f'{_esc(_defang(v["value"], ioc_type))}</td>'
        f'<td style="padding:9px 12px;text-align:right;border-bottom:1px solid #eef1f4;">'
        f'<span style="color:{"#1e7d43" if v.get("portals_succeeded") else "#a33131"};font-size:12px;">'
        f'{"&#10003; " + _esc(", ".join(v["portals_succeeded"])) if v.get("portals_succeeded") else "&#10007; not distributed"}'
        f'</span></td></tr>'
        for v in value_details
    )

    all_failures = [(v["value"], f["portal"], f["reason"])
                    for v in value_details for f in v.get("failures", [])]
    if all_failures:
        grouped: dict[tuple[str, str], list[str]] = {}
        order: list[tuple[str, str]] = []
        for val, portal, reason in all_failures:
            key = (val, reason)
            if key not in grouped:
                grouped[key] = []
                order.append(key)
            grouped[key].append(portal)

        failure_rows = "".join(
            f'<tr><td style="padding:9px 12px;font-family:Consolas,monospace;'
            f'font-size:12.5px;color:#1a2733;border-bottom:1px solid #eef1f4;">{_esc(_defang(val, ioc_type))}</td>'
            f'<td style="padding:9px 12px;font-size:12.5px;color:#1a2733;border-bottom:1px solid #eef1f4;">{_esc(", ".join(grouped[(val, reason)]))}</td>'
            f'<td style="padding:9px 12px;font-size:12px;color:#a33131;border-bottom:1px solid #eef1f4;">{_esc(reason)}</td></tr>'
            for val, reason in order
        )
        failures_block = f"""
        <tr><td style="padding:20px 28px 8px;">
          <div style="font-size:11px;font-weight:600;color:#8a95a1;letter-spacing:.4px;margin-bottom:8px;">FAILURES ({len(order)})</div>
          <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border:1px solid #f3caca;border-radius:4px;overflow:hidden;">
            <tr style="background:#fbe9e9;">
              <td style="padding:8px 12px;font-size:11px;font-weight:600;color:#a33131;border-bottom:1px solid #f3caca;">VALUE</td>
              <td style="padding:8px 12px;font-size:11px;font-weight:600;color:#a33131;border-bottom:1px solid #f3caca;">PLATFORM</td>
              <td style="padding:8px 12px;font-size:11px;font-weight:600;color:#a33131;border-bottom:1px solid #f3caca;">REASON</td>
            </tr>
            {failure_rows}
          </table>
        </td></tr>"""
    else:
        failures_block = """
        <tr><td style="padding:20px 28px 8px;">
          <div style="font-size:11px;font-weight:600;color:#8a95a1;letter-spacing:.4px;margin-bottom:8px;">FAILURES</div>
          <div style="background:#e8f5ee;border:1px solid #cdebd9;border-radius:4px;padding:10px 14px;font-size:12.5px;color:#1e7d43;">
            No failures &mdash; every selected platform succeeded for every value.
          </div>
        </td></tr>"""

    html = f"""
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f3f5;padding:24px 0;font-family:'Segoe UI',Arial,sans-serif;">
    <tr><td align="center">
    <table role="presentation" width="640" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid #d8dde3;border-radius:6px;overflow:hidden;">

      <tr><td style="background:#1a2733;padding:14px 28px;">
        <table role="presentation" cellpadding="0" cellspacing="0"><tr>
          <td style="padding-left:10px;vertical-align:middle;">
            <div><span style="color:#4e8cff;font-size:15px;font-weight:700;letter-spacing:.03em;">EZ</span><span style="color:#ffffff;font-size:15px;font-weight:700;letter-spacing:.03em;">IOCHUB</span></div>
            <div style="color:#8b98a9;font-size:9.5px;font-weight:500;letter-spacing:.06em;text-transform:uppercase;margin-top:2px;">Routing Intel. Strengthening Defenses</div>
          </td>
        </tr></table>
      </td></tr>

      <tr><td style="background:{bg};border-bottom:1px solid {border};padding:10px 28px;">
        <span style="color:{text};font-size:13px;font-weight:600;">{headline}</span>
        <span style="color:{text};font-size:12px;opacity:.85;"> &mdash; {_esc(subtext)}</span>
      </td></tr>

      <tr><td style="padding:24px 28px 8px;">
        <div style="font-size:18px;font-weight:600;color:#1a2733;margin-bottom:4px;">Indicator submitted for distribution</div>
        <div style="font-size:13px;color:#65717c;">Reference {_esc(reference)} &middot; {_esc(date)}</div>
      </td></tr>

      <tr><td style="padding:16px 28px 0;">
        <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:13px;">
          <tr><td width="140" style="padding:8px 0;color:#8a95a1;border-bottom:1px solid #eef1f4;">Submitted by</td>
              <td style="padding:8px 0;color:#1a2733;border-bottom:1px solid #eef1f4;">{_esc(submitted_by)}</td></tr>
          <tr><td style="padding:8px 0;color:#8a95a1;border-bottom:1px solid #eef1f4;">Indicator type</td>
              <td style="padding:8px 0;color:#1a2733;border-bottom:1px solid #eef1f4;">
                <span style="background:#eef2f7;border-radius:3px;padding:2px 8px;font-family:Consolas,monospace;font-size:11px;">{_esc(ioc_type.upper())}</span>
              </td></tr>
          <tr><td style="padding:8px 0;color:#8a95a1;border-bottom:1px solid #eef1f4;">Platforms</td>
              <td style="padding:8px 0;color:#1a2733;border-bottom:1px solid #eef1f4;">{_esc(", ".join(all_selected)) or "&mdash;"}</td></tr>
          <tr><td style="padding:8px 0;color:#8a95a1;">Reference</td>
              <td style="padding:8px 0;color:#1a2733;font-family:Consolas,monospace;">{_esc(reference)}</td></tr>
        </table>
      </td></tr>

      <tr><td style="padding:20px 28px 8px;">
        <div style="font-size:11px;font-weight:600;color:#8a95a1;letter-spacing:.4px;margin-bottom:8px;">SUBMITTED VALUES ({len(value_details)})</div>
        <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border:1px solid #e4e8ec;border-radius:4px;overflow:hidden;">
          <tr style="background:#f8f9fa;">
            <td style="padding:8px 12px;font-size:11px;font-weight:600;color:#65717c;border-bottom:1px solid #e4e8ec;">VALUE</td>
            <td style="padding:8px 12px;font-size:11px;font-weight:600;color:#65717c;border-bottom:1px solid #e4e8ec;" align="right">STATUS</td>
          </tr>
          {rows}
        </table>
      </td></tr>
      {failures_block}

      <tr><td style="padding:20px 28px 24px;">
        <div style="font-size:11.5px;color:#96a0aa;line-height:1.5;">
          This is an automated notification from EZ IOCHUB. No action is required.
          If you did not initiate this submission, contact the SOC team immediately.
        </div>
      </td></tr>

      <tr><td style="background:#f8f9fa;border-top:1px solid #e4e8ec;padding:12px 28px;">
        <span style="font-size:10.5px;color:#a4adb6;">EZ IOCHUB &middot; Routing Intel. Strengthening Defenses</span>
      </td></tr>

    </table>
    </td></tr>
    </table>
    """
    # Subject comes from configuration, not hard-coded — a plain
    # EMAIL_SUBJECT value is used as-is; known placeholders are optional.
    subject = _render_subject(
        cfg.EMAIL_SUBJECT(), count=len(value_details), ioc_type=ioc_type,
        reference=reference, date=date)
    return _send(subject, html, to=to, cc=cc)
