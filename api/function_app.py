"""IOC Distribution Portal — API (Azure Functions, Python v2 model).

All requests arrive via the App Service proxy (users cannot reach this app
directly); identity comes from x-portal-* headers it injects. Role checks
use the "permissions" map from the runtime config (blob-tunable).

Routes:
  GET  /api/config                   runtime-tunable config for the UI
  GET  /api/iocs                     inventory (reference-store CSV)
  GET  /api/iocs/export              CSV download (export-permitted roles only)
  POST /api/iocs                     add indicators -> platforms + CSV
  POST /api/iocs/delete              delete selected indicators -> platforms + CSV
  GET  /api/advisories               mirrored Teams advisories
  GET  /api/advisories/{id}          one advisory (full body)
  POST /api/advisories/{id}/extract  extract IOCs from body/links/attachments
  POST /api/push                     push extracted IOCs to chosen platforms
Timers:
  teams_poll                         mirrors new posts from the SOC channel
                                     (cadence = TEAMS_POLL_CRON app setting)
  ca_policy_watch                    alerts admins (webhook -> email) on new
                                     Conditional Access exclusions
                                     (cadence = CA_WATCH_CRON app setting)
"""
import json
import logging

import azure.functions as func

from shared import config as cfg
from shared.auth import AuthError, error_response, principal, require_roles
from shared.connectors import dispatch
from shared.extractor import extract_from_advisory
from shared.internal_check import find_internal
from shared.ca_watch import check_ca_exclusions
from shared.notify import notify_admins
from shared.notify import notify_submission
from shared.storage import Storage
from shared.teams import TeamsService
from shared.validators import VALID_TYPES, has_internal_whitespace, validate_batch

app = func.FunctionApp()

_json = lambda body, status=200: func.HttpResponse(
    json.dumps(body), status_code=status, mimetype="application/json")


def _perm_roles(storage: Storage, action: str) -> list[str]:
    """Roles allowed to perform an action — from runtime config (blob-tunable)."""
    return (cfg.runtime_config(storage).get("permissions") or {}).get(action, [])


def _summarize(results: list[dict]) -> dict:
    """Roll per-platform results up into an overall status so the caller can
    never mistake 'the HTTP call succeeded' for 'the indicators actually went
    anywhere'. A platform being disabled/misconfigured/erroring all count as
    a failure here — nothing is swallowed as a silent success."""
    ok = [r for r in results if r.get("ok")]
    failed = [r for r in results if not r.get("ok")]
    if not results:
        status = "no_platforms"
    elif not failed:
        status = "all_ok"
    elif not ok:
        status = "all_failed"
    else:
        status = "partial"
    return {"status": status, "ok_count": len(ok), "failed_count": len(failed)}


@app.route(route="config", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def get_config(req: func.HttpRequest) -> func.HttpResponse:
    try:
        principal(req)  # any assigned role may read config
        return _json(cfg.runtime_config(Storage()))
    except AuthError as e:
        return error_response(e)


# --------------------------------------------------------------------------
# IOC inventory + add + delete
# --------------------------------------------------------------------------
@app.route(route="iocs", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def list_iocs(req: func.HttpRequest) -> func.HttpResponse:
    """Inventory tab data. Gated behind 'viewInventory' — a role without it
    gets a 403 here even if it somehow calls this directly; the hidden tab
    in the UI is a courtesy, not the actual boundary."""
    try:
        storage = Storage()
        require_roles(req, _perm_roles(storage, "viewInventory"))
        return _json({"items": storage.list_iocs()})
    except AuthError as e:
        return error_response(e)


@app.route(route="iocs", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def add_iocs(req: func.HttpRequest) -> func.HttpResponse:
    try:
        storage = Storage()
        # Fetch the runtime-config blob ONCE for this whole request —
        # permissions, service codes, and platform-type support all live in
        # this same small blob. Re-fetching it per-check (the platform-type
        # validation was doing this on top of the existing permission
        # check) added a redundant blob read to every submission — this was
        # the actual cause of the recent slowdown, not the CSV/dispatch
        # optimizations, which are genuinely faster in isolation.
        rc = cfg.runtime_config(storage)
        who = require_roles(req, (rc.get("permissions") or {}).get("add", []))
        body = req.get_json()
        ioc_type = body.get("ioc_type", "")
        portals = body.get("portals") or []
        service = (body.get("service") or "").strip().upper()
        if service and not portals:
            portals = (rc.get("serviceCodes") or {}).get(service) or []
            if not portals:
                raise AuthError(f"Unknown service code '{service}'.", 400)
        if ioc_type not in VALID_TYPES:
            raise AuthError(f"Unknown indicator type '{ioc_type}'.", 400)
        if not portals:
            raise AuthError("Choose at least one target platform.", 400)

        # Per-platform type support — validated BEFORE anything is attempted,
        # not discovered only after dispatch as a silent "not applicable".
        platform_types = rc.get("platformTypes") or {}
        unsupported = [p for p in portals if ioc_type not in (platform_types.get(p) or [])]
        if unsupported:
            names = {"crowdstrike": "CrowdStrike", "sentinel": "Microsoft Sentinel",
                     "proofpoint": "Proofpoint", "zscaler": "Zscaler"}
            raise AuthError(
                f"{ioc_type} is not supported on: "
                + ", ".join(names.get(p, p) for p in unsupported)
                + " — unselect the unsupported platform(s) or change the indicator type.", 400)

        raw_values = body.get("values") or []
        spaced = [v for v in raw_values if v.strip() and has_internal_whitespace(v)]
        if spaced:
            raise AuthError(
                f"Value(s) contain a space or other whitespace inside them — "
                f"an indicator must be one continuous value with no internal "
                f"spaces: {', '.join(spaced[:5])}", 400)

        good, bad = validate_batch(ioc_type, raw_values)
        if bad:
            raise AuthError(f"Invalid {ioc_type} value(s): {', '.join(bad[:5])}", 400)
        if not good:
            raise AuthError("No indicator values supplied.", 400)

        meta = {"reference": (body.get("reference") or "").strip()[:200],
                "date": (body.get("date") or "").strip(), "added_by": who["user"]}
        if not meta["reference"]:
            if cfg.REFERENCE_REQUIRED():
                raise AuthError("Reference is required.", 400)
        else:
            import re as _re
            if not _re.match(cfg.REFERENCE_PATTERN(), meta["reference"]):
                raise AuthError("Reference must contain letters and numbers only "
                                "(no spaces or punctuation).", 400)
        if not meta["date"]:
            raise AuthError("Date is required.", 400)

        # CrowdStrike Action — type-conditional, per Falcon's actual API
        # constraints (confirmed by testing: a "prevent" submission for an
        # IP returned HTTP 400). Only hash indicators support more than
        # "detect", so only hash submissions require/accept a chosen action;
        # ip/domain are set automatically and the field is not required.
        if "crowdstrike" in portals:
            if ioc_type == "hash":
                allowed_hash_actions = set(cfg.FALCON_HASH_ACTION_VALUES())
                falcon_action = (body.get("falconAction") or "").strip().lower()
                if not falcon_action:
                    raise AuthError("A CrowdStrike action (Block / Detect Only / Block + Hide "
                                    "Detection) is required for hash indicators when CrowdStrike "
                                    "is a selected platform.", 400)
                if falcon_action not in allowed_hash_actions:
                    raise AuthError(f"Unknown CrowdStrike action '{falcon_action}'.", 400)
                meta["falcon_action"] = falcon_action
            else:
                # ip / domain — Falcon only supports detect for these types;
                # no dropdown, no analyst choice, always this fixed value.
                meta["falcon_action"] = cfg.FALCON_NON_HASH_ACTION()

        # Optional extra CC recipient(s) for the submission notification —
        # comma-separated, free text, so validated here like any other
        # user input rather than trusted as-is when it reaches notify.py.
        import re as _re2
        _EMAIL_RE = _re2.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")
        raw_extra = (body.get("extraEmail") or "").strip()
        extra_cc, bad_extra = [], []
        if raw_extra:
            for addr in [a.strip() for a in raw_extra.split(",") if a.strip()]:
                (extra_cc if _EMAIL_RE.match(addr) else bad_extra).append(addr)
        if bad_extra:
            raise AuthError(f"Additional email address is not valid: {', '.join(bad_extra[:5])}", 400)
            
        from datetime import date as _date
        if meta["date"] != _date.today().isoformat():
            raise AuthError("Date must be today — backdated or future-dated entries aren't permitted.", 400)
        items = [{"type": ioc_type, "value": v} for v in good]

        storage.ensure_containers()
        # Internal-environment validation: submissions containing internal
        # assets are rejected outright — the analyst must remove them.
        internal = find_internal(storage, items)
        if internal:
            raise AuthError("Internal asset value(s) detected: "
                            + ", ".join(f"{b['value']} ({b['reason']})" for b in internal[:10])
                            + " — remove them and try again.", 400)

        # Per-value, per-platform duplicate check: a value is only "nothing
        # left to do" if EVERY requested platform is already confirmed for
        # it. A value confirmed on Sentinel but not CrowdStrike still has
        # work to do — it's included, but only dispatched to CrowdStrike;
        # Sentinel is never touched again.
        groups: dict[tuple, list[dict]] = {}   # missing-platforms tuple -> items
        fully_done: list[str] = []
        active_lookup = storage.get_active_portals_bulk(items)
        for it in items:
            already = active_lookup[(it["type"], it["value"].strip().lower())]
            missing = tuple(sorted(set(portals) - already))
            if not missing:
                fully_done.append(it["value"])
            else:
                groups.setdefault(missing, []).append(it)

        if not groups:
            raise AuthError("Already distributed to every selected platform: "
                            + ", ".join(fully_done[:10])
                            + " — remove them and try again.", 409)

        # Dispatch each group to only the platforms it actually still needs;
        # merge same-platform results together for one clean summary.
        merged: dict[str, dict] = {}
        for missing_portals, group_items in groups.items():
            for r in dispatch("add", list(missing_portals), group_items, meta):
                p = r["portal"]
                if p not in merged:
                    merged[p] = r
                else:
                    merged[p]["ok"] = merged[p]["ok"] and r["ok"]
                    merged[p]["detail"] = (merged[p]["detail"] + "; " + r["detail"])[:400]
        results = list(merged.values())

        # Platforms already confirmed for EVERY item in this submission were
        # correctly never dispatched (see the "missing" computation above) —
        # but that means they'd otherwise be invisible in the result popup,
        # looking like they were simply forgotten rather than intentionally
        # skipped. Add an explicit row for each so "already distributed" is
        # shown, not silently omitted. Only added if that platform wasn't
        # ALSO dispatched for some other item in the same batch — a portal
        # that's a real dispatch target elsewhere in this submission keeps
        # its real result, not a synthetic one.
        dispatched_portals = {r["portal"] for r in results}
        already_confirmed_everywhere = set(portals) - set().union(*groups.keys()) if groups else set(portals)
        for p in sorted(already_confirmed_everywhere - dispatched_portals):
            results.append({"portal": p, "ok": True, "detail": "already distributed"})

        summary = _summarize(results)

        # Record ONLY the platforms that actually succeeded, per value —
        # never the ones that failed or weren't attempted this round. A
        # value that failed on every platform gets no row at all.
        ok_portals = {r["portal"] for r in results if r.get("ok")}
        updates = []
        for missing_portals, group_items in groups.items():
            succeeded_here = [p for p in missing_portals if p in ok_portals]
            if not succeeded_here:
                continue
            for it in group_items:
                updates.append({
                    "ioc_type": it["type"], "ioc_value": it["value"],
                    "added_by": who["user"], "date": meta["date"],
                    "reference": meta["reference"], "succeeded_portals": succeeded_here,
                })
        storage.merge_portal_success(updates)
        added = len({u["ioc_value"].lower() for u in updates})
        # Notify the submitter + SOC team. Wrapped so a webhook problem can
        # never fail a submission whose indicators are already distributed.
        if added:
            try:
                # Per-value success is already tracked (updates); build the
                # matching per-value FAILURE list against the full originally
                # -selected platform set, using the real per-platform detail
                # from dispatch — not just "it wasn't in the success list".
                fail_detail = {r["portal"]: (r.get("detail") or "no detail returned")
                               for r in results if not r.get("ok")}
                value_details = []
                for u in updates:
                    succeeded = set(u["succeeded_portals"])
                    failed = [{"portal": p, "reason": fail_detail.get(p, "not attempted")}
                             for p in portals if p not in succeeded]
                    value_details.append({
                        "value": u["ioc_value"],
                        "portals_selected": sorted(portals),
                        "portals_succeeded": sorted(succeeded),
                        "failures": failed,
                    })
                notify_submission(
                    submitted_by=who["user"], ioc_type=ioc_type,
                    date=meta["date"], reference=meta["reference"],
                    summary=summary, value_details=value_details,
                    extra_cc=extra_cc)
            except Exception:
                logging.exception("submission notification failed (submission itself succeeded)")

        return _json({"results": results, "summary": summary, "stored": added > 0,
                      "added": added, "already_complete": fully_done})
    except AuthError as e:
        return error_response(e)
    except Exception as e:
        logging.exception("add_iocs failed")
        return error_response(e)


@app.route(route="iocs/delete", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def delete_iocs(req: func.HttpRequest) -> func.HttpResponse:
    try:
        storage = Storage()
        who = require_roles(req, _perm_roles(storage, "delete"))
        body = req.get_json()
        ids = body.get("ids") or []
        if not ids:
            raise AuthError("Select at least one indicator to delete.", 400)
        if not (body.get("reference") or "").strip():
            raise AuthError("Reference is required.", 400)

        all_rows = {r["id"]: r for r in storage.list_iocs()}
        targets = [all_rows[i] for i in ids if i in all_rows and all_rows[i]["status"] == "active"]
        if not targets:
            raise AuthError("Selected indicators were not found or are already deleted.", 404)

        selected = set(body.get("portals") or [])
        per_portal: dict[str, list[dict]] = {}
        for r in targets:
            for p in r["portals"]:
                if selected and p not in selected:
                    continue
                per_portal.setdefault(p, []).append(
                    {"type": r["ioc_type"], "value": r["ioc_value"]})

        meta = {"reference": (body.get("reference") or "").strip()[:200],
                "added_by": who["user"]}
        results = []
        for pid in sorted(per_portal):
            results += dispatch("delete", [pid], per_portal[pid], meta)
        summary = _summarize(results)
        if summary["status"] == "all_ok":
            storage.mark_deleted([r["id"] for r in targets], who["user"])
            deleted = len(targets)
        else:
            deleted = 0
        return _json({"results": results, "summary": summary, "stored": summary["status"] == "all_ok",
                      "deleted": deleted})
    except AuthError as e:
        return error_response(e)
    except Exception as e:
        logging.exception("delete_iocs failed")
        return error_response(e)


@app.route(route="iocs/export", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def export_iocs(req: func.HttpRequest) -> func.HttpResponse:
    """CSV export of the reference store, filtered the same way the
    Inventory tab is."""
    try:
        storage = Storage()
        require_roles(req, _perm_roles(storage, "export"))
        import csv as _csv
        import io as _io
        cols = ["ioc_type", "ioc_value", "added_by", "date", "reference",
                "portals", "status", "submitted_at", "deleted_by", "deleted_at"]

        q = (req.params.get("q") or "").strip().lower()
        ftype = req.params.get("type") or ""
        fstatus = req.params.get("status") or ""
        date_from = req.params.get("date_from") or ""
        date_to = req.params.get("date_to") or ""

        rows = storage.list_iocs()
        if q:
            rows = [r for r in rows if q in (r.get("ioc_value") or "").lower()
                    or q in (r.get("reference") or "").lower()
                    or q in (r.get("added_by") or "").lower()]
        if ftype:
            rows = [r for r in rows if r.get("ioc_type") == ftype]
        if fstatus:
            rows = [r for r in rows if r.get("status") == fstatus]
        if date_from:
            rows = [r for r in rows if (r.get("date") or "") >= date_from]
        if date_to:
            rows = [r for r in rows if (r.get("date") or "") <= date_to]

        buf = _io.StringIO()
        w = _csv.writer(buf)
        w.writerow(cols)
        for r in rows:
            w.writerow(["|".join(r[c]) if c == "portals" else (r.get(c) or "") for c in cols])
        return func.HttpResponse(
            buf.getvalue(), status_code=200, mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=ioc-inventory.csv"})
    except AuthError as e:
        return error_response(e)
    except Exception as e:
        logging.exception("export failed")
        return error_response(e)


@app.route(route="iocs/check-internal", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def check_internal(req: func.HttpRequest) -> func.HttpResponse:
    """Pre-submit check so the UI can flag problems on the ledger BEFORE the
    confirmation popup — internal assets and values with nothing left to do
    (every requested platform already confirmed) both get flagged here as
    'blocked'. A value confirmed on Sentinel but not CrowdStrike is NOT
    blocked if CrowdStrike is among the requested platforms — it still has
    work to do. This is a convenience layer only; add_iocs/push_iocs run
    the same checks again server-side regardless of what this returns."""
    try:
        storage = Storage()
        principal(req)
        body = req.get_json()
        items = [{"type": i.get("type", ""), "value": (i.get("value") or "").strip()}
                 for i in (body.get("items") or []) if (i.get("value") or "").strip()]
        portals = body.get("portals") or []

        blocked = find_internal(storage, items)
        if portals:
            active_lookup = storage.get_active_portals_bulk(items)
            for it in items:
                already = active_lookup[(it["type"], it["value"].strip().lower())]
                if set(portals) <= already:
                    blocked.append({"value": it["value"],
                                    "reason": "already distributed to every selected platform"})
        return _json({"blocked": blocked})
    except AuthError as e:
        return error_response(e)
    except Exception as e:
        logging.exception("check_internal failed")
        return error_response(e)


# --------------------------------------------------------------------------
# Advisories (mirrored Teams channel) + extraction + push
# --------------------------------------------------------------------------
@app.route(route="advisories", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def list_advisories(req: func.HttpRequest) -> func.HttpResponse:
    """Advisories tab data. Gated behind 'viewAdvisories' — same server-side
    boundary as the Inventory tab, not just a hidden button."""
    try:
        storage = Storage()
        require_roles(req, _perm_roles(storage, "viewAdvisories"))
        return _json({"items": storage.list_advisories()})
    except AuthError as e:
        return error_response(e)


@app.route(route="advisories/{adv_id}", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def get_advisory(req: func.HttpRequest) -> func.HttpResponse:
    try:
        storage = Storage()
        require_roles(req, _perm_roles(storage, "viewAdvisories"))
        adv = storage.get_advisory(req.route_params["adv_id"])
        return _json(adv) if adv else _json({"error": "Advisory not found."}, 404)
    except AuthError as e:
        return error_response(e)


@app.route(route="advisories/{adv_id}/extract", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def extract_advisory(req: func.HttpRequest) -> func.HttpResponse:
    try:
        storage = Storage()
        require_roles(req, _perm_roles(storage, "viewAdvisories"))
        adv = storage.get_advisory(req.route_params["adv_id"])
        if not adv:
            raise AuthError("Advisory not found.", 404)
        teams = TeamsService() if adv.get("attachments") else None
        return _json({"items": extract_from_advisory(adv, teams)})
    except AuthError as e:
        return error_response(e)
    except Exception as e:
        logging.exception("extract failed")
        return error_response(e)


@app.route(route="push", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def push_iocs(req: func.HttpRequest) -> func.HttpResponse:
    try:
        storage = Storage()
        rc = cfg.runtime_config(storage)
        who = require_roles(req, (rc.get("permissions") or {}).get("add", []))
        body = req.get_json()
        portals = body.get("portals") or []
        service = (body.get("service") or "").strip().upper()
        if service and not portals:
            portals = (rc.get("serviceCodes") or {}).get(service) or []
            if not portals:
                raise AuthError(f"Unknown service code '{service}'.", 400)
        raw_items = body.get("items") or []
        if not portals:
            raise AuthError("Choose at least one target platform.", 400)

        items, by_type = [], {}
        for it in raw_items:
            t, v = it.get("type"), (it.get("value") or "").strip()
            good, _ = validate_batch(t, [v]) if t in VALID_TYPES else ([], [v])
            if good:
                items.append({"type": t, "value": good[0]})
                by_type.setdefault(t, []).append(good[0])
        if not items:
            raise AuthError("No valid indicators to push.", 400)

        ref = (body.get("reference") or "").strip()[:200]
        if not ref and body.get("advisory_id"):
            ref = f"ADV:{body['advisory_id']}"
        if not ref:
            raise AuthError("Reference is required.", 400)
        meta = {"reference": ref, "added_by": who["user"]}

        storage.ensure_containers()
        internal = find_internal(storage, items)
        if internal:
            raise AuthError("Internal asset value(s) detected: "
                            + ", ".join(f"{b['value']} ({b['reason']})" for b in internal[:10])
                            + " — unselect them and try again.", 400)

        groups: dict[tuple, list[dict]] = {}
        fully_done: list[str] = []
        active_lookup = storage.get_active_portals_bulk(items)
        for it in items:
            already = active_lookup[(it["type"], it["value"].strip().lower())]
            missing = tuple(sorted(set(portals) - already))
            if not missing:
                fully_done.append(it["value"])
            else:
                groups.setdefault(missing, []).append(it)

        if not groups:
            raise AuthError("Already distributed to every selected platform: "
                            + ", ".join(fully_done[:10])
                            + " — unselect them and try again.", 409)

        merged: dict[str, dict] = {}
        for missing_portals, group_items in groups.items():
            for r in dispatch("add", list(missing_portals), group_items, meta):
                p = r["portal"]
                if p not in merged:
                    merged[p] = r
                else:
                    merged[p]["ok"] = merged[p]["ok"] and r["ok"]
                    merged[p]["detail"] = (merged[p]["detail"] + "; " + r["detail"])[:400]
        results = list(merged.values())
        summary = _summarize(results)

        from datetime import date, datetime, timezone
        ok_portals = {r["portal"] for r in results if r.get("ok")}
        updates = []
        for missing_portals, group_items in groups.items():
            succeeded_here = [p for p in missing_portals if p in ok_portals]
            if not succeeded_here:
                continue
            for it in group_items:
                updates.append({
                    "ioc_type": it["type"], "ioc_value": it["value"],
                    "added_by": who["user"], "date": date.today().isoformat(),
                    "reference": ref, "succeeded_portals": succeeded_here,
                })
        storage.merge_portal_success(updates)
        stored_ok = len(updates) > 0

        adv_id = body.get("advisory_id")
        if adv_id:
            adv = storage.get_advisory(adv_id)
            if adv:
                adv["action_taken"] = {
                    "by": who["user"],
                    "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "portals": portals,
                    "indicators": len(items),
                }
                storage.update_advisory(adv)
        return _json({"results": results, "summary": summary, "stored": stored_ok,
                      "pushed": len({u["ioc_value"].lower() for u in updates}),
                      "already_complete": fully_done})
    except AuthError as e:
        return error_response(e)
    except Exception as e:
        logging.exception("push failed")
        return error_response(e)


# --------------------------------------------------------------------------
# Timer: mirror the SOC Teams channel into the advisory store.
# Cadence is the TEAMS_POLL_CRON app setting (e.g. "0 */5 * * * *").
# --------------------------------------------------------------------------
@app.timer_trigger(schedule="%TEAMS_POLL_CRON%", arg_name="timer", run_on_startup=False)
def teams_poll(timer: func.TimerRequest) -> None:
    try:
        storage = Storage()
        storage.ensure_containers()
        state = storage.get_state()
        last_seen = state.get("last_posted_at", "")
        newest = last_seen
        count = 0
        for adv in TeamsService().fetch_channel_messages():
            if adv["posted_at"] and adv["posted_at"] <= last_seen:
                continue
            storage.save_advisory(adv)
            newest = max(newest, adv["posted_at"])
            count += 1
        if newest != last_seen:
            storage.set_state({"last_posted_at": newest})
        if count:
            logging.info("teams_poll mirrored %d new advisories", count)
    except Exception:
        logging.exception("teams_poll failed")


# --------------------------------------------------------------------------
# Timer: Conditional Access exclusion watcher — admins get an email (via the
# Key-Vault-held webhook) whenever a user/group/application is newly added
# to a CA policy's exclusions. Cadence = CA_WATCH_CRON app setting.
# --------------------------------------------------------------------------
@app.timer_trigger(schedule="%CA_WATCH_CRON%", arg_name="timer", run_on_startup=False)
def ca_policy_watch(timer: func.TimerRequest) -> None:
    try:
        storage = Storage()
        storage.ensure_containers()
        alerts = check_ca_exclusions(storage, TeamsService())
        if alerts:
            notify_admins("Conditional Access exclusion change detected", alerts)
            logging.info("ca_policy_watch raised %d alert(s)", len(alerts))
    except Exception:
        logging.exception("ca_policy_watch failed")
