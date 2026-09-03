"""Build-gate tests for the IOC Distribution Portal backend.

These are deliberately targeted at the failure modes this project has
actually hit in production, not generic coverage:

  1. Syntax / indentation damage from manual file edits (repeatedly broke
     function_app.py and internal_check.py).
  2. A connector calling a config attribute that doesn't exist (broke
     Proofpoint at runtime: PROOFPOINT_BLOCKLIST_URL, PROOFPOINT_DELETE_ACTION).
  3. A module importing a name the connector registry no longer exports
     (looks_like_conflict).
  4. A storage method called by function_app.py that isn't defined
     (get_active_portals_bulk).

Every one of these previously reached a live environment and was only found
by a user hitting it. They now fail the build instead.
"""
import ast
import importlib
import inspect
import pathlib
import pkgutil
import re

import pytest

API_ROOT = pathlib.Path(__file__).resolve().parent.parent / "api"


# ---------------------------------------------------------------------------
# 1. Every Python file parses
# ---------------------------------------------------------------------------
def _all_py_files():
    return [
        p for p in API_ROOT.rglob("*.py")
        if ".python_packages" not in p.parts and "__pycache__" not in p.parts
    ]


@pytest.mark.parametrize("path", _all_py_files(), ids=lambda p: str(p.name))
def test_file_parses(path):
    """Catches IndentationError / SyntaxError before deploy."""
    source = path.read_text(encoding="utf-8")
    try:
        ast.parse(source)
    except SyntaxError as e:
        pytest.fail(f"{path} line {e.lineno}: {e.msg}")


# ---------------------------------------------------------------------------
# 2. Accidental implicit string concatenation inside dict literals
#    (this is what silently dropped Sentinel's validUntil + displayName)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("path", _all_py_files(), ids=lambda p: str(p.name))
def test_no_stray_triple_quoted_dict_values(path):
    """A triple-quoted string sitting where a dict key should be silently
    concatenates with the next key, producing a garbage key and dropping a
    real field. It compiles fine, so only an explicit check catches it."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key in node.keys:
                if key is None:
                    continue  # **kwargs expansion
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    if '"' in key.value or "\n" in key.value:
                        pytest.fail(
                            f"{path} line {getattr(key, 'lineno', '?')}: dict key "
                            f"{key.value[:60]!r} looks like a malformed/concatenated "
                            f"string — check for a stray triple-quoted line."
                        )


# ---------------------------------------------------------------------------
# 3. Every cfg.SOMETHING() referenced anywhere actually exists in config.py
# ---------------------------------------------------------------------------
def test_all_referenced_config_attributes_exist():
    config = importlib.import_module("shared.config")
    pattern = re.compile(r"\bcfg\.([A-Za-z_][A-Za-z0-9_]*)")
    missing = []
    for path in _all_py_files():
        if path.name == "config.py":
            continue
        for name in set(pattern.findall(path.read_text(encoding="utf-8"))):
            if not hasattr(config, name):
                missing.append(f"{path.name} references cfg.{name} (not in config.py)")
    assert not missing, "Missing config attributes:\n  " + "\n  ".join(sorted(missing))


# ---------------------------------------------------------------------------
# 4. Every shared module imports cleanly
# ---------------------------------------------------------------------------
def test_all_shared_modules_import():
    import shared
    failures = []
    for mod in pkgutil.walk_packages(shared.__path__, prefix="shared."):
        try:
            importlib.import_module(mod.name)
        except Exception as e:  # noqa: BLE001 — reporting, not handling
            failures.append(f"{mod.name}: {type(e).__name__}: {e}")
    assert not failures, "Modules failed to import:\n  " + "\n  ".join(failures)


def test_function_app_itself_imports():
    """The single most direct check: does `import function_app` succeed —
    the exact command used to verify every deploy on the server. A module
    importing cleanly on its own (previous test) does NOT guarantee a name
    another file imports FROM it still exists — a module missing a function
    still imports fine by itself; only the CALLER's `from x import y` fails.
    This test closes that gap by importing function_app.py directly, the
    same way the Azure Functions host does at startup."""
    import importlib
    import function_app  # noqa: F401 — import itself is the assertion
    importlib.reload(function_app)


def test_every_from_shared_import_name_actually_exists():
    """Statically checks every `from shared.X import a, b, c` across the
    codebase against what X actually defines — catches a file that imports
    fine on its own but is missing a name something else imports from it
    (e.g. notify.py present but missing notify_admins)."""
    import ast
    import importlib

    failures = []
    for path in _all_py_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("shared"):
                try:
                    mod = importlib.import_module(node.module)
                except Exception as e:
                    failures.append(f"{path.name}: cannot import {node.module}: {e}")
                    continue
                for alias in node.names:
                    if alias.name != "*" and not hasattr(mod, alias.name):
                        failures.append(
                            f"{path.name}: 'from {node.module} import {alias.name}' "
                            f"— {node.module} has no attribute '{alias.name}'")
    assert not failures, "Broken imports:\n  " + "\n  ".join(failures)


# ---------------------------------------------------------------------------
# 5. Connector registry is intact and every connector honours the interface
# ---------------------------------------------------------------------------
def test_connector_registry_resolves():
    from shared.connectors import get_connectors
    connectors = get_connectors()
    assert set(connectors) == {"crowdstrike", "sentinel", "proofpoint", "zscaler"}
    for pid, c in connectors.items():
        for method in ("enabled", "add", "delete"):
            assert callable(getattr(c, method, None)), f"{pid} missing {method}()"


def test_conflict_helper_exported():
    """Connector modules import this by name; if the registry stops exporting
    it, every add/delete fails at runtime with ImportError."""
    from shared.connectors import looks_like_conflict
    assert looks_like_conflict(409, "") is True
    assert looks_like_conflict(400, "already exists") is True
    assert looks_like_conflict(401, "Unauthorized") is False


# ---------------------------------------------------------------------------
# 6. Every storage.* method called by function_app.py is actually defined
# ---------------------------------------------------------------------------
def test_storage_methods_called_by_routes_exist():
    from shared.storage import Storage
    source = (API_ROOT / "function_app.py").read_text(encoding="utf-8")
    called = set(re.findall(r"\bstorage\.([a-z_][a-z0-9_]*)\s*\(", source))
    missing = [m for m in called if not hasattr(Storage, m)]
    assert not missing, f"function_app.py calls undefined Storage methods: {sorted(missing)}"


# ---------------------------------------------------------------------------
# 7. Internal-asset guard behaves as specified
# ---------------------------------------------------------------------------
def test_internal_check_exceptions_block_every_type():
    from shared.internal_check import internal_reason
    assets = {
        "cidrs": [], "domains": [], "urls": [], "emails": [], "hashes": [],
        "exceptions": ["corp.example"],
    }
    for ioc_type, value in [
        ("email", "someone@corp.example"),
        ("domain", "corp.example"),
        ("url", "https://corp.example/path"),
    ]:
        assert internal_reason(assets, ioc_type, value) is not None, \
            f"{ioc_type} {value} should be blocked by the exceptions rule"
    assert internal_reason(assets, "email", "someone@unrelated.example") is None


def test_internal_check_survives_missing_optional_keys():
    """A config blob written before 'exceptions' existed must not crash —
    checked as 'still blocks it', not the specific wording, since the
    reason string is intentionally generic across all match types."""
    from shared.internal_check import internal_reason
    legacy = {"cidrs": [], "domains": ["corp.example"], "urls": [],
              "emails": [], "hashes": []}
    assert internal_reason(legacy, "domain", "corp.example") is not None


# ---------------------------------------------------------------------------
# 8. Validators
# ---------------------------------------------------------------------------
def test_validators_accept_and_reject():
    from shared.validators import is_valid
    assert is_valid("ip", "203.0.113.45")
    assert is_valid("ip", "2001:db8::7d1")
    assert is_valid("domain", "malicious.example")
    assert is_valid("hash", "44d88612fea8a8f36de82e1278abb02f")
    assert is_valid("email", "bad@phish.example")
    assert is_valid("url", "https://phish.example/login")
    assert not is_valid("ip", "999.999.999.999")
    assert not is_valid("hash", "nothex")
    assert not is_valid("url", "ftp://phish.example")


def test_dispatch_returns_one_result_per_portal():
    """Concurrency must not drop or duplicate platform results."""
    from shared.connectors import dispatch
    portals = ["crowdstrike", "sentinel", "proofpoint", "zscaler"]
    results = dispatch("add", portals, [{"type": "ip", "value": "203.0.113.45"}], {})
    assert [r["portal"] for r in results] == portals
    assert all("ok" in r and "detail" in r for r in results)


# ---------------------------------------------------------------------------
# 9. Email notification — no credentials configured on a build agent, so
#    this only tests the parts that don't require a live Graph call.
# ---------------------------------------------------------------------------
def test_notify_disabled_by_default_sends_nothing():
    """A bare checkout must never attempt to send mail — no build agent has
    (or should have) real Graph mail credentials."""
    from shared import notify
    from unittest.mock import patch
    with patch.object(notify.requests, "post") as mock_post:
        result = notify.notify_submission(
            submitted_by="a@corp.example", ioc_type="ip",
            date="2026-01-01", reference="INC1", summary={},
            value_details=[{"value": "1.2.3.4", "portals": ["sentinel"]}])
        assert result is False
        mock_post.assert_not_called()


def test_notify_html_escapes_ioc_values():
    """An IOC value can legitimately contain '<' or '&' (e.g. a crafted
    URL) — it must never be interpreted as markup in the rendered email."""
    from shared import notify
    assert notify._esc("<script>alert(1)</script>") == \
        "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert notify._esc("Q1 & Q2") == "Q1 &amp; Q2"


# ---------------------------------------------------------------------------
# 10. Email provider configuration — mutual exclusivity, required subject,
#     and that a misconfiguration is logged, not crashed, not silently sent.
# ---------------------------------------------------------------------------
def test_email_config_rejects_both_providers_enabled(monkeypatch):
    from shared import config
    monkeypatch.setenv("NOTIFY_ON_SUBMIT", "true")
    monkeypatch.setenv("EMAIL_USING_WEBHOOK", "true")
    monkeypatch.setenv("EMAIL_USING_GRAPH", "true")
    monkeypatch.setenv("EMAIL_SUBJECT", "x")
    with __import__("pytest").raises(RuntimeError, match="both true"):
        config.validate_email_config()


def test_email_config_rejects_no_provider_enabled(monkeypatch):
    from shared import config
    monkeypatch.setenv("NOTIFY_ON_SUBMIT", "true")
    monkeypatch.setenv("EMAIL_USING_WEBHOOK", "false")
    monkeypatch.setenv("EMAIL_USING_GRAPH", "false")
    monkeypatch.setenv("EMAIL_SUBJECT", "x")
    with __import__("pytest").raises(RuntimeError, match="both false"):
        config.validate_email_config()


def test_email_config_rejects_empty_subject(monkeypatch):
    from shared import config
    monkeypatch.setenv("NOTIFY_ON_SUBMIT", "true")
    monkeypatch.setenv("EMAIL_USING_WEBHOOK", "true")
    monkeypatch.setenv("EMAIL_USING_GRAPH", "false")
    monkeypatch.setenv("EMAIL_WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setenv("EMAIL_SUBJECT", "")
    with __import__("pytest").raises(RuntimeError, match="EMAIL_SUBJECT"):
        config.validate_email_config()


def test_email_config_skipped_when_notifications_disabled(monkeypatch):
    """A misconfigured provider setup must not block anything if email
    notifications are off entirely — validation only applies when they're
    actually going to be used."""
    from shared import config
    monkeypatch.setenv("NOTIFY_ON_SUBMIT", "false")
    monkeypatch.setenv("EMAIL_USING_WEBHOOK", "true")
    monkeypatch.setenv("EMAIL_USING_GRAPH", "true")
    config.validate_email_config()  # must not raise


def test_email_provider_bypass_is_real_not_just_configured(monkeypatch):
    """The strongest version of the bypass requirement: with webhook
    selected, Graph's OWN send function must never be called, and vice
    versa — not just 'the webhook wins if both are somehow reachable'."""
    from shared import notify
    from unittest.mock import patch

    monkeypatch.setenv("NOTIFY_ON_SUBMIT", "true")
    monkeypatch.setenv("EMAIL_USING_WEBHOOK", "true")
    monkeypatch.setenv("EMAIL_USING_GRAPH", "false")
    monkeypatch.setenv("EMAIL_WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setenv("EMAIL_SUBJECT", "Test Subject")
    monkeypatch.setenv("SOC_NOTIFY_EMAILS", "soc@corp.example")

    with patch.object(notify, "_send_via_graph") as graph_send, \
         patch.object(notify, "_send_via_webhook", return_value=True) as webhook_send:
        notify.notify_admins("Test", ["line"])
        graph_send.assert_not_called()
        webhook_send.assert_called_once()


def test_email_subject_used_verbatim_when_no_placeholders():
    """The requirement's own example — a plain fixed subject string —
    must pass through completely unchanged."""
    from shared.notify import _render_subject
    assert _render_subject("IOC Distribution Notification",
                           count=3, ioc_type="ip", reference="INC1", date="2026-01-01") \
        == "IOC Distribution Notification"


def test_email_subject_template_placeholders_substitute_safely():
    from shared.notify import _render_subject
    result = _render_subject("{count} {ioc_type} — {reference}",
                             count=2, ioc_type="url", reference="INC42", date="2026-01-01")
    assert result == "2 url — INC42"
    # An unknown placeholder must not crash — left literal instead.
    result2 = _render_subject("{count} {typo_field}", count=1, ioc_type="ip",
                              reference="INC1", date="2026-01-01")
    assert result2 == "1 {typo_field}"
