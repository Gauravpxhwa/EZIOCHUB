"""Server-side identity + authorisation.

Identity arrives in x-portal-user / x-portal-oid / x-portal-roles headers
injected by the App Service frontend AFTER Entra ID sign-in (Easy Auth).
These headers are trustworthy because users cannot reach this Function App
directly: public network access is disabled (private endpoint only), the
App Service is the sole caller, and every call carries the function key.
The proxy strips any client-supplied x-portal-* headers before injecting
its own, so 'added_by' can never be spoofed.

Which roles may perform which action (add / delete / export) is
configuration — the "permissions" map in the runtime portal config —
so tightening or loosening access never needs a code change.
"""
import json

import azure.functions as func


class AuthError(Exception):
    def __init__(self, message: str, status: int = 403):
        super().__init__(message)
        self.status = status


def principal(req: func.HttpRequest) -> dict:
    user = req.headers.get("x-portal-user")
    if not user:
        raise AuthError("Not authenticated.", 401)
    roles = [r.strip() for r in (req.headers.get("x-portal-roles") or "").split(",") if r.strip()]
    return {
        "user": user,
        "user_id": req.headers.get("x-portal-oid", ""),
        "roles": roles,
    }


def require_roles(req: func.HttpRequest, allowed: list[str]) -> dict:
    p = principal(req)
    if not set(p["roles"]) & set(allowed or []):
        raise AuthError("Your role does not permit this action.", 403)
    return p


def error_response(e: Exception) -> func.HttpResponse:
    status = getattr(e, "status", 500)
    return func.HttpResponse(
        json.dumps({"error": str(e)}), status_code=status, mimetype="application/json"
    )
