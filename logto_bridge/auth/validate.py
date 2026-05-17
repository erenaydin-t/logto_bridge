"""Frappe `auth_hooks` entrypoint for Logto bearer-token authentication."""

from __future__ import annotations

import frappe

from logto_bridge.auth.jwt_verifier import verify_token
from logto_bridge.auth.user import resolve_user
from logto_bridge.logto_bridge.doctype.logto_bridge_settings.logto_bridge_settings import (
    get_logto_settings,
)

_BEARER_PREFIX = "bearer"


def validate_auth() -> None:
    """Authenticate the current request from a Logto bearer token.

    Runs on every request via `auth_hooks`. Behaviour:

    * No ``Authorization: Bearer`` header  -> no-op (cookie / API-key auth
      still applies).
    * Header present, bridge enabled       -> verify the JWT against Logto
      and set the request user.
    * Verification failure                 -> ``frappe.AuthenticationError``
      (fail closed).

    The user is set for THIS request only — `frappe.set_user` rather than
    `login_manager.login()` — so no session cookie is issued and the endpoint
    carries no CSRF-token requirement.
    """
    token = _extract_bearer_token()
    if not token:
        return

    settings = get_logto_settings()
    if not settings["enabled"]:
        return

    if not settings["endpoint"] or not settings["audience"]:
        # Misconfigured bridge: log it, and do not silently authenticate.
        frappe.log_error(title="Logto bridge is enabled but not fully configured")
        return

    claims = verify_token(
        token,
        jwks_uri=settings["jwks_uri"],
        issuer=settings["issuer"],
        audience=settings["audience"],
    )

    # Pass the raw access token through — `resolve_user` calls /userinfo
    # on first sign-in for a new sub to enrich the profile (email, name).
    user = resolve_user(claims, settings, access_token=token)

    frappe.set_user(user)
    # Expose the verified claims for downstream whitelisted methods if needed.
    frappe.local.logto_claims = claims


def _extract_bearer_token() -> str | None:
    """Return the bearer token from the Authorization header, if any."""
    header = frappe.get_request_header("Authorization") or ""
    parts = header.split(" ", 1)
    if len(parts) == 2 and parts[0].strip().lower() == _BEARER_PREFIX:
        return parts[1].strip() or None
    return None
