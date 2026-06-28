"""Frappe `auth_hooks` entrypoint for Logto bearer-token authentication."""

from __future__ import annotations

import frappe

from logto_bridge.auth.jwt_verifier import verify_token
from logto_bridge.auth.opaque_verifier import verify_opaque_token
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
    * JWT access token (resource-scoped)    -> verify the signature against the
      Logto JWKS and set the request user.
    * Opaque access token (no resource)     -> validate it at Logto's userinfo
      endpoint and set the request user.
    * Verification failure                 -> ``frappe.AuthenticationError``
      (fail closed).

    Logto only mints a *JWT* access token when the client requests the ERPNext
    API resource; a client that does not (e.g. the Raven mobile app) gets an
    *opaque* token instead. Both are accepted here — a JWT is verified locally
    against the JWKS, an opaque token is validated via ``/oidc/me`` — so the
    bridge no longer rejects opaque tokens with ``Not enough segments``.

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

    if _looks_like_jwt(token):
        # Resource-scoped JWT: full local verification (signature, iss, aud, exp).
        claims = verify_token(
            token,
            jwks_uri=settings["jwks_uri"],
            issuer=settings["issuer"],
            audience=settings["audience"],
        )
    else:
        # Opaque token: Logto vouches for it via the userinfo endpoint. The
        # returned claims already carry sub/email/name, so `resolve_user` does
        # not need a second round-trip.
        claims = verify_opaque_token(token, userinfo_uri=settings["userinfo_uri"])

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


def _looks_like_jwt(token: str) -> bool:
    """True if the token has the three non-empty dot-separated segments of a JWS.

    A JWT is ``header.payload.signature``; an opaque Logto access token is a
    bare random string with no dots. This is a structural check only — the
    actual signature is still verified by ``verify_token``.
    """
    parts = token.split(".")
    return len(parts) == 3 and all(parts)
