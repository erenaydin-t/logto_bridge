"""Validate opaque (non-JWT) Logto access tokens via the userinfo endpoint.

Logto only issues a *JWT* access token when the client requests a token for a
registered API resource. A client that signs in with plain OIDC scopes and
never asks for the ERPNext resource (e.g. the Raven mobile app) receives an
*opaque* access token instead — a random string with no JWT structure, which
cannot be verified locally against the JWKS. Feeding it to ``jwt.decode`` is
exactly what produces the ``Not enough segments`` failure.

An opaque token is, however, valid at Logto's userinfo endpoint
(``/oidc/me``): the endpoint returns the token owner's claims only for a live,
unexpired, non-revoked token. A successful userinfo response is therefore the
validation — it both proves the token is good and yields the ``sub`` / ``email``
/ ``name`` claims that :func:`logto_bridge.auth.user.resolve_user` needs.

Trade-off versus :mod:`logto_bridge.auth.jwt_verifier`: this path does NOT
assert the token's ``aud`` (an opaque token carries none we can inspect); it
relies on Logto to vouch for the token. For a first-party deployment that is an
acceptable relaxation. The userinfo result is cached briefly, keyed by a hash
of the token, so a polling client does not trigger a Logto round-trip on every
single request.
"""

from __future__ import annotations

import hashlib

import frappe
import requests
from frappe import _

_USERINFO_TIMEOUT_S = 5
# Cache a successful userinfo lookup for this many seconds. Short enough that a
# revoked token stops working quickly; long enough to spare Logto a request on
# every poll. A token that expires within the window is still rejected by Logto
# on the next cache miss.
_USERINFO_CACHE_TTL_S = 60


def verify_opaque_token(token: str, *, userinfo_uri: str) -> dict:
    """Validate an opaque Logto access token and return its claims.

    Returns a claims dict (at minimum ``sub``, plus ``email`` / ``name`` when
    the token's scopes allow) shaped like the JWT claim set, so it can be handed
    straight to ``resolve_user``. Raises ``frappe.AuthenticationError`` when the
    token is not accepted by Logto.
    """
    if not userinfo_uri:
        frappe.log_error(title="Logto opaque-token path has no userinfo_uri")
        frappe.throw(_("Could not verify Logto token."), frappe.AuthenticationError)

    cache_key = f"logto_bridge:userinfo:{hashlib.sha256(token.encode()).hexdigest()}"
    cached = frappe.cache().get_value(cache_key)
    if cached:
        return cached

    claims = _fetch_userinfo(userinfo_uri, token)

    sub = (claims.get("sub") or "").strip()
    if not sub:
        frappe.log_error(
            message="userinfo response carried no sub",
            title="Logto opaque token has no sub",
        )
        frappe.throw(_("Invalid Logto token."), frappe.AuthenticationError)

    frappe.cache().set_value(cache_key, claims, expires_in_sec=_USERINFO_CACHE_TTL_S)
    return claims


def _fetch_userinfo(userinfo_uri: str, access_token: str) -> dict:
    """GET Logto's userinfo with the access token; return its JSON claims.

    A non-200 is the normal "bad/expired token" signal for an opaque token, so
    it is treated as an authentication failure. Details are logged server-side;
    the caller only ever sees a generic ``AuthenticationError`` (Frappe strips
    the message from such responses anyway).
    """
    try:
        response = requests.get(
            userinfo_uri,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=_USERINFO_TIMEOUT_S,
        )
    except requests.RequestException as exc:
        frappe.log_error(message=str(exc), title="Logto userinfo request failed")
        frappe.throw(
            _("Could not reach Logto to verify the token."),
            frappe.AuthenticationError,
        )

    if response.status_code != 200:
        frappe.log_error(
            message=f"status={response.status_code} body={response.text[:500]}",
            title="Logto userinfo rejected token",
        )
        frappe.throw(_("Invalid Logto token."), frappe.AuthenticationError)

    try:
        return response.json()
    except ValueError:
        frappe.log_error(
            message=response.text[:500], title="Logto userinfo invalid JSON"
        )
        frappe.throw(
            _("Logto userinfo returned a malformed response."),
            frappe.AuthenticationError,
        )
