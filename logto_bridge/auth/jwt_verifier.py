"""Logto JWT verification against the tenant JWKS.

Stateless, fail-closed token validation. No `verify=False` shortcuts: every
token must carry a valid signature plus the required registered claims.
"""

from __future__ import annotations

import frappe
import jwt
from frappe import _
from jwt import PyJWKClient

# Logto signs access tokens with ES384 by default; RS256/ES256 are accepted
# in case the tenant is configured otherwise. The concrete algorithm is still
# pinned per-token from the JWKS — `alg: none` can never be selected.
_ALLOWED_ALGORITHMS = ["ES384", "ES256", "RS256"]

# Process-level cache of JWKS clients, keyed by URI. PyJWKClient keeps its own
# TTL'd key cache so we are not fetching the JWKS on every request.
_jwks_clients: dict[str, PyJWKClient] = {}


def _get_jwks_client(jwks_uri: str) -> PyJWKClient:
    client = _jwks_clients.get(jwks_uri)
    if client is None:
        client = PyJWKClient(jwks_uri, cache_keys=True, lifespan=3600)
        _jwks_clients[jwks_uri] = client
    return client


def verify_token(token: str, *, jwks_uri: str, issuer: str, audience: str) -> dict:
    """Verify a Logto-issued JWT access token.

    Validates the signature against the tenant JWKS and enforces issuer,
    audience, expiry and the presence of required claims. Returns the decoded
    claim set on success; raises ``frappe.AuthenticationError`` otherwise.
    """
    try:
        signing_key = _get_jwks_client(jwks_uri).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=_ALLOWED_ALGORITHMS,
            issuer=issuer,
            audience=audience,
            options={
                "require": ["exp", "iat", "iss", "aud", "sub"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
    except jwt.ExpiredSignatureError:
        frappe.throw(_("Logto token has expired."), frappe.AuthenticationError)
    except jwt.InvalidTokenError as exc:
        # Bad signature, wrong issuer/audience, missing claim, malformed token.
        # Log details server-side so the admin can debug from Error Log
        # (Frappe strips messages from AuthenticationError responses for security).
        frappe.log_error(message=str(exc), title="Logto JWT rejected")
        frappe.throw(
            _("Invalid Logto token: {0}").format(str(exc)),
            frappe.AuthenticationError,
        )
    except Exception as exc:
        # Network / JWKS-fetch failures — log server-side, stay vague to caller.
        frappe.log_error(message=str(exc), title="Logto JWKS verification failed")
        frappe.throw(_("Could not verify Logto token."), frappe.AuthenticationError)

    return claims
