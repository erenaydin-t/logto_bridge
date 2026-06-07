"""Map verified Logto claims to a Frappe User.

User-resolution model
---------------------
Identity is resolved automatically from the verified access-token claims —
no manual `logto:<sub>` mapping is ever required. The flow is:

  1. Look up `User.username == "logto:<sub>"`. If found, return it. This is
     the fast path for every returning user — zero network overhead.
  2. First sign-in for a new sub: read `email` (and `name`) DIRECTLY from the
     verified JWT claims. Logto is configured to emit these as custom JWT
     claims on the access token, so no second round-trip is needed.
  3. Match an existing ERPNext User by that email and link it by setting
     `username = "logto:<sub>"`. The user keeps all of its native ERPNext
     roles and permissions — Logto only authenticates, ERPNext authorises.
  4. If no User matches and `auto_create_user` is on, provision a new one.

A resource-scoped access token (`aud = <ERPNext resource>`) is NOT valid at
Logto's `/oidc/me` endpoint, so userinfo is only attempted as a last-resort
fallback when the claims carry no email — it is not on the happy path.

ORM-only — no raw SQL anywhere in this module.
"""

from __future__ import annotations

import frappe
import requests
from frappe import _

_USERINFO_TIMEOUT_S = 5


def resolve_user(claims: dict, settings: dict, *, access_token: str) -> str:
    """Resolve verified Logto claims to a Frappe User name.

    Raises ``frappe.AuthenticationError`` when the user cannot be resolved.
    """
    sub = (claims.get("sub") or "").strip()
    if not sub:
        frappe.throw(
            _("Logto token does not contain a sub claim."),
            frappe.AuthenticationError,
        )

    logto_username = f"logto:{sub}"

    # Step 1: existing linked User — the common case after first sign-in.
    user_name = frappe.db.get_value("User", {"username": logto_username}, "name")
    if user_name:
        _ensure_enabled(user_name)
        return user_name

    # Step 2: first sign-in for this sub. Read identity straight from the
    # verified claims. Only when the access token carries no email do we fall
    # back to /userinfo (which a resource-scoped token cannot satisfy).
    email = _claim_email(claims)
    name = _claim_name(claims)

    if not email:
        userinfo = _fetch_userinfo(settings["userinfo_uri"], access_token)
        email = (userinfo.get("email") or "").strip().lower()
        name = name or (userinfo.get("name") or "").strip()

    if not email:
        # Without an email we cannot resolve or create a User. This means the
        # access token is missing its email claim — point the admin at the
        # Logto custom-JWT configuration rather than a per-user manual mapping.
        frappe.log_error(
            message=f"No email claim on token or userinfo for sub={sub}",
            title="Logto token missing email claim",
        )
        frappe.throw(
            _(
                "Logto did not provide an email for this user. Add an 'email' "
                "custom JWT claim to the ERPNext API resource in Logto."
            ),
            frappe.AuthenticationError,
        )

    if not frappe.utils.validate_email_address(email):
        frappe.throw(
            _("Logto returned an invalid email address."),
            frappe.AuthenticationError,
        )

    # Step 3: existing User with that email — link it to this sub for next
    # time. The User keeps its native ERPNext roles and permissions untouched.
    user_name = frappe.db.get_value("User", {"email": email}, "name")
    if user_name:
        _ensure_enabled(user_name)
        frappe.db.set_value("User", user_name, "username", logto_username)
        frappe.db.commit()
        return user_name

    # Step 4: no match by sub or email — provision (or fail closed).
    if not settings["auto_create_user"]:
        frappe.throw(
            _("No ERPNext account is linked to {0}.").format(email),
            frappe.AuthenticationError,
        )

    return _provision_user(
        email=email,
        full_name=name,
        logto_username=logto_username,
        settings=settings,
    )


def _ensure_enabled(user_name: str) -> None:
    """Reject sign-in for a disabled ERPNext User."""
    if not frappe.db.get_value("User", user_name, "enabled"):
        frappe.throw(_("This user account is disabled."), frappe.AuthenticationError)


def _claim_email(claims: dict) -> str:
    """Return the normalised email from the verified token claims, if present."""
    raw = claims.get("email")
    return raw.strip().lower() if isinstance(raw, str) else ""


def _claim_name(claims: dict) -> str:
    """Best-effort display name from common OIDC/profile claim keys."""
    for key in ("name", "preferred_username", "username"):
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _fetch_userinfo(userinfo_uri: str, access_token: str) -> dict:
    """Call Logto's `/userinfo` with the access token. Returns its JSON claims.

    Failures are logged server-side and surface to the caller as a generic
    ``AuthenticationError`` — never leak Logto-side error details to API
    consumers.
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
            _("Could not reach Logto to enrich the user profile."),
            frappe.AuthenticationError,
        )

    if response.status_code != 200:
        frappe.log_error(
            message=f"status={response.status_code} body={response.text[:500]}",
            title="Logto userinfo non-200",
        )
        frappe.throw(
            _("Logto userinfo rejected the token."),
            frappe.AuthenticationError,
        )

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


def _provision_user(
    *,
    email: str,
    full_name: str,
    logto_username: str,
    settings: dict,
) -> str:
    """Create a new enabled User from Logto claims (ORM only)."""
    first_name = full_name or email.split("@", 1)[0]

    user = frappe.new_doc("User")
    user.email = email
    user.first_name = first_name
    user.username = logto_username
    user.enabled = 1
    user.user_type = "System User"
    user.send_welcome_email = 0
    # The PWA owns authentication — suppress the local password-login path.
    user.flags.no_welcome_mail = True

    default_role = settings["default_role"]
    if default_role and frappe.db.exists("Role", default_role):
        user.append("roles", {"role": default_role})

    # ignore_permissions: the auth hook runs before any user context.
    user.insert(ignore_permissions=True)
    # Commit so the freshly provisioned user survives even on a GET request
    # (which Frappe would otherwise roll back at end of request).
    frappe.db.commit()

    return user.name
