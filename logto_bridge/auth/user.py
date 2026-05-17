"""Map verified Logto claims to a Frappe User.

User-resolution model
---------------------
Logto access tokens are intentionally minimal (per OIDC) — they carry
`sub`/`aud`/`exp`/`iss` but NOT `email` or profile claims. Those live in
the ID token and behind `/userinfo`. We therefore:

  1. Look up `User.username == "logto:<sub>"`.
  2. If found, return it. Zero network overhead.
  3. If not found, call Logto's `/userinfo` ONCE with the access token to
     get `email` + `name`. Then either link an existing User (matched by
     email) by setting its `username = "logto:<sub>"`, or auto-provision
     a new one when `auto_create_user` is on.

Step 3 only runs on the first request from a new sub — every subsequent
request is a pure local DB lookup.

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
        if not frappe.db.get_value("User", user_name, "enabled"):
            frappe.throw(_("This user account is disabled."), frappe.AuthenticationError)
        return user_name

    # Step 2: not linked yet — enrich from userinfo.
    userinfo = _fetch_userinfo(settings["userinfo_uri"], access_token)
    email = (userinfo.get("email") or "").strip().lower()
    name = (userinfo.get("name") or "").strip()

    if not email:
        # Without an email we cannot create a valid User. Tell the admin
        # which sub to link manually so they can create the User in the
        # ERPNext UI and rerun.
        frappe.log_error(
            message=f"Userinfo for sub={sub} returned no email; claims={userinfo}",
            title="Logto userinfo missing email",
        )
        frappe.throw(
            _(
                "Logto did not return an email for this user. "
                "Create an ERPNext User and set its username to 'logto:{0}'."
            ).format(sub),
            frappe.AuthenticationError,
        )

    if not frappe.utils.validate_email_address(email):
        frappe.throw(
            _("Logto returned an invalid email address."),
            frappe.AuthenticationError,
        )

    # Step 3: existing User with that email — link it to this sub for next time.
    user_name = frappe.db.get_value("User", {"email": email}, "name")
    if user_name:
        if not frappe.db.get_value("User", user_name, "enabled"):
            frappe.throw(
                _("This user account is disabled."), frappe.AuthenticationError
            )
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
