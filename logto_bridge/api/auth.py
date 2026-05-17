"""Whitelisted endpoints the Visitor Sales PWA calls after Logto sign-in.

Every method here assumes the Logto auth hook has already run. They reject
the Guest user explicitly as a defence-in-depth check and are rate limited.
"""

from __future__ import annotations

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit


@frappe.whitelist()
@rate_limit(limit=60, seconds=60)
def get_current_user() -> dict:
    """Identity + roles bootstrap for the PWA, called right after login.

    Returns only non-sensitive profile fields. Raises AuthenticationError if
    the request was not resolved to a real user by the auth hook.
    """
    _reject_guest()

    user = frappe.get_cached_doc("User", frappe.session.user)
    return {
        "user": user.name,
        "email": user.email,
        "full_name": user.full_name,
        "roles": frappe.get_roles(user.name),
        "language": user.language or frappe.local.lang,
        "time_zone": user.time_zone,
    }


@frappe.whitelist()
@rate_limit(limit=120, seconds=60)
def ping() -> dict:
    """Lightweight authenticated health probe for the PWA sync layer."""
    _reject_guest()
    return {
        "authenticated": True,
        "user": frappe.session.user,
        "server_time": frappe.utils.now(),
    }


def _reject_guest() -> None:
    if frappe.session.user == "Guest":
        frappe.throw(_("Not authenticated."), frappe.AuthenticationError)
