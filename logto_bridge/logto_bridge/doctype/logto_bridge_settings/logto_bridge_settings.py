import frappe
from frappe import _
from frappe.model.document import Document
from frappe.utils.caching import request_cache


class LogtoBridgeSettings(Document):
    def validate(self) -> None:
        # Normalise URLs so downstream string joins are predictable and the
        # 'iss' comparison is exact.
        if self.logto_endpoint:
            self.logto_endpoint = self.logto_endpoint.strip().rstrip("/")
        if self.jwks_uri:
            self.jwks_uri = self.jwks_uri.strip()
        if self.userinfo_uri:
            self.userinfo_uri = self.userinfo_uri.strip()
        if self.audience:
            self.audience = self.audience.strip()

        if self.enabled and not (self.logto_endpoint and self.audience):
            frappe.throw(
                _("Logto Endpoint and Audience are required when the bridge is enabled.")
            )

        if self.auto_create_user and self.default_role:
            if not frappe.db.exists("Role", self.default_role):
                frappe.throw(_("Default Role {0} does not exist.").format(self.default_role))


@request_cache
def get_logto_settings() -> dict:
    """Return the validated Logto bridge configuration.

    Cached for the lifetime of the request so the auth hook does not re-read
    the DB on every internal call within a single request.
    """
    doc = frappe.get_cached_doc("Logto Bridge Settings")
    endpoint = (doc.logto_endpoint or "").strip().rstrip("/")

    return {
        "enabled": bool(doc.enabled),
        "endpoint": endpoint,
        # Logto's OIDC issuer is always <endpoint>/oidc.
        "issuer": f"{endpoint}/oidc" if endpoint else "",
        "jwks_uri": (doc.jwks_uri or "").strip() or (f"{endpoint}/oidc/jwks" if endpoint else ""),
        # Logto's userinfo endpoint is <endpoint>/oidc/me (spec-standard
        # /oidc/userinfo also works on most deployments).
        "userinfo_uri": (
            (doc.userinfo_uri or "").strip() or (f"{endpoint}/oidc/me" if endpoint else "")
        ),
        "audience": (doc.audience or "").strip(),
        "auto_create_user": bool(doc.auto_create_user),
        "default_role": doc.default_role or "Sales User",
    }
