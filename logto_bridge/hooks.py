app_name = "logto_bridge"
app_title = "Logto Bridge"
app_publisher = "Milan Pars"
app_description = "Logto SSO (OIDC) authentication bridge for the Visitor Sales PWA on ERPNext 16"
app_email = "dev@milanpars.example"
app_license = "MIT"

# This app depends on a working Frappe install only.
required_apps = ["frappe"]

# ─────────────────────────────────────────────────────────────────────────────
# Request authentication
# ─────────────────────────────────────────────────────────────────────────────
# `auth_hooks` are invoked by Frappe on every incoming request (see
# frappe.auth.validate_auth_via_hooks). Our hook inspects the
# `Authorization: Bearer` header, verifies the Logto JWT and resolves the
# request user. A missing header is a no-op, so native cookie/API-key auth
# continues to work unchanged.
auth_hooks = ["logto_bridge.auth.validate.validate_auth"]
