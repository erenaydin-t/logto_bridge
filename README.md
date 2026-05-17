# Logto Bridge

A Frappe v16 custom app that authenticates **ERPNext** requests with **Logto**
(OIDC) bearer tokens issued to the Visitor Sales PWA.

It bypasses the default Frappe login: the PWA runs the Authorization Code + PKCE
flow against Logto, then calls ERPNext with `Authorization: Bearer <access_token>`.
This app verifies that token and resolves it to a Frappe `User` — **per request,
statelessly, with no session cookie**.

## How it works

1. `auth_hooks` registers `logto_bridge.auth.validate.validate_auth`, which runs
   on every incoming request.
2. If an `Authorization: Bearer` header is present and the bridge is enabled,
   the JWT is verified against the Logto tenant **JWKS** (signature, `iss`,
   `aud`, `exp`, `iat`, required claims).
3. The verified `email` claim is mapped to a Frappe `User` via the ORM. With
   *Auto Create User* enabled, an unknown user is provisioned with the
   configured default role.
4. `frappe.set_user()` sets the user for that request only. No
   `login_manager.login()`, so no session cookie is issued — which also keeps
   these endpoints free of CSRF-token requirements.

## Security properties

- **No raw SQL.** All DB access goes through the Frappe ORM
  (`frappe.db.get_value`, `frappe.db.exists`, `frappe.new_doc`).
- **Full JWT validation.** Signature via JWKS, plus `iss` / `aud` / `exp` /
  `iat` and a `require` list — no `verify=False` shortcuts.
- **Stateless.** Bearer-only; no cookie session, no CSRF surface.
- **Rate limited.** Whitelisted endpoints carry `@rate_limit` decorators.
- **Fail closed.** Any verification error raises `frappe.AuthenticationError`;
  a missing header is a silent no-op so native API-key auth still works.

## Install

```bash
# from the bench directory
bench get-app logto_bridge /path/to/visitor/backend/logto_bridge
bench --site <your-site> install-app logto_bridge
bench --site <your-site> migrate
```

`pyjwt[crypto]` is declared in `pyproject.toml` and installed by `bench get-app`.

## Configure

Open **Logto Bridge Settings** (a Single DocType) in ERPNext and set:

| Field              | Value                                                        |
| ------------------ | ------------------------------------------------------------ |
| Enabled            | ✓                                                            |
| Logto Endpoint     | `https://<tenant>.logto.app` (no trailing slash)             |
| Audience           | The ERPNext API **resource indicator** registered in Logto   |
| JWKS URI           | *(optional)* defaults to `<endpoint>/oidc/jwks`              |
| Auto Create User   | ✓ to provision unknown users on first login                  |
| Default Role       | Role granted to provisioned users (default: `Sales User`)    |

The issuer is derived as `<endpoint>/oidc`.

## API

| Method                                            | Purpose                                  |
| -------------------------------------------------- | ---------------------------------------- |
| `logto_bridge.api.auth.get_current_user`           | Identity + roles bootstrap for the PWA   |
| `logto_bridge.api.auth.ping`                       | Authenticated health probe for sync      |
