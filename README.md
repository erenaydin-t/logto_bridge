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
   the token is validated by one of two paths depending on its shape:
   - **JWT access token** (the client requested the ERPNext API resource):
     verified locally against the Logto tenant **JWKS** (signature, `iss`,
     `aud`, `exp`, `iat`, required claims).
   - **Opaque access token** (the client signed in with plain OIDC scopes and
     never requested the resource — e.g. the Raven mobile app): validated at
     Logto's userinfo endpoint (`/oidc/me`), which returns the token owner's
     claims only for a live, unexpired token. The result is cached briefly
     (keyed by a hash of the token) so polling clients don't hit Logto on every
     request.
3. The resulting `email` claim is mapped to a Frappe `User` via the ORM. With
   *Auto Create User* enabled, an unknown user is provisioned with the
   configured default role.
4. `frappe.set_user()` sets the user for that request only. No
   `login_manager.login()`, so no session cookie is issued — which also keeps
   these endpoints free of CSRF-token requirements.

> **Preferred:** issue **JWT** access tokens by granting the client app the
> ERPNext API resource in Logto *and* having the client request it
> (`resources: ['<audience>']`). The opaque-token path is a compatibility
> fallback for clients that cannot request a resource; it relies on Logto to
> vouch for the token via userinfo rather than an `aud`-pinned local signature
> check.

## Security properties

- **No raw SQL.** All DB access goes through the Frappe ORM
  (`frappe.db.get_value`, `frappe.db.exists`, `frappe.new_doc`).
- **Full JWT validation.** Signature via JWKS, plus `iss` / `aud` / `exp` /
  `iat` and a `require` list — no `verify=False` shortcuts.
- **Opaque tokens validated by Logto.** A non-JWT token is never decoded
  locally; it is accepted only if Logto's userinfo endpoint returns `200` with
  a `sub`. This path does not assert `aud` (an opaque token carries none), so
  prefer resource-scoped JWTs where the client can request them.
- **Stateless.** Bearer-only; no cookie session, no CSRF surface.
- **Rate limited.** Whitelisted endpoints carry `@rate_limit` decorators.
- **Fail closed for Logto tokens.** A Logto-token verification error raises
  `frappe.AuthenticationError`; a missing header is a silent no-op.
- **Defers non-Logto bearer tokens.** This hook runs after Frappe's native
  bearer auth. If the request is already authenticated, or the token is a
  Frappe-issued OAuth2 bearer token (e.g. the **Raven mobile app**, which uses
  `frappe.integrations.oauth2`), the bridge no-ops and lets Frappe's native
  auth handle it — it does not hijack or reject non-Logto tokens.

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
