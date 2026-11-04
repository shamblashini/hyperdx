# Single sign-on with OpenID Connect

HyperDX can sign users in through any OpenID Connect provider (Authentik,
Keycloak, Okta, Entra ID, Google, Dex, ...). Users are created on their first
login and placed in a team chosen from their IdP groups, so one HyperDX instance
can serve several teams.

## How it works

- Authorization code flow with PKCE, `state` and `nonce`. Only confidential
  clients (with a client secret) are supported.
- A user is identified by the provider's issuer and `sub` claim, not by email,
  so renaming someone's email in the IdP does not create a second account.
- On every login the user's team, name and email are re-synced from the IdP.
  Moving someone to another group moves them to that team at their next login.
- A user belongs to exactly one HyperDX team. If they are in several mapped
  groups, the first match wins (see [Mapping groups to teams](#mapping-groups-to-teams)).
- Teams are created the first time someone from their group logs in, with the
  same defaults as password registration (`DEFAULT_CONNECTIONS` /
  `DEFAULT_SOURCES`).
- Users whose groups map to no team are refused and nothing is created.

## Configuration

| Variable | Required | Description |
|---|---|---|
| `OIDC_ISSUER_URL` | yes | Issuer URL. Setting it enables SSO. Discovery is read from `<issuer>/.well-known/openid-configuration`. |
| `OIDC_CLIENT_ID` | yes | Client ID. |
| `OIDC_CLIENT_SECRET` | yes | Client secret. |
| `OIDC_TEAM_MAPPING` | one of these two | JSON object of `{"<group>": "<team name>"}`. |
| `OIDC_TEAM_GROUP_PREFIX` | one of these two | Any group starting with this prefix becomes a team named after the rest of the group name, e.g. `hyperdx-payments` → `payments`. |
| `OIDC_REDIRECT_URI` | no | Defaults to `${FRONTEND_URL}/api/login/oidc/callback`. |
| `OIDC_SCOPES` | no | Defaults to `openid email profile`. Must include `openid`. |
| `OIDC_GROUPS_CLAIM` | no | Claim that holds the user's groups. Defaults to `groups`. |
| `OIDC_DISPLAY_NAME` | no | Shown on the login button ("Sign in with ..."). Defaults to `SSO`. |
| `OIDC_SESSION_MAX_AGE_HOURS` | no | Absolute lifetime of an SSO session before the user must go back through the IdP. Defaults to `24`; `0` disables the cap (sessions then last up to 30 days, like password sessions). |
| `PASSWORD_AUTH_DISABLED` | no | `true` turns off password login, registration and invite acceptance. Requires `OIDC_ISSUER_URL`. |
| `OIDC_ALLOW_INSECURE_HTTP` | no | `true` allows `http://` issuer and redirect URLs. Local testing only. |

The API refuses to start if the OIDC configuration is incomplete or invalid, so
a typo is caught at deploy time rather than at someone's first login.

### Mapping groups to teams

```bash
OIDC_TEAM_MAPPING='{"hyperdx-platform": "Platform", "hyperdx-payments": "Payments"}'
OIDC_TEAM_GROUP_PREFIX=hyperdx-
```

Resolution order for a user:

1. The first entry in `OIDC_TEAM_MAPPING`, in the order written, whose group the
   user is in.
2. Otherwise, the alphabetically first group starting with
   `OIDC_TEAM_GROUP_PREFIX`.
3. Otherwise, the login is refused.

Use the mapping when team names should differ from group names or when the
order matters; use the prefix to add teams from the IdP without redeploying
HyperDX. They can be combined.

A team is bound to its group the first time it is used and found by that group
afterwards, so renaming the team in HyperDX is safe.

**Keeping the team you already have.** If you set HyperDX up with a password
account first, map a group to that team's exact current name (by default
`<your email>'s Team`, or rename it in Team settings first). The first SSO login
from that group binds the existing team instead of creating a new one.

### Existing password accounts

An SSO login whose email matches an existing password account is linked to it
only when the IdP reports `email_verified: true`. Otherwise it is refused, since
linking on an unverified email would let anyone who can set that address in the
IdP take over the account. Once linked, the account is matched by `sub` and the
password keeps working until you set `PASSWORD_AUTH_DISABLED=true`.

## Authentik setup

1. **Create the provider.** In the admin interface go to *Applications →
   Providers → Create → OAuth2/OpenID Provider*.
   - Client type: *Confidential*.
   - Redirect URIs: strict, `https://<your HyperDX host>/api/login/oidc/callback`.
   - Signing key: pick a certificate so ID tokens are signed with RS256.
   - Scopes: keep the default `openid`, `email` and `profile` mappings. The
     default `profile` mapping includes the `groups` claim.
   - Subject mode: keep *Based on the User's hashed ID* (the default). Do not
     use a mode based on email or username, since those can change.
2. **Create the application** (*Applications → Applications → Create*) and
   select the provider. Note its slug.
3. **Create a group per team**, e.g. `hyperdx-platform` and `hyperdx-payments`,
   and add users to them.
4. **Restrict access.** On the application's *Policy / Group / User Bindings*
   tab, bind the HyperDX groups so that users outside them are stopped at
   Authentik and never reach HyperDX.
5. **Configure HyperDX:**

   ```bash
   FRONTEND_URL=https://hyperdx.example.com
   OIDC_ISSUER_URL=https://authentik.example.com/application/o/<app-slug>/
   OIDC_CLIENT_ID=<client id>
   OIDC_CLIENT_SECRET=<client secret>
   OIDC_DISPLAY_NAME=Authentik
   OIDC_TEAM_GROUP_PREFIX=hyperdx-
   # After the first admin has signed in through Authentik:
   PASSWORD_AUTH_DISABLED=true
   ```

**About `email_verified`:** check what your Authentik version sends (*Providers
→ your provider → Preview*). It only matters when linking to existing password
accounts. If it is `false`, and you do not let users change their own email in
Authentik, you can add a custom `email` scope mapping that returns
`email_verified: True`.

## Removing access

HyperDX has no SCIM endpoint, so it learns about IdP changes only when a user
logs in. When you remove or disable someone in the IdP:

- Their browser session ends within `OIDC_SESSION_MAX_AGE_HOURS`, after which
  the IdP refuses the new login.
- **Their personal API access key (used by the External API and MCP) keeps
  working until you delete the user in Team settings.** Delete departing users
  in HyperDX as well as in the IdP.

## What teams do and do not isolate

Teams separate HyperDX metadata: dashboards, saved searches, alerts, webhooks,
sources and ClickHouse connections. They do not separate telemetry by
themselves. Every team's ingestion key feeds the same collector pipeline, and
teams created from `DEFAULT_CONNECTIONS` all point at the same ClickHouse
tables, so they can query the same data.

If teams must not see each other's data, give each team its own ClickHouse user
restricted to its own databases or rows (row policies), configure that as the
team's connection, and route each team's telemetry to its own tables.
