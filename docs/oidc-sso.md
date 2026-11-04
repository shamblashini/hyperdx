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
| `OIDC_SCOPES` | no | Defaults to `openid email profile offline_access`. Must include `openid`; keep `offline_access` so the IdP issues the refresh token used for [revalidation](#removing-access). |
| `OIDC_GROUPS_CLAIM` | no | Claim that holds the user's groups. Defaults to `groups`. |
| `OIDC_DISPLAY_NAME` | no | Shown on the login button ("Sign in with ..."). Defaults to `SSO`. |
| `OIDC_SESSION_MAX_AGE_HOURS` | no | Absolute lifetime of a browser session before the user must sign in through the IdP again. Defaults to `24`; `0` disables the cap (sessions then last up to 30 days, like password sessions). |
| `OIDC_IDENTITY_MAX_AGE_HOURS` | no | How long after the IdP last vouched for a user (at login or by revalidation) their sessions and personal API access key keep working. Defaults to `24`. |
| `OIDC_REVALIDATE_INTERVAL_MINUTES` | no | How often each user is re-checked with the IdP in the background. Defaults to `15`; `0` turns revalidation off, so users must sign in again every `OIDC_IDENTITY_MAX_AGE_HOURS`. At most a third of the identity max age. |
| `PASSWORD_AUTH_DISABLED` | no | `true` turns off password login, registration and invite acceptance, and stops sessions and access keys of accounts that never signed in through SSO. Requires `OIDC_ISSUER_URL`. |
| `TOKEN_ENCRYPTION_KEY` | for revalidation | Refresh tokens are stored only encrypted. Without this key none are stored and revalidation cannot run (generate one with `openssl rand -base64 32`). |
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
IdP take over the account. Once linked, the account is matched by `sub`. Its password
keeps working until you set `PASSWORD_AUTH_DISABLED=true`, but only while the
IdP still vouches for the user (see [Removing access](#removing-access)).

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
   # Needed to store refresh tokens for revalidation:
   TOKEN_ENCRYPTION_KEY=<openssl rand -base64 32>
   # After the first admin has signed in through Authentik:
   PASSWORD_AUTH_DISABLED=true
   ```

**About `email_verified`:** check what your Authentik version sends (*Providers
→ your provider → Preview*). It only matters when linking to existing password
accounts. If it is `false`, and you do not let users change their own email in
Authentik, you can add a custom `email` scope mapping that returns
`email_verified: True`.

## Removing access

HyperDX has no SCIM endpoint. Instead, a personal API access key (used by the
External API and MCP) and every browser session are only valid while the IdP
keeps vouching for the user:

1. At login HyperDX stores the user's refresh token, encrypted.
2. Every `OIDC_REVALIDATE_INTERVAL_MINUTES` it uses that token to ask the IdP
   about the user again, and re-reads their groups.
3. If the IdP refuses the token (`invalid_grant`: the user was disabled or
   deleted, or their IdP session ended), or the user is no longer in a mapped
   group, their sessions and access key stop working at once.
4. If the IdP cannot be reached, nobody is revoked. Instead, anyone the IdP has
   not confirmed for `OIDC_IDENTITY_MAX_AGE_HOURS` loses access until it
   answers again or they sign in again.

So after you disable someone in the IdP, their key stops working within
`OIDC_REVALIDATE_INTERVAL_MINUTES` (15 by default). In the worst case, with the
IdP unreachable, it stops within `OIDC_IDENTITY_MAX_AGE_HOURS`.

A revoked user keeps their access key. If they sign in again, because they
were re-enabled or only their IdP session had ended, the same key works again,
so their MCP and API configuration doesn't break.

Every API replica runs the check. Each user is leased while being checked, so
two replicas never use the same refresh token at once, which IdPs that rotate
refresh tokens (Authentik does) would treat as token theft.

**Authentik specifics.** Authentik deletes a user's refresh tokens when it
deactivates them or when their Authentik session ends, and a refreshed ID token
carries their current groups. Two settings matter:

- The provider's *Refresh Token validity* must be longer than the revalidation
  interval (the default 30 days is fine).
- A user's Authentik session length, the *Session duration* on your
  authentication flow's *User Login* stage, bounds how long their access key
  works without a browser sign-in. With the default (`seconds=0`, the session
  ends with the browser), keys stop once that session is gone. Set it to how
  long you want keys to keep working unattended, e.g. `weeks=4`.

Check the setup by disabling a test user in Authentik and confirming that
their access key gets `401` within the revalidation interval.

## What teams do and do not isolate

Teams separate HyperDX metadata: dashboards, saved searches, alerts, webhooks,
sources and ClickHouse connections. They do not separate telemetry by
themselves. Every team's ingestion key feeds the same collector pipeline, and
teams created from `DEFAULT_CONNECTIONS` all point at the same ClickHouse
tables, so they can query the same data.

If teams must not see each other's data, give each team its own ClickHouse user
restricted to its own databases or rows (row policies), configure that as the
team's connection, and route each team's telemetry to its own tables.
