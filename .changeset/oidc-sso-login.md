---
'@hyperdx/api': minor
'@hyperdx/app': minor
'@hyperdx/common-utils': minor
---

feat: Sign in with OpenID Connect (Authentik, Keycloak, Okta, ...). Users are created on first login and placed in a team chosen from their IdP groups, so one instance can serve several teams. `PASSWORD_AUTH_DISABLED=true` makes SSO the only way in. See `docs/oidc-sso.md`.
