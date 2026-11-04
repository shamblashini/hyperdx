---
'@hyperdx/api': minor
---

feat: Personal API access keys and sessions of SSO users now depend on the IdP still vouching for them. HyperDX re-checks each user with their refresh token every `OIDC_REVALIDATE_INTERVAL_MINUTES` (default 15) and cuts off anyone the IdP disables, deletes or removes from every mapped group. If the IdP is unreachable, access lapses after `OIDC_IDENTITY_MAX_AGE_HOURS` (default 24). With `PASSWORD_AUTH_DISABLED=true`, accounts that never signed in through SSO are cut off too. Requires `TOKEN_ENCRYPTION_KEY`.
