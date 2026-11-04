import * as client from 'openid-client';

import { type OidcIdentity, toOidcIdentity } from './claims';
import type { OidcSettings } from './config';

/** Per-login values kept in the session between redirect and callback. */
export type PendingOidcLogin = {
  state: string;
  nonce: string;
  codeVerifier: string;
  createdAt: number;
};

// A login must finish within this window; it bounds how long a stolen or
// leaked state value stays usable.
export const PENDING_LOGIN_TTL_MS = 10 * 60 * 1000;

let configurationPromise: Promise<client.Configuration> | null = null;

function getConfiguration(settings: OidcSettings) {
  if (configurationPromise == null) {
    configurationPromise = client
      .discovery(
        settings.issuerUrl,
        settings.clientId,
        settings.clientSecret,
        undefined,
        settings.allowInsecureHttp
          ? { execute: [client.allowInsecureRequests] }
          : undefined,
      )
      .catch(err => {
        // Retry discovery on the next login instead of caching the failure,
        // so an IdP that was down at startup does not need an API restart.
        configurationPromise = null;
        throw err;
      });
  }
  return configurationPromise;
}

export async function startOidcLogin(settings: OidcSettings): Promise<{
  authorizationUrl: URL;
  pending: PendingOidcLogin;
}> {
  const configuration = await getConfiguration(settings);
  const codeVerifier = client.randomPKCECodeVerifier();
  const pending: PendingOidcLogin = {
    state: client.randomState(),
    nonce: client.randomNonce(),
    codeVerifier,
    createdAt: Date.now(),
  };

  const authorizationUrl = client.buildAuthorizationUrl(configuration, {
    redirect_uri: settings.redirectUri.href,
    scope: settings.scopes,
    state: pending.state,
    nonce: pending.nonce,
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: 'S256',
  });

  return { authorizationUrl, pending };
}

export type OidcLoginResult = {
  identity: OidcIdentity;
  // Absent when the IdP issued none, e.g. without the offline_access scope.
  refreshToken?: string;
};

/**
 * Exchanges the authorization code and returns the verified identity. The
 * callback URL is rebuilt from the configured redirect URI rather than the
 * request's Host header, which a proxy or client could otherwise influence.
 */
export async function completeOidcLogin(
  settings: OidcSettings,
  pending: PendingOidcLogin,
  callbackQuery: URLSearchParams,
): Promise<OidcLoginResult> {
  const configuration = await getConfiguration(settings);

  const currentUrl = new URL(settings.redirectUri.href);
  for (const [key, value] of callbackQuery) {
    currentUrl.searchParams.append(key, value);
  }

  const tokens = await client.authorizationCodeGrant(
    configuration,
    currentUrl,
    {
      pkceCodeVerifier: pending.codeVerifier,
      expectedState: pending.state,
      expectedNonce: pending.nonce,
      idTokenExpected: true,
    },
  );

  const idTokenClaims = tokens.claims();
  if (idTokenClaims == null) {
    throw new Error('OIDC token response did not include an ID token');
  }

  return {
    identity: await identityFromTokens(
      configuration,
      settings,
      tokens.access_token,
      idTokenClaims,
    ),
    refreshToken: tokens.refresh_token,
  };
}

export type OidcRefreshResult =
  | { kind: 'verified'; identity: OidcIdentity; refreshToken?: string }
  // The IdP refused the refresh token: the user was disabled or deleted, their
  // IdP session ended, or the grant was revoked.
  | { kind: 'refused'; error: string };

/**
 * Re-checks a user with the IdP using their refresh token. Anything other than
 * an explicit refusal throws, so the caller can tell "the IdP said no" from
 * "the IdP could not answer" (retry later).
 */
export async function refreshOidcIdentity(
  settings: OidcSettings,
  refreshToken: string,
  expected: { issuer: string; subject: string },
): Promise<OidcRefreshResult> {
  const configuration = await getConfiguration(settings);

  let tokens: Awaited<ReturnType<typeof client.refreshTokenGrant>>;
  try {
    tokens = await client.refreshTokenGrant(configuration, refreshToken);
  } catch (err) {
    // Only invalid_grant is about the user. invalid_client and the like mean
    // HyperDX is misconfigured, and must not lock every user out.
    if (
      err instanceof client.ResponseBodyError &&
      err.error === 'invalid_grant'
    ) {
      return { kind: 'refused', error: err.error };
    }
    throw err;
  }

  // A refresh need not return an ID token; userinfo then carries the claims,
  // pinned to the subject we already know.
  const idTokenClaims = tokens.claims() ?? {
    iss: expected.issuer,
    sub: expected.subject,
  };
  if (
    idTokenClaims.iss !== expected.issuer ||
    idTokenClaims.sub !== expected.subject
  ) {
    return { kind: 'refused', error: 'subject_mismatch' };
  }

  return {
    kind: 'verified',
    identity: await identityFromTokens(
      configuration,
      settings,
      tokens.access_token,
      idTokenClaims,
    ),
    refreshToken: tokens.refresh_token,
  };
}

async function identityFromTokens(
  configuration: client.Configuration,
  settings: OidcSettings,
  accessToken: string,
  idTokenClaims: Record<string, unknown> & { sub: string },
): Promise<OidcIdentity> {
  // Fetch userinfo only when the ID token lacks what we need, saving a round
  // trip for providers that put everything in the ID token.
  const needsUserInfo =
    idTokenClaims.email == null || idTokenClaims[settings.groupsClaim] == null;
  const userInfo =
    needsUserInfo && configuration.serverMetadata().userinfo_endpoint
      ? await client.fetchUserInfo(
          configuration,
          accessToken,
          idTokenClaims.sub,
        )
      : undefined;

  return toOidcIdentity(idTokenClaims, userInfo, settings.groupsClaim);
}
