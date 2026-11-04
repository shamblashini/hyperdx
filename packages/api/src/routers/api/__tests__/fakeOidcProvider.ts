import crypto from 'crypto';
import express from 'express';
import type { Server } from 'http';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import type { AddressInfo } from 'net';

export const FAKE_CLIENT_ID = 'hyperdx-test';
export const FAKE_CLIENT_SECRET = 'hyperdx-test-secret';

type PendingCode = {
  claims: Record<string, unknown>;
  nonce: string;
  codeChallenge: string;
  scope: string;
};

/**
 * Just enough of an OIDC provider for the authorization code flow with PKCE
 * and refresh tokens: discovery, JWKS and a token endpoint issuing RS256 ID
 * tokens. Tests skip the browser leg by reading the authorization URL HyperDX
 * redirects to and minting a code for it with `authorize`.
 *
 * Like Authentik, it rotates the refresh token on every use, refuses a used
 * one, and builds the refreshed ID token from the user's current claims.
 */
export async function startFakeOidcProvider() {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'test', alg: 'RS256' };
  const codes = new Map<string, PendingCode>();
  // Current claims per subject, as the IdP's user directory would hold them.
  const users = new Map<string, Record<string, unknown>>();
  const refreshTokens = new Map<string, string>();
  let outage = false;
  let beforeRefresh: (() => Promise<void>) | null = null;

  const app = express();
  app.use(express.urlencoded({ extended: false }));

  let issuer = '';

  // Timestamps come from Date.now so tests that move it move the IdP too.
  const signIdToken = (claims: Record<string, unknown>) => {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'test' })
      .setIssuer(issuer)
      .setAudience(FAKE_CLIENT_ID)
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(privateKey);
  };

  const issueRefreshToken = (sub: string) => {
    const token = crypto.randomUUID();
    refreshTokens.set(token, sub);
    return token;
  };

  app.get('/application/o/hyperdx/.well-known/openid-configuration', (_, res) =>
    res.json({
      issuer,
      authorization_endpoint: `${issuer}authorize`,
      token_endpoint: `${issuer}token`,
      jwks_uri: `${issuer}jwks`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      code_challenge_methods_supported: ['S256'],
    }),
  );
  app.get('/application/o/hyperdx/jwks', (_, res) => res.json({ keys: [jwk] }));
  app.post('/application/o/hyperdx/token', async (req, res) => {
    if (outage) {
      return res.status(503).send('unavailable');
    }
    if (req.body.client_secret !== FAKE_CLIENT_SECRET) {
      return res.status(401).json({ error: 'invalid_client' });
    }

    if (req.body.grant_type === 'refresh_token') {
      await beforeRefresh?.();
      const sub = refreshTokens.get(req.body.refresh_token);
      refreshTokens.delete(req.body.refresh_token);
      const claims = sub == null ? undefined : users.get(sub);
      if (sub == null || claims == null) {
        return res.status(400).json({ error: 'invalid_grant' });
      }
      return res.json({
        access_token: crypto.randomUUID(),
        token_type: 'Bearer',
        expires_in: 300,
        id_token: await signIdToken(claims),
        refresh_token: issueRefreshToken(sub),
      });
    }

    const pending = codes.get(req.body.code);
    codes.delete(req.body.code);
    const challenge = crypto
      .createHash('sha256')
      .update(String(req.body.code_verifier ?? ''))
      .digest('base64url');
    if (pending == null || challenge !== pending.codeChallenge) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    const sub = String(pending.claims.sub);
    users.set(sub, pending.claims);
    res.json({
      access_token: crypto.randomUUID(),
      token_type: 'Bearer',
      expires_in: 300,
      id_token: await signIdToken({ ...pending.claims, nonce: pending.nonce }),
      ...(pending.scope.split(' ').includes('offline_access')
        ? { refresh_token: issueRefreshToken(sub) }
        : {}),
    });
  });

  const server: Server = await new Promise(resolve => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}/application/o/hyperdx/`;

  return {
    issuer,
    /** Mints a code for the authorization request in `authorizationUrl`. */
    authorize(authorizationUrl: string, claims: Record<string, unknown>) {
      const params = new URL(authorizationUrl).searchParams;
      const code = crypto.randomUUID();
      codes.set(code, {
        claims,
        nonce: params.get('nonce') ?? '',
        codeChallenge: params.get('code_challenge') ?? '',
        scope: params.get('scope') ?? '',
      });
      return { code, state: params.get('state') ?? '' };
    },
    /** Changes a user's claims, e.g. their groups, as an IdP admin would. */
    updateUser(sub: string, claims: Record<string, unknown>) {
      users.set(sub, { ...users.get(sub), ...claims });
    },
    /** Disables a user: their refresh tokens stop working. */
    disableUser(sub: string) {
      users.delete(sub);
      for (const [token, owner] of refreshTokens) {
        if (owner === sub) {
          refreshTokens.delete(token);
        }
      }
    },
    setOutage(value: boolean) {
      outage = value;
    },
    /** Runs while a refresh request is in flight, before it is answered. */
    setBeforeRefresh(hook: (() => Promise<void>) | null) {
      beforeRefresh = hook;
    },
    stop: () => new Promise<void>(resolve => server.close(() => resolve())),
  };
}
