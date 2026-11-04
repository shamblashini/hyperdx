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
};

/**
 * Just enough of an OIDC provider for the authorization code flow with PKCE:
 * discovery, JWKS and a token endpoint issuing RS256 ID tokens. Tests skip the
 * browser leg by reading the authorization URL HyperDX redirects to and
 * minting a code for it with `authorize`.
 */
export async function startFakeOidcProvider() {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'test', alg: 'RS256' };
  const codes = new Map<string, PendingCode>();

  const app = express();
  app.use(express.urlencoded({ extended: false }));

  let issuer = '';
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
    const pending = codes.get(req.body.code);
    codes.delete(req.body.code);
    const challenge = crypto
      .createHash('sha256')
      .update(String(req.body.code_verifier ?? ''))
      .digest('base64url');
    if (
      pending == null ||
      req.body.client_secret !== FAKE_CLIENT_SECRET ||
      challenge !== pending.codeChallenge
    ) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    const idToken = await new SignJWT({
      ...pending.claims,
      nonce: pending.nonce,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'test' })
      .setIssuer(issuer)
      .setAudience(FAKE_CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
    res.json({
      access_token: crypto.randomUUID(),
      token_type: 'Bearer',
      expires_in: 300,
      id_token: idToken,
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
      });
      return { code, state: params.get('state') ?? '' };
    },
    stop: () => new Promise<void>(resolve => server.close(() => resolve())),
  };
}
