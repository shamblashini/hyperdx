import crypto from 'crypto';

import { revalidateDueOidcUsers } from '@/controllers/oidcRevalidation';
import { getAgent, getLoggedInAgent, getServer } from '@/fixtures';
import User from '@/models/user';
import { isPasswordAuthEnabled, oidcSettings } from '@/utils/oidc/config';
import {
  createAesGcmProvider,
  isTokenEnvelope,
  registerTokenEncryptionProvider,
  setActiveTokenEncryptionProvider,
} from '@/utils/tokenEncryption';

import { startFakeOidcProvider } from './fakeOidcProvider';

jest.mock('@/utils/oidc/config', () => ({
  oidcSettings: {
    issuerUrl: new URL('http://127.0.0.1:1/'),
    clientId: 'hyperdx-test',
    clientSecret: 'hyperdx-test-secret',
    redirectUri: new URL('http://app:8080/api/login/oidc/callback'),
    scopes: 'openid email profile offline_access',
    displayName: 'Authentik',
    groupsClaim: 'groups',
    teamMapping: [
      { group: 'hdx-platform', teamName: 'Platform' },
      { group: 'hdx-payments', teamName: 'Payments' },
    ],
    teamGroupPrefix: '',
    sessionMaxAgeMs: 0,
    identityMaxAgeMs: 24 * 60 * 60 * 1000,
    revalidateIntervalMs: 15 * 60 * 1000,
    allowInsecureHttp: true,
  },
  isPasswordAuthEnabled: jest.fn(() => true),
}));

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const { realFetch } = globalThis as unknown as { realFetch: typeof fetch };

describe('OIDC revalidation of sessions and access keys', () => {
  const server = getServer();
  let idp: Awaited<ReturnType<typeof startFakeOidcProvider>>;
  const realNow = Date.now;
  let clock = 0;

  // Moves "now" for HyperDX (Date.now) without touching timers.
  const advance = (ms: number) => {
    clock += ms;
  };

  beforeAll(async () => {
    jest.mocked(global.fetch).mockImplementation(realFetch);
    const key = crypto.randomBytes(32);
    registerTokenEncryptionProvider(
      createAesGcmProvider('test-aes', () => key),
    );
    setActiveTokenEncryptionProvider('test-aes');
    idp = await startFakeOidcProvider();
    if (oidcSettings == null) {
      throw new Error('mock settings missing');
    }
    oidcSettings.issuerUrl = new URL(idp.issuer);
    await server.start();
  });

  beforeEach(() => {
    clock = 0;
    Date.now = () => realNow() + clock;
    idp.setOutage(false);
    idp.setBeforeRefresh(null);
  });

  afterEach(async () => {
    Date.now = realNow;
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
    await idp.stop();
  });

  const sweep = () => {
    if (oidcSettings == null) {
      throw new Error('mock settings missing');
    }
    return revalidateDueOidcUsers(oidcSettings);
  };

  const login = async (sub: string, groups = ['hdx-platform']) => {
    const agent = getAgent(server);
    const start = await agent.get('/login/oidc').expect(303);
    const { code, state } = idp.authorize(start.headers.location, {
      sub,
      email: `${sub}@example.com`,
      email_verified: true,
      name: sub,
      groups,
    });
    await agent.get('/login/oidc/callback').query({ code, state }).expect(303);
    const me = await agent.get('/me').expect(200);
    return { agent, accessKey: me.body.accessKey as string };
  };

  const callApi = (accessKey: string) =>
    getAgent(server)
      .get('/api/v2/team')
      .set('Authorization', `Bearer ${accessKey}`);

  it('stores the refresh token encrypted', async () => {
    await login('alice');
    const user = await User.findOne({ oidcSubject: 'alice' }).select(
      '+oidcRefreshToken',
    );
    expect(user?.oidcRefreshToken).toMatch(/^v1:test-aes:/);
    expect(isTokenEnvelope(user?.oidcRefreshToken ?? '')).toBe(true);
  });

  it('keeps the key working while the IdP keeps vouching for the user', async () => {
    const { accessKey } = await login('alice');
    await callApi(accessKey).expect(200);

    for (let i = 0; i < 4; i++) {
      advance(8 * HOUR);
      expect(await sweep()).toEqual({ verified: 1 });
      await callApi(accessKey).expect(200);
    }
  });

  it('cuts off the key and the session once the user is disabled in the IdP', async () => {
    const { agent, accessKey } = await login('alice');
    idp.disableUser('alice');

    // Not due yet: nothing happens before the revalidation interval.
    expect(await sweep()).toEqual({});
    await callApi(accessKey).expect(200);

    advance(16 * MINUTE);
    expect(await sweep()).toEqual({ revoked_refused: 1 });
    await callApi(accessKey).expect(401);
    await agent.get('/me').expect(401);
  });

  it('cuts off a user removed from every mapped group', async () => {
    const { accessKey } = await login('alice');
    idp.updateUser('alice', { groups: ['unrelated'] });

    advance(16 * MINUTE);
    expect(await sweep()).toEqual({ revoked_no_team: 1 });
    await callApi(accessKey).expect(401);
  });

  it('moves a user whose group changed without waiting for a login', async () => {
    const { accessKey } = await login('alice');
    idp.updateUser('alice', { groups: ['hdx-payments'] });

    advance(16 * MINUTE);
    expect(await sweep()).toEqual({ verified: 1 });
    const team = await callApi(accessKey).expect(200);
    expect(team.body.data.name).toBe('Payments');
  });

  it('does not revoke anyone during an IdP outage, then lapses after the max age', async () => {
    const { accessKey } = await login('alice');
    idp.setOutage(true);

    advance(16 * MINUTE);
    expect(await sweep()).toEqual({ error: 1 });
    await callApi(accessKey).expect(200);
    // Backed off: no second attempt right away.
    expect(await sweep()).toEqual({});

    advance(24 * HOUR);
    await callApi(accessKey).expect(401);

    idp.setOutage(false);
    expect(await sweep()).toEqual({ verified: 1 });
    await callApi(accessKey).expect(200);
  });

  it('refreshes once when two replicas sweep at the same time', async () => {
    const { accessKey } = await login('alice');
    advance(16 * MINUTE);

    const results = await Promise.all([sweep(), sweep()]);
    expect(results.map(r => r.verified ?? 0).reduce((a, b) => a + b)).toBe(1);
    expect(results.some(r => r.revoked_refused)).toBe(false);
    await callApi(accessKey).expect(200);
  });

  it('gives the same key back after the user logs in again', async () => {
    const { accessKey } = await login('alice');
    idp.disableUser('alice');
    advance(16 * MINUTE);
    await sweep();
    await callApi(accessKey).expect(401);

    const again = await login('alice');
    expect(again.accessKey).toBe(accessKey);
    await callApi(accessKey).expect(200);
  });

  it('does not recreate a user an admin deletes while their refresh is in flight', async () => {
    await login('alice');
    idp.setBeforeRefresh(async () => {
      await User.deleteOne({ oidcSubject: 'alice' });
    });

    advance(16 * MINUTE);
    await sweep();
    expect(await User.countDocuments({ oidcSubject: 'alice' })).toBe(0);
  });

  it('rejects password-only accounts once password auth is disabled', async () => {
    const { user, agent } = await getLoggedInAgent(server);
    await callApi(user.accessKey).expect(200);

    jest.mocked(isPasswordAuthEnabled).mockReturnValue(false);
    try {
      await callApi(user.accessKey).expect(401);
      await agent.get('/me').expect(401);
    } finally {
      jest.mocked(isPasswordAuthEnabled).mockReturnValue(true);
    }
  });
});
