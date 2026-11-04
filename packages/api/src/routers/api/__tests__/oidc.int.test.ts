import { getAgent, getLoggedInAgent, getServer } from '@/fixtures';
import Team from '@/models/team';
import User from '@/models/user';
import { isPasswordAuthEnabled, oidcSettings } from '@/utils/oidc/config';

import {
  FAKE_CLIENT_ID,
  FAKE_CLIENT_SECRET,
  startFakeOidcProvider,
} from './fakeOidcProvider';

// The real module reads env at import; the provider's port is only known once
// it listens, so tests fill in issuerUrl before the first login.
jest.mock('@/utils/oidc/config', () => ({
  oidcSettings: {
    issuerUrl: new URL('http://127.0.0.1:1/'),
    clientId: 'hyperdx-test',
    clientSecret: 'hyperdx-test-secret',
    redirectUri: new URL('http://app:8080/api/login/oidc/callback'),
    scopes: 'openid email profile',
    displayName: 'Authentik',
    groupsClaim: 'groups',
    teamMapping: [
      { group: 'hdx-platform', teamName: 'Platform' },
      { group: 'hdx-payments', teamName: 'Payments' },
    ],
    teamGroupPrefix: 'hyperdx-',
    sessionMaxAgeMs: 60 * 60 * 1000,
    identityMaxAgeMs: 24 * 60 * 60 * 1000,
    revalidateIntervalMs: 15 * 60 * 1000,
    allowInsecureHttp: true,
  },
  isPasswordAuthEnabled: jest.fn(() => true),
}));

const FRONTEND = 'http://app:8080';
// jest.setup.ts stubs fetch; openid-client needs the real one to reach the IdP.
const { realFetch } = globalThis as unknown as { realFetch: typeof fetch };

describe('OIDC login', () => {
  const server = getServer();
  let idp: Awaited<ReturnType<typeof startFakeOidcProvider>>;

  beforeAll(async () => {
    jest.mocked(global.fetch).mockImplementation(realFetch);
    idp = await startFakeOidcProvider();
    if (oidcSettings == null) {
      throw new Error('mock settings missing');
    }
    oidcSettings.issuerUrl = new URL(idp.issuer);
    expect(oidcSettings.clientId).toBe(FAKE_CLIENT_ID);
    expect(oidcSettings.clientSecret).toBe(FAKE_CLIENT_SECRET);
    await server.start();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
    await idp.stop();
  });

  const claimsFor = (
    sub: string,
    overrides: Record<string, unknown> = {},
  ): Record<string, unknown> => ({
    sub,
    email: `${sub}@example.com`,
    email_verified: true,
    name: `User ${sub}`,
    groups: ['hdx-platform'],
    ...overrides,
  });

  const login = async (
    claims: Record<string, unknown>,
    agent = getAgent(server),
  ) => {
    const start = await agent.get('/login/oidc').expect(303);
    const { code, state } = idp.authorize(start.headers.location, claims);
    const callback = await agent
      .get('/login/oidc/callback')
      .query({ code, state })
      .expect(303);
    return { agent, location: callback.headers.location };
  };

  it('redirects to the provider with PKCE, state and nonce', async () => {
    const res = await getAgent(server).get('/login/oidc').expect(303);
    const url = new URL(res.headers.location);
    expect(url.href.startsWith(`${idp.issuer}authorize`)).toBe(true);
    expect(url.searchParams.get('client_id')).toBe(FAKE_CLIENT_ID);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('redirect_uri')).toBe(
      `${FRONTEND}/api/login/oidc/callback`,
    );
    for (const param of ['state', 'nonce', 'code_challenge']) {
      expect(url.searchParams.get(param)).toBeTruthy();
    }
  });

  it('creates the team and user on first login and signs them in', async () => {
    const { agent, location } = await login(claimsFor('alice'));
    expect(location).toBe(`${FRONTEND}/`);

    const me = await agent.get('/me').expect(200);
    expect(me.body.email).toBe('alice@example.com');
    expect(me.body.team.name).toBe('Platform');

    const team = await Team.findOne({ oidcGroup: 'hdx-platform' });
    expect(team?.name).toBe('Platform');
    expect(team?.collectorAuthenticationEnforced).toBe(true);
  });

  it('keeps teams separate, including their API keys', async () => {
    const { agent: alice } = await login(claimsFor('alice'));
    const { agent: bob } = await login(
      claimsFor('bob', { groups: ['hyperdx-search'] }),
    );

    const aliceTeam = (await alice.get('/team').expect(200)).body;
    const bobTeam = (await bob.get('/team').expect(200)).body;
    expect(aliceTeam.name).toBe('Platform');
    expect(bobTeam.name).toBe('search');
    expect(bobTeam.apiKey).not.toBe(aliceTeam.apiKey);
    expect(await Team.countDocuments()).toBe(2);
  });

  it('reuses the user by subject and moves them when their group changes', async () => {
    await login(claimsFor('alice'));
    const { agent } = await login(
      claimsFor('alice', {
        email: 'alice.renamed@example.com',
        groups: ['hdx-payments', 'hdx-other'],
      }),
    );

    const me = await agent.get('/me').expect(200);
    expect(me.body.team.name).toBe('Payments');
    expect(me.body.email).toBe('alice.renamed@example.com');
    expect(await User.countDocuments({ oidcSubject: 'alice' })).toBe(1);
  });

  it('binds the existing password team by name and links a verified email', async () => {
    const { team, user } = await getLoggedInAgent(server);
    await Team.updateOne({ _id: team._id }, { name: 'Platform' });

    const { agent } = await login(
      claimsFor('admin', { email: user.email.toUpperCase() }),
    );

    const me = await agent.get('/me').expect(200);
    expect(me.body.id).toBe(user._id.toString());
    expect(me.body.team.id).toBe(team._id.toString());
    expect((await Team.findById(team._id))?.oidcGroup).toBe('hdx-platform');
  });

  it('refuses to link a password account to an unverified email', async () => {
    const { user } = await getLoggedInAgent(server);
    const { location } = await login(
      claimsFor('mallory', { email: user.email, email_verified: false }),
    );
    expect(location).toBe(`${FRONTEND}/login?err=oidcEmailUnverified`);
    expect((await User.findById(user._id))?.oidcSubject).toBeUndefined();
  });

  it('refuses an email that belongs to another OIDC identity', async () => {
    await login(claimsFor('alice'));
    const { location } = await login(
      claimsFor('impostor', { email: 'alice@example.com' }),
    );
    expect(location).toBe(`${FRONTEND}/login?err=oidcEmailConflict`);
  });

  it('rejects users with no mapped group', async () => {
    const { agent, location } = await login(
      claimsFor('carol', { groups: ['unrelated'] }),
    );
    expect(location).toBe(`${FRONTEND}/login?err=oidcNoTeam`);
    await agent.get('/me').expect(401);
    expect(await User.countDocuments()).toBe(0);
    expect(await Team.countDocuments()).toBe(0);
  });

  it('rejects a callback whose state does not match the session', async () => {
    const agent = getAgent(server);
    const start = await agent.get('/login/oidc').expect(303);
    const { code } = idp.authorize(start.headers.location, claimsFor('alice'));
    const res = await agent
      .get('/login/oidc/callback')
      .query({ code, state: 'forged' })
      .expect(303);
    expect(res.headers.location).toBe(`${FRONTEND}/login?err=oidcFailed`);
    await agent.get('/me').expect(401);
  });

  it('rejects a callback without a pending login', async () => {
    const res = await getAgent(server)
      .get('/login/oidc/callback')
      .query({ code: 'x', state: 'y' })
      .expect(303);
    expect(res.headers.location).toBe(`${FRONTEND}/login?err=oidcExpired`);
  });

  it('cannot replay a callback', async () => {
    const agent = getAgent(server);
    const start = await agent.get('/login/oidc').expect(303);
    const { code, state } = idp.authorize(
      start.headers.location,
      claimsFor('alice'),
    );
    await agent.get('/login/oidc/callback').query({ code, state }).expect(303);
    await agent.get('/logout');
    const replay = await agent
      .get('/login/oidc/callback')
      .query({ code, state })
      .expect(303);
    expect(replay.headers.location).toBe(`${FRONTEND}/login?err=oidcExpired`);
  });

  it('ends the session once it is older than the configured max age', async () => {
    const { agent } = await login(claimsFor('alice'));
    await agent.get('/me').expect(200);

    const realNow = Date.now;
    try {
      Date.now = () => realNow() + 2 * 60 * 60 * 1000;
      await agent.get('/me').expect(401);
    } finally {
      Date.now = realNow;
    }
    await agent.get('/me').expect(401);
  });

  it('blocks every password entry point when password auth is disabled', async () => {
    jest.mocked(isPasswordAuthEnabled).mockReturnValue(false);
    try {
      const agent = getAgent(server);
      const loginRes = await agent
        .post('/login/password')
        .type('form')
        .send({ email: 'a@example.com', password: 'x' })
        .expect(303);
      expect(loginRes.headers.location).toBe(
        `${FRONTEND}/login?err=passwordAuthNotAllowed`,
      );
      await agent
        .post('/register/password')
        .set('Accept', 'application/json')
        .send({ email: 'a@example.com', password: 'x', confirmPassword: 'x' })
        .expect(403);
      await agent.post('/team/setup/some-token').type('form').expect(303);
      expect(await User.countDocuments()).toBe(0);

      const installation = await agent.get('/installation').expect(200);
      expect(installation.body.passwordAuthEnabled).toBe(false);
    } finally {
      jest.mocked(isPasswordAuthEnabled).mockReturnValue(true);
    }
  });

  it('reports SSO in /installation', async () => {
    const res = await getAgent(server).get('/installation').expect(200);
    expect(res.body).toMatchObject({
      passwordAuthEnabled: true,
      oidc: { enabled: true, displayName: 'Authentik' },
    });
  });
});
