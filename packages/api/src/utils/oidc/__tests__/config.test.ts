import { type OidcEnv, parseOidcSettings } from '@/utils/oidc/config';

const baseEnv: OidcEnv = {
  issuerUrl: 'https://auth.example.com/application/o/hyperdx/',
  clientId: 'client',
  clientSecret: 'secret',
  redirectUri: '',
  scopes: '',
  displayName: '',
  groupsClaim: '',
  teamMapping: '{"hdx-platform":"Platform","hdx-payments":"Payments"}',
  teamGroupPrefix: '',
  sessionMaxAgeHours: '',
  identityMaxAgeHours: '',
  revalidateIntervalMinutes: '',
  allowInsecureHttp: false,
  frontendUrl: 'https://hyperdx.example.com/',
};

describe('parseOidcSettings', () => {
  it('returns null when no issuer is set', () => {
    expect(parseOidcSettings({ ...baseEnv, issuerUrl: '' })).toBeNull();
  });

  it('applies defaults and derives the redirect URI from FRONTEND_URL', () => {
    const settings = parseOidcSettings(baseEnv);
    expect(settings).toMatchObject({
      scopes: 'openid email profile offline_access',
      groupsClaim: 'groups',
      displayName: 'SSO',
      sessionMaxAgeMs: 24 * 60 * 60 * 1000,
      identityMaxAgeMs: 24 * 60 * 60 * 1000,
      revalidateIntervalMs: 15 * 60 * 1000,
    });
    expect(settings?.redirectUri.href).toBe(
      'https://hyperdx.example.com/api/login/oidc/callback',
    );
  });

  it('keeps the team mapping in declared order', () => {
    expect(parseOidcSettings(baseEnv)?.teamMapping).toEqual([
      { group: 'hdx-platform', teamName: 'Platform' },
      { group: 'hdx-payments', teamName: 'Payments' },
    ]);
  });

  it.each([
    [{ clientId: '' }, /OIDC_CLIENT_ID/],
    [{ clientSecret: '' }, /OIDC_CLIENT_SECRET/],
    [{ teamMapping: 'not json' }, /not valid JSON/],
    [{ teamMapping: '["a"]' }, /JSON object/],
    [{ teamMapping: '{"a":""}' }, /JSON object/],
    [{ teamMapping: '' }, /OIDC_TEAM_MAPPING or OIDC_TEAM_GROUP_PREFIX/],
    [{ scopes: 'email profile' }, /must include "openid"/],
    [{ sessionMaxAgeHours: '-1' }, /non-negative/],
    [{ identityMaxAgeHours: '0' }, /must be above 0/],
    [
      { identityMaxAgeHours: '1', revalidateIntervalMinutes: '30' },
      /at most a third/,
    ],
    [{ issuerUrl: 'http://auth.local/' }, /must use https/],
    [{ frontendUrl: '' }, /OIDC_REDIRECT_URI or FRONTEND_URL/],
  ])('rejects %j', (override, message) => {
    expect(() => parseOidcSettings({ ...baseEnv, ...override })).toThrow(
      message,
    );
  });

  it('allows http only when explicitly enabled', () => {
    const settings = parseOidcSettings({
      ...baseEnv,
      issuerUrl: 'http://localhost:9000/application/o/hyperdx/',
      frontendUrl: 'http://localhost:8080',
      allowInsecureHttp: true,
    });
    expect(settings?.issuerUrl.protocol).toBe('http:');
  });

  it('accepts a prefix without a mapping and 0 to disable the session cap', () => {
    const settings = parseOidcSettings({
      ...baseEnv,
      teamMapping: '',
      teamGroupPrefix: 'hyperdx-',
      sessionMaxAgeHours: '0',
    });
    expect(settings).toMatchObject({
      teamMapping: [],
      teamGroupPrefix: 'hyperdx-',
      sessionMaxAgeMs: 0,
    });
  });
});
