import {
  OidcClaimsError,
  resolveTeamTarget,
  toOidcIdentity,
} from '@/utils/oidc/claims';

describe('toOidcIdentity', () => {
  const idToken = {
    iss: 'https://auth.example.com/application/o/hyperdx/',
    sub: 'abc123',
    email: 'Jane@Example.com',
    email_verified: true,
    name: 'Jane',
    groups: ['hdx-platform'],
  };

  it('normalizes the email and reads groups from the ID token', () => {
    expect(toOidcIdentity(idToken, undefined, 'groups')).toEqual({
      issuer: idToken.iss,
      subject: 'abc123',
      email: 'jane@example.com',
      emailVerified: true,
      name: 'Jane',
      groups: ['hdx-platform'],
    });
  });

  it('falls back to userinfo for claims missing from the ID token', () => {
    const identity = toOidcIdentity(
      { iss: idToken.iss, sub: 'abc123' },
      {
        sub: 'abc123',
        email: 'jane@example.com',
        email_verified: 'true',
        preferred_username: 'jane',
        roles: ['hdx-payments', 42],
      },
      'roles',
    );
    expect(identity).toMatchObject({
      emailVerified: true,
      name: 'jane',
      groups: ['hdx-payments'],
    });
  });

  it('does not let userinfo override the ID token subject', () => {
    const identity = toOidcIdentity(
      idToken,
      { sub: 'someone-else', email: 'x@example.com' },
      'groups',
    );
    expect(identity.subject).toBe('abc123');
    expect(identity.email).toBe('jane@example.com');
  });

  it('treats a missing email_verified as unverified', () => {
    const { email_verified: _, ...rest } = idToken;
    expect(toOidcIdentity(rest, undefined, 'groups').emailVerified).toBe(false);
  });

  it('throws a typed error when email is missing', () => {
    const { email: _, ...rest } = idToken;
    expect(() => toOidcIdentity(rest, undefined, 'groups')).toThrow(
      OidcClaimsError,
    );
  });
});

describe('resolveTeamTarget', () => {
  const settings = {
    teamMapping: [
      { group: 'hdx-platform', teamName: 'Platform' },
      { group: 'hdx-payments', teamName: 'Payments' },
    ],
    teamGroupPrefix: 'hyperdx-',
  };

  it('uses the first mapping in configured order, not group order', () => {
    expect(
      resolveTeamTarget(['hdx-payments', 'hdx-platform'], settings),
    ).toEqual({ group: 'hdx-platform', teamName: 'Platform' });
  });

  it('prefers mappings over prefixed groups', () => {
    expect(
      resolveTeamTarget(['hyperdx-aaa', 'hdx-payments'], settings),
    ).toEqual({ group: 'hdx-payments', teamName: 'Payments' });
  });

  it('picks the alphabetically first prefixed group and strips the prefix', () => {
    expect(
      resolveTeamTarget(['hyperdx-search', 'hyperdx-infra', 'other'], settings),
    ).toEqual({ group: 'hyperdx-infra', teamName: 'infra' });
  });

  it('ignores a group that is only the prefix', () => {
    expect(resolveTeamTarget(['hyperdx-'], settings)).toBeNull();
  });

  it('returns null when nothing matches', () => {
    expect(resolveTeamTarget(['other'], settings)).toBeNull();
    expect(resolveTeamTarget([], settings)).toBeNull();
  });
});
