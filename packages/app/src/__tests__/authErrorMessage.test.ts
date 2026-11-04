import { getAuthErrorMessage } from '@/authErrorMessage';

describe('getAuthErrorMessage', () => {
  it('maps known codes, including OIDC ones', () => {
    expect(getAuthErrorMessage('authFail')).toMatch(/email and password/);
    expect(getAuthErrorMessage('oidcNoTeam')).toMatch(/not in a group/);
  });

  it('uses the first value of a repeated param', () => {
    expect(getAuthErrorMessage(['oidcExpired', 'authFail'])).toMatch(/expired/);
  });

  it('falls back for unknown codes and prototype keys', () => {
    const fallback = 'Unknown error occurred, please try again later.';
    expect(getAuthErrorMessage('nope')).toBe(fallback);
    expect(getAuthErrorMessage('toString')).toBe(fallback);
    expect(getAuthErrorMessage('__proto__')).toBe(fallback);
  });
});
