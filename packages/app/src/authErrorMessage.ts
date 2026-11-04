// Keys are the `err` query values the API redirects to /login with
// (middleware/auth.ts and routers/api/oidc.ts in packages/api).
const AUTH_ERROR_MESSAGES: Record<string, string> = {
  missing: 'Please provide a valid email and password',
  invalid: 'Email or password is invalid',
  authFail: 'Failed to login with email and password, please try again.',
  passwordAuthNotAllowed:
    'Password authentication is not allowed by your team admin.',
  teamAlreadyExists: 'Team already exists, please login instead.',
  oidcDenied: 'Sign-in was cancelled or denied by your identity provider.',
  oidcExpired: 'Your sign-in attempt expired, please try again.',
  oidcNoTeam:
    'Your account is not in a group that has access. Ask your admin to add you to a HyperDX group.',
  oidcMissingEmail:
    'Your identity provider did not share an email address. Ask your admin to enable the email scope.',
  oidcEmailUnverified:
    'An account with this email already exists, but your identity provider has not verified the email, so it cannot be linked.',
  oidcEmailConflict:
    'This email is already linked to a different single sign-on account. Contact your admin.',
  oidcFailed: 'Single sign-on failed, please try again.',
};

export function getAuthErrorMessage(err: string | string[]): string {
  const code = Array.isArray(err) ? err[0] : err;
  // hasOwn so a crafted `?err=toString` cannot reach Object.prototype.
  return Object.hasOwn(AUTH_ERROR_MESSAGES, code)
    ? AUTH_ERROR_MESSAGES[code]
    : 'Unknown error occurred, please try again later.';
}
