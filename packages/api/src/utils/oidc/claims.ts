import { z } from 'zod';

import type { OidcSettings } from './config';

export type OidcIdentity = {
  issuer: string;
  subject: string;
  email: string;
  emailVerified: boolean;
  name: string;
  groups: string[];
};

export type TeamTarget = {
  // The IdP group the team is bound to; it identifies the team across renames.
  group: string;
  // Used only when the team has to be created or bound for the first time.
  teamName: string;
};

const ClaimsSchema = z
  .object({
    iss: z.string().min(1),
    sub: z.string().min(1),
    email: z.string().trim().toLowerCase().email().optional(),
    // Some providers send "true"/"false" strings.
    email_verified: z
      .union([z.boolean(), z.enum(['true', 'false'])])
      .optional()
      .transform(v => v === true || v === 'true'),
    name: z.string().optional(),
    preferred_username: z.string().optional(),
  })
  .passthrough();

export class OidcClaimsError extends Error {
  constructor(
    // Low-cardinality reason, used as a metric attribute and a login error code.
    readonly reason: 'missing_email' | 'invalid_claims',
    message: string,
  ) {
    super(message);
    this.name = 'OidcClaimsError';
  }
}

function readGroups(claims: Record<string, unknown>, claimName: string) {
  const value = claims[claimName];
  if (Array.isArray(value)) {
    return value.filter((g): g is string => typeof g === 'string' && g !== '');
  }
  // A single group is sometimes sent as a bare string.
  if (typeof value === 'string' && value !== '') {
    return [value];
  }
  return [];
}

/**
 * Merges ID token and userinfo claims into the identity HyperDX needs. The ID
 * token wins for `iss`/`sub`; userinfo fills claims the provider leaves out of
 * the ID token (Authentik can be configured either way).
 */
export function toOidcIdentity(
  idTokenClaims: Record<string, unknown>,
  userInfo: Record<string, unknown> | undefined,
  groupsClaim: string,
): OidcIdentity {
  const merged = { ...userInfo, ...stripUndefined(idTokenClaims) };
  const parsed = ClaimsSchema.safeParse(merged);
  if (!parsed.success) {
    throw new OidcClaimsError(
      'invalid_claims',
      `OIDC claims failed validation: ${parsed.error.issues
        .map(i => i.path.join('.'))
        .join(', ')}`,
    );
  }
  const claims = parsed.data;
  if (!claims.email) {
    throw new OidcClaimsError(
      'missing_email',
      'OIDC provider did not return an email claim; add the "email" scope',
    );
  }

  const groups = readGroups(idTokenClaims, groupsClaim);
  return {
    issuer: claims.iss,
    subject: claims.sub,
    email: claims.email,
    emailVerified: claims.email_verified,
    name: claims.name || claims.preferred_username || claims.email,
    groups:
      groups.length > 0 || userInfo == null
        ? groups
        : readGroups(userInfo, groupsClaim),
  };
}

function stripUndefined(obj: Record<string, unknown>) {
  return Object.fromEntries(
    Object.entries(obj).filter(([, v]) => v !== undefined),
  );
}

/**
 * Picks the team a user belongs to from their IdP groups. A HyperDX user has
 * exactly one team, so the choice must be deterministic: explicit mappings in
 * the order configured, then prefixed groups in alphabetical order.
 */
export function resolveTeamTarget(
  groups: string[],
  settings: Pick<OidcSettings, 'teamMapping' | 'teamGroupPrefix'>,
): TeamTarget | null {
  const userGroups = new Set(groups);

  const mapped = settings.teamMapping.find(entry =>
    userGroups.has(entry.group),
  );
  if (mapped) {
    return { group: mapped.group, teamName: mapped.teamName };
  }

  const prefix = settings.teamGroupPrefix;
  if (prefix) {
    const prefixed = [...userGroups]
      .filter(g => g.startsWith(prefix) && g.length > prefix.length)
      .sort();
    if (prefixed.length > 0) {
      return { group: prefixed[0], teamName: prefixed[0].slice(prefix.length) };
    }
  }

  return null;
}
