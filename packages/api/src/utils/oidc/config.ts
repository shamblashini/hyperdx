import { z } from 'zod';

import * as config from '@/config';

// offline_access asks for a refresh token, which revalidation needs.
const DEFAULT_SCOPES = 'openid email profile offline_access';
const DEFAULT_GROUPS_CLAIM = 'groups';
const DEFAULT_DISPLAY_NAME = 'SSO';
const DEFAULT_SESSION_MAX_AGE_HOURS = 24;
const DEFAULT_IDENTITY_MAX_AGE_HOURS = 24;
const DEFAULT_REVALIDATE_INTERVAL_MINUTES = 15;

// JSON object of IdP group -> HyperDX team name. Key order is significant: a
// user in several mapped groups lands in the team of the first one listed.
const TeamMappingSchema = z
  .record(z.string().min(1), z.string().trim().min(1))
  .transform(record =>
    Object.entries(record).map(([group, teamName]) => ({ group, teamName })),
  );

type TeamMappingEntry = z.output<typeof TeamMappingSchema>[number];

export type OidcSettings = {
  issuerUrl: URL;
  clientId: string;
  clientSecret: string;
  redirectUri: URL;
  scopes: string;
  displayName: string;
  groupsClaim: string;
  teamMapping: TeamMappingEntry[];
  teamGroupPrefix: string;
  sessionMaxAgeMs: number;
  // How long after the IdP last vouched for a user (login or refresh) their
  // sessions and access key keep working.
  identityMaxAgeMs: number;
  // How often each user is re-checked with the IdP; 0 turns revalidation off.
  revalidateIntervalMs: number;
  allowInsecureHttp: boolean;
};

export type OidcEnv = {
  issuerUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string;
  displayName: string;
  groupsClaim: string;
  teamMapping: string;
  teamGroupPrefix: string;
  sessionMaxAgeHours: string;
  identityMaxAgeHours: string;
  revalidateIntervalMinutes: string;
  allowInsecureHttp: boolean;
  frontendUrl: string;
};

class OidcConfigError extends Error {
  constructor(message: string) {
    super(`Invalid OIDC configuration: ${message}`);
    this.name = 'OidcConfigError';
  }
}

function parseUrl(name: string, value: string): URL {
  try {
    return new URL(value);
  } catch {
    throw new OidcConfigError(`${name} is not a valid URL`);
  }
}

function parseDuration(name: string, raw: string, fallback: number) {
  if (!raw) {
    return fallback;
  }
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) {
    throw new OidcConfigError(`${name} must be a non-negative number`);
  }
  return value;
}

/**
 * Returns null when OIDC is not configured. Throws on a partial or invalid
 * configuration so a typo fails startup instead of silently disabling SSO.
 */
export function parseOidcSettings(env: OidcEnv): OidcSettings | null {
  if (!env.issuerUrl) {
    return null;
  }
  if (!env.clientId) {
    throw new OidcConfigError('OIDC_CLIENT_ID is required');
  }
  if (!env.clientSecret) {
    throw new OidcConfigError('OIDC_CLIENT_SECRET is required');
  }

  const issuerUrl = parseUrl('OIDC_ISSUER_URL', env.issuerUrl);

  let redirectUri: URL;
  if (env.redirectUri) {
    redirectUri = parseUrl('OIDC_REDIRECT_URI', env.redirectUri);
  } else if (env.frontendUrl) {
    redirectUri = parseUrl(
      'FRONTEND_URL',
      `${env.frontendUrl.replace(/\/+$/, '')}/api/login/oidc/callback`,
    );
  } else {
    throw new OidcConfigError(
      'set OIDC_REDIRECT_URI or FRONTEND_URL so the callback URL is known',
    );
  }

  for (const [name, url] of [
    ['OIDC_ISSUER_URL', issuerUrl],
    ['OIDC_REDIRECT_URI', redirectUri],
  ] as const) {
    if (url.protocol !== 'https:' && !env.allowInsecureHttp) {
      throw new OidcConfigError(
        `${name} must use https (set OIDC_ALLOW_INSECURE_HTTP=true for local testing only)`,
      );
    }
  }

  let teamMapping: TeamMappingEntry[] = [];
  if (env.teamMapping) {
    let raw: unknown;
    try {
      raw = JSON.parse(env.teamMapping);
    } catch {
      throw new OidcConfigError('OIDC_TEAM_MAPPING is not valid JSON');
    }
    const parsed = TeamMappingSchema.safeParse(raw);
    if (!parsed.success) {
      throw new OidcConfigError(
        'OIDC_TEAM_MAPPING must be a JSON object of {"<group>": "<team name>"}',
      );
    }
    teamMapping = parsed.data;
  }

  const teamGroupPrefix = env.teamGroupPrefix.trim();
  if (teamMapping.length === 0 && !teamGroupPrefix) {
    throw new OidcConfigError(
      'set OIDC_TEAM_MAPPING or OIDC_TEAM_GROUP_PREFIX so users can be assigned to a team',
    );
  }

  const sessionMaxAgeHours = parseDuration(
    'OIDC_SESSION_MAX_AGE_HOURS',
    env.sessionMaxAgeHours,
    DEFAULT_SESSION_MAX_AGE_HOURS,
  );
  const identityMaxAgeHours = parseDuration(
    'OIDC_IDENTITY_MAX_AGE_HOURS',
    env.identityMaxAgeHours,
    DEFAULT_IDENTITY_MAX_AGE_HOURS,
  );
  if (identityMaxAgeHours === 0) {
    throw new OidcConfigError('OIDC_IDENTITY_MAX_AGE_HOURS must be above 0');
  }
  const revalidateIntervalMinutes = parseDuration(
    'OIDC_REVALIDATE_INTERVAL_MINUTES',
    env.revalidateIntervalMinutes,
    DEFAULT_REVALIDATE_INTERVAL_MINUTES,
  );
  // Each user needs room for a few attempts inside the max age, or one slow
  // IdP response would lock them out.
  if (revalidateIntervalMinutes * 3 > identityMaxAgeHours * 60) {
    throw new OidcConfigError(
      'OIDC_REVALIDATE_INTERVAL_MINUTES must be at most a third of OIDC_IDENTITY_MAX_AGE_HOURS',
    );
  }

  const scopes = env.scopes.trim() || DEFAULT_SCOPES;
  if (!scopes.split(/\s+/).includes('openid')) {
    throw new OidcConfigError('OIDC_SCOPES must include "openid"');
  }

  return {
    issuerUrl,
    clientId: env.clientId,
    clientSecret: env.clientSecret,
    redirectUri,
    scopes,
    displayName: env.displayName.trim() || DEFAULT_DISPLAY_NAME,
    groupsClaim: env.groupsClaim.trim() || DEFAULT_GROUPS_CLAIM,
    teamMapping,
    teamGroupPrefix,
    sessionMaxAgeMs: sessionMaxAgeHours * 60 * 60 * 1000,
    identityMaxAgeMs: identityMaxAgeHours * 60 * 60 * 1000,
    revalidateIntervalMs: revalidateIntervalMinutes * 60 * 1000,
    allowInsecureHttp: env.allowInsecureHttp,
  };
}

export const oidcSettings = parseOidcSettings({
  issuerUrl: config.OIDC_ISSUER_URL,
  clientId: config.OIDC_CLIENT_ID,
  clientSecret: config.OIDC_CLIENT_SECRET,
  redirectUri: config.OIDC_REDIRECT_URI,
  scopes: config.OIDC_SCOPES,
  displayName: config.OIDC_DISPLAY_NAME,
  groupsClaim: config.OIDC_GROUPS_CLAIM,
  teamMapping: config.OIDC_TEAM_MAPPING,
  teamGroupPrefix: config.OIDC_TEAM_GROUP_PREFIX,
  sessionMaxAgeHours: config.OIDC_SESSION_MAX_AGE_HOURS,
  identityMaxAgeHours: config.OIDC_IDENTITY_MAX_AGE_HOURS,
  revalidateIntervalMinutes: config.OIDC_REVALIDATE_INTERVAL_MINUTES,
  allowInsecureHttp: config.OIDC_ALLOW_INSECURE_HTTP,
  frontendUrl: config.FRONTEND_URL,
});

if (config.PASSWORD_AUTH_DISABLED && oidcSettings == null) {
  throw new OidcConfigError(
    'PASSWORD_AUTH_DISABLED=true requires OIDC_ISSUER_URL, otherwise nobody can log in',
  );
}

export const isPasswordAuthEnabled = () => !config.PASSWORD_AUTH_DISABLED;
