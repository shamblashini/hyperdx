import { OidcUserGoneError, provisionOidcUser } from '@/controllers/oidcUser';
import User, { type UserDocument } from '@/models/user';
import {
  getCounter,
  getStaticFeatureFlags,
  setBusinessContext,
  withSpan,
} from '@/utils/instrumentation';
import logger from '@/utils/logger';
import { resolveTeamTarget } from '@/utils/oidc/claims';
import { refreshOidcIdentity } from '@/utils/oidc/client';
import type { OidcSettings } from '@/utils/oidc/config';
import { decryptToken } from '@/utils/tokenEncryption';

// Long enough for one refresh round trip, short enough that a replica dying
// mid-refresh only delays that user by a few minutes.
const LEASE_MS = 2 * 60 * 1000;
// After the IdP fails to answer, wait before asking about this user again.
const RETRY_BACKOFF_MS = 5 * 60 * 1000;
const MAX_USERS_PER_SWEEP = 500;

type RevalidationOutcome =
  | 'verified'
  | 'revoked_refused'
  | 'revoked_no_team'
  | 'revoked_unreadable_token'
  | 'error';

const revalidations = getCounter('hyperdx.auth.oidc.revalidations', {
  description: 'Background re-checks of OIDC users with the IdP, by outcome.',
});

/**
 * Claims one user whose IdP confirmation is older than the revalidation
 * interval. The lease is a conditional update, so two API replicas never
 * refresh the same token at once. That matters: IdPs that rotate refresh
 * tokens (Authentik does) treat the second use of a rotated token as theft
 * and refuse it.
 */
function claimDueUser(settings: OidcSettings, now: number) {
  return User.findOneAndUpdate(
    {
      oidcSubject: { $type: 'string' },
      oidcRefreshToken: { $type: 'string' },
      oidcVerifiedAt: { $lt: new Date(now - settings.revalidateIntervalMs) },
      $or: [
        { oidcRevalidationLockedUntil: { $exists: false } },
        { oidcRevalidationLockedUntil: { $lt: new Date(now) } },
      ],
    },
    { $set: { oidcRevalidationLockedUntil: new Date(now + LEASE_MS) } },
    { new: true, sort: { oidcVerifiedAt: 1 } },
  ).select('+oidcRefreshToken');
}

/**
 * Stops trusting a user until they log in again. Their sessions and access
 * key fail the identity check in middleware/auth.ts from this point on. The
 * key itself is kept, so someone whose IdP session merely expired gets the
 * same key back after their next login.
 */
async function revokeOidcUser(user: UserDocument) {
  await User.updateOne(
    // Matching the claimed timestamp leaves alone a user who logged in again
    // while their old token was being checked.
    { _id: user._id, oidcVerifiedAt: user.oidcVerifiedAt },
    {
      $set: { oidcVerifiedAt: null },
      $unset: { oidcRefreshToken: '', oidcRevalidationLockedUntil: '' },
    },
  );
}

async function revalidateUser(
  settings: OidcSettings,
  user: UserDocument,
): Promise<RevalidationOutcome> {
  return withSpan('oidc.revalidate.user', async span => {
    setBusinessContext({
      teamId: user.team?.toString(),
      userId: user._id.toString(),
      email: user.email,
      ...getStaticFeatureFlags(),
    });

    let refreshToken: string;
    try {
      refreshToken = await decryptToken(user.oidcRefreshToken ?? '');
    } catch (err) {
      // Most likely TOKEN_ENCRYPTION_KEY changed. The token is unusable, so
      // the user has to log in again either way.
      logger.error(
        { err, userId: user._id },
        'Cannot decrypt stored OIDC refresh token',
      );
      await revokeOidcUser(user);
      return 'revoked_unreadable_token';
    }

    const result = await refreshOidcIdentity(settings, refreshToken, {
      issuer: user.oidcIssuer ?? '',
      subject: user.oidcSubject ?? '',
    });
    if (result.kind === 'refused') {
      span.setAttribute('oidc.refresh.error', result.error);
      await revokeOidcUser(user);
      return 'revoked_refused';
    }

    const target = resolveTeamTarget(result.identity.groups, settings);
    span.setAttribute('oidc.groups.count', result.identity.groups.length);
    if (target == null) {
      await revokeOidcUser(user);
      return 'revoked_no_team';
    }

    const { teamChanged } = await provisionOidcUser(result.identity, target, {
      source: 'revalidation',
      refreshToken: result.refreshToken,
    });
    span.setAttributes({
      'oidc.team.group': target.group,
      'oidc.team.changed': teamChanged,
    });
    await User.updateOne(
      { _id: user._id },
      { $unset: { oidcRevalidationLockedUntil: '' } },
    );
    return 'verified';
  });
}

/**
 * Re-checks every OIDC user that is due with the IdP. A user the IdP refuses
 * (disabled, deleted, IdP session ended) or who no longer has a mapped group
 * loses access right away. When the IdP cannot be reached nobody is revoked;
 * their access then lapses on its own after OIDC_IDENTITY_MAX_AGE_HOURS, so
 * an outage can delay revocation by at most that long.
 */
export async function revalidateDueOidcUsers(settings: OidcSettings) {
  const counts: Partial<Record<RevalidationOutcome, number>> = {};
  for (let i = 0; i < MAX_USERS_PER_SWEEP; i++) {
    const now = Date.now();
    const user = await claimDueUser(settings, now);
    if (user == null) {
      break;
    }

    let outcome: RevalidationOutcome;
    try {
      outcome = await revalidateUser(settings, user);
    } catch (err) {
      if (err instanceof OidcUserGoneError) {
        // Deleted by an admin while its refresh was in flight.
        continue;
      }
      logger.warn(
        { err, userId: user._id },
        'OIDC revalidation failed; will retry',
      );
      await User.updateOne(
        { _id: user._id },
        {
          $set: {
            oidcRevalidationLockedUntil: new Date(now + RETRY_BACKOFF_MS),
          },
        },
      );
      outcome = 'error';
    }

    revalidations.add(1, { outcome });
    counts[outcome] = (counts[outcome] ?? 0) + 1;
    if (outcome.startsWith('revoked')) {
      logger.info(
        { userId: user._id, teamId: user.team, outcome },
        'OIDC user revoked after revalidation',
      );
    }
  }
  return counts;
}

/** Runs the sweep on an interval in this process. Returns a stop function. */
export function startOidcRevalidation(settings: OidcSettings) {
  if (settings.revalidateIntervalMs === 0) {
    return () => {};
  }
  // Every replica ticks; the per-user lease keeps them from doubling up.
  // A tick is cheap when nobody is due: one indexed findOneAndUpdate.
  const tickMs = Math.min(60 * 1000, settings.revalidateIntervalMs);
  let running = false;
  const timer = setInterval(() => {
    if (running) {
      return;
    }
    running = true;
    revalidateDueOidcUsers(settings)
      .catch(err => logger.error({ err }, 'OIDC revalidation sweep failed'))
      .finally(() => {
        running = false;
      });
  }, tickMs);
  timer.unref();
  return () => clearInterval(timer);
}
