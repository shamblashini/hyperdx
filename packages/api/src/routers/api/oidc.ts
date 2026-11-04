import express from 'express';

import * as config from '@/config';
import {
  OidcLoginRejectedError,
  provisionOidcUser,
} from '@/controllers/oidcUser';
import { redirectToDashboard } from '@/middleware/auth';
import {
  getCounter,
  getStaticFeatureFlags,
  setBusinessContext,
  withSpan,
} from '@/utils/instrumentation';
import logger from '@/utils/logger';
import { OidcClaimsError, resolveTeamTarget } from '@/utils/oidc/claims';
import {
  completeOidcLogin,
  PENDING_LOGIN_TTL_MS,
  startOidcLogin,
} from '@/utils/oidc/client';
import { oidcSettings } from '@/utils/oidc/config';

// Each value is both a metric attribute and the `err` code the login page
// renders, so keep the set small and fixed.
type OidcLoginOutcome =
  | 'success'
  | 'provider_error'
  | 'expired'
  | 'no_team'
  | 'missing_email'
  | 'email_unverified'
  | 'email_conflict'
  | 'failed';

const ERROR_CODES: Record<Exclude<OidcLoginOutcome, 'success'>, string> = {
  provider_error: 'oidcDenied',
  expired: 'oidcExpired',
  no_team: 'oidcNoTeam',
  missing_email: 'oidcMissingEmail',
  email_unverified: 'oidcEmailUnverified',
  email_conflict: 'oidcEmailConflict',
  failed: 'oidcFailed',
};

const oidcLogins = getCounter('hyperdx.auth.oidc.logins', {
  description: 'OIDC login callbacks, labeled by outcome.',
});

const router = express.Router();

function redirectWithError(
  res: express.Response,
  outcome: Exclude<OidcLoginOutcome, 'success'>,
) {
  oidcLogins.add(1, { outcome });
  res.redirect(
    303,
    `${config.FRONTEND_REDIRECT_BASE}/login?err=${ERROR_CODES[outcome]}`,
  );
}

router.get('/login/oidc', async (req, res) => {
  const settings = oidcSettings;
  if (settings == null) {
    return res.sendStatus(404);
  }
  try {
    const { authorizationUrl, pending } = await startOidcLogin(settings);
    req.session.oidcLogin = pending;
    req.session.save(err => {
      if (err) {
        logger.error({ err }, 'Failed to save session before OIDC redirect');
        return redirectWithError(res, 'failed');
      }
      res.redirect(303, authorizationUrl.href);
    });
  } catch (err) {
    logger.error({ err }, 'Failed to start OIDC login');
    redirectWithError(res, 'failed');
  }
});

router.get('/login/oidc/callback', async (req, res, next) => {
  const settings = oidcSettings;
  if (settings == null) {
    return res.sendStatus(404);
  }

  // Single use: a replayed callback finds nothing to compare against.
  const pending = req.session.oidcLogin;
  delete req.session.oidcLogin;

  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(req.query)) {
    if (typeof value === 'string') {
      query.append(key, value);
    }
  }

  if (query.has('error')) {
    logger.info(
      { error: query.get('error') },
      'OIDC provider returned an error to the callback',
    );
    return redirectWithError(res, 'provider_error');
  }
  if (
    pending == null ||
    Date.now() - pending.createdAt > PENDING_LOGIN_TTL_MS
  ) {
    return redirectWithError(res, 'expired');
  }

  try {
    await withSpan('oidc.login.callback', async span => {
      const identity = await completeOidcLogin(settings, pending, query);
      span.setAttributes({
        'oidc.issuer': identity.issuer,
        'oidc.email_verified': identity.emailVerified,
        'oidc.groups.count': identity.groups.length,
      });

      const target = resolveTeamTarget(identity.groups, settings);
      if (target == null) {
        logger.info(
          { email: identity.email, groups: identity.groups },
          'OIDC login has no group mapped to a team',
        );
        span.setAttribute('oidc.outcome', 'no_team');
        return redirectWithError(res, 'no_team');
      }

      const { user, outcome, teamCreated, teamChanged } =
        await provisionOidcUser(identity, target);

      setBusinessContext({
        teamId: user.team?.toString(),
        userId: user._id.toString(),
        email: user.email,
        ...getStaticFeatureFlags(),
      });
      span.setAttributes({
        'oidc.outcome': 'success',
        'oidc.user.provision': outcome,
        'oidc.team.group': target.group,
        'oidc.team.created': teamCreated,
        'oidc.team.changed': teamChanged,
      });
      logger.info(
        {
          type: 'user_login',
          authType: 'oidc',
          userId: user._id,
          teamId: user.team,
          provision: outcome,
          teamCreated,
          teamChanged,
        },
        'OIDC login succeeded',
      );

      await new Promise<void>((resolve, reject) => {
        req.login(user, err => (err ? reject(err) : resolve()));
      });
      // After req.login, which regenerates the session.
      req.session.oidcAuthenticatedAt = Date.now();
      oidcLogins.add(1, { outcome: 'success' });
      redirectToDashboard(req, res);
    });
  } catch (err) {
    if (err instanceof OidcLoginRejectedError) {
      logger.warn({ reason: err.reason }, 'OIDC login rejected');
      return redirectWithError(res, err.reason);
    }
    if (err instanceof OidcClaimsError) {
      logger.warn({ err }, 'OIDC claims rejected');
      return redirectWithError(
        res,
        err.reason === 'missing_email' ? 'missing_email' : 'failed',
      );
    }
    logger.error({ err }, 'OIDC login failed');
    if (res.headersSent) {
      return next(err);
    }
    redirectWithError(res, 'failed');
  }
});

export default router;
