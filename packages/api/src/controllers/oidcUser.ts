import { findOrCreateTeamForOidcGroup } from '@/controllers/team';
import { findUserByEmail } from '@/controllers/user';
import User, { type UserDocument } from '@/models/user';
import { setupTeamDefaults } from '@/setupDefaults';
import { isDuplicateKeyError } from '@/utils/errors';
import logger from '@/utils/logger';
import type { OidcIdentity, TeamTarget } from '@/utils/oidc/claims';

export type OidcLoginRejection =
  // A password account has this email but the IdP has not verified it, so
  // linking would let anyone who can set that email in the IdP take it over.
  | 'email_unverified'
  // The email already belongs to an account linked to a different identity.
  | 'email_conflict';

export class OidcLoginRejectedError extends Error {
  constructor(readonly reason: OidcLoginRejection) {
    super(`OIDC login rejected: ${reason}`);
    this.name = 'OidcLoginRejectedError';
  }
}

export type OidcProvisionOutcome = 'created' | 'linked' | 'existing';

async function findOrLinkUser(
  identity: OidcIdentity,
  teamId: UserDocument['team'],
): Promise<{ user: UserDocument; outcome: OidcProvisionOutcome }> {
  const bySubject = await User.findOne({
    oidcIssuer: identity.issuer,
    oidcSubject: identity.subject,
  });
  if (bySubject) {
    return { user: bySubject, outcome: 'existing' };
  }

  const byEmail = await findUserByEmail(identity.email);
  if (byEmail) {
    if (byEmail.oidcSubject) {
      throw new OidcLoginRejectedError('email_conflict');
    }
    if (!identity.emailVerified) {
      throw new OidcLoginRejectedError('email_unverified');
    }
    byEmail.oidcIssuer = identity.issuer;
    byEmail.oidcSubject = identity.subject;
    return { user: byEmail, outcome: 'linked' };
  }

  const created = new User({
    email: identity.email,
    name: identity.name,
    team: teamId,
    oidcIssuer: identity.issuer,
    oidcSubject: identity.subject,
  });
  try {
    await created.save();
  } catch (err) {
    // A concurrent first login for the same person won the insert.
    if (isDuplicateKeyError(err)) {
      const winner = await User.findOne({
        oidcIssuer: identity.issuer,
        oidcSubject: identity.subject,
      });
      if (winner) {
        return { user: winner, outcome: 'existing' };
      }
      throw new OidcLoginRejectedError('email_conflict');
    }
    throw err;
  }
  return { user: created, outcome: 'created' };
}

/**
 * Finds or creates the HyperDX user for an OIDC identity and puts them in the
 * team their groups map to. The IdP is the source of truth: team, name and
 * email are re-synced on every login, so moving someone between groups in the
 * IdP moves them between teams here at their next login.
 */
export async function provisionOidcUser(
  identity: OidcIdentity,
  target: TeamTarget,
): Promise<{
  user: UserDocument;
  outcome: OidcProvisionOutcome;
  teamCreated: boolean;
  teamChanged: boolean;
}> {
  const { team, created: teamCreated } =
    await findOrCreateTeamForOidcGroup(target);
  if (teamCreated) {
    try {
      await setupTeamDefaults(team._id.toString());
    } catch (err) {
      // Same as password registration: the team is usable without defaults.
      logger.error({ err, teamId: team._id }, 'Failed to setup team defaults');
    }
  }

  const { user, outcome } = await findOrLinkUser(identity, team._id);

  const teamChanged = user.team?.toString() !== team._id.toString();
  user.team = team._id;
  user.name = identity.name;

  if (user.email !== identity.email) {
    const taken = await findUserByEmail(identity.email);
    if (taken == null) {
      user.email = identity.email;
    } else {
      // Keep the old address rather than fail the login over a rename that
      // collides with another account; an admin can resolve it.
      logger.warn(
        { userId: user._id, teamId: team._id },
        'OIDC email changed to an address another user already has',
      );
    }
  }

  if (user.isModified()) {
    await user.save();
  }

  return {
    user,
    outcome,
    teamCreated,
    teamChanged: teamChanged && outcome !== 'created',
  };
}
