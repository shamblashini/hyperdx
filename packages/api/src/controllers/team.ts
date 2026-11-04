import {
  TagResourceType,
  TeamClickHouseSettingsUpdate,
} from '@hyperdx/common-utils/dist/types';
import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';

import * as config from '@/config';
import type { ObjectId } from '@/models';
import Alert from '@/models/alert';
import Dashboard from '@/models/dashboard';
import { SavedSearch } from '@/models/savedSearch';
import Team, { type ITeam, type TeamDocument } from '@/models/team';

export function getTeamInviteUrl(token: string) {
  return `${config.FRONTEND_URL}/join-team?token=${token}`;
}

const LOCAL_APP_TEAM_ID = '_local_team_';
export const LOCAL_APP_TEAM = {
  _id: new mongoose.Types.ObjectId(LOCAL_APP_TEAM_ID),
  id: LOCAL_APP_TEAM_ID,
  name: 'Local App Team',
  // Placeholder keys
  hookId: uuidv4(),
  apiKey: uuidv4(),
  collectorAuthenticationEnforced: false,
  isMetricsSeriesTableEnabled: false,
  toJSON() {
    return this;
  },
};

export async function isTeamExisting() {
  if (config.IS_LOCAL_APP_MODE) {
    return true;
  }

  const teamCount = await Team.countDocuments({});
  return teamCount > 0;
}

export async function createTeam({
  name,
  collectorAuthenticationEnforced = true,
}: {
  name: string;
  collectorAuthenticationEnforced?: boolean;
}) {
  if (await isTeamExisting()) {
    throw new Error('Team already exists');
  }

  const team = new Team({ name, collectorAuthenticationEnforced });

  await team.save();

  return team;
}

/**
 * Returns the team bound to an OIDC group, creating it on first use. Unlike
 * `createTeam`, this may add a team when others already exist: SSO is how a
 * self-hosted instance gets more than one team.
 *
 * An existing unbound team whose name matches exactly is bound instead of
 * creating a duplicate, so the team made at password setup can be handed over
 * to a group by naming it in OIDC_TEAM_MAPPING.
 */
export async function findOrCreateTeamForOidcGroup({
  group,
  teamName,
}: {
  group: string;
  teamName: string;
}): Promise<{ team: TeamDocument; created: boolean }> {
  const bound = await Team.findOne({ oidcGroup: group });
  if (bound) {
    return { team: bound, created: false };
  }

  const unboundByName = await Team.find({
    name: teamName,
    oidcGroup: { $exists: false },
  }).limit(2);
  if (unboundByName.length === 1) {
    const claimed = await Team.findOneAndUpdate(
      { _id: unboundByName[0]._id, oidcGroup: { $exists: false } },
      { $set: { oidcGroup: group } },
      { new: true },
    );
    if (claimed) {
      return { team: claimed, created: false };
    }
  }

  // Upsert so two first logins racing for the same group end with one team;
  // the partial unique index on oidcGroup backs this up.
  const result = await Team.findOneAndUpdate(
    { oidcGroup: group },
    {
      $setOnInsert: {
        name: teamName,
        collectorAuthenticationEnforced: true,
      },
    },
    { upsert: true, new: true, rawResult: true, setDefaultsOnInsert: true },
  );
  if (result.value == null) {
    throw new Error(`Failed to provision team for OIDC group ${group}`);
  }
  return {
    team: result.value,
    created: result.lastErrorObject?.updatedExisting === false,
  };
}

export function getAllTeams(fields?: string[]) {
  if (config.IS_LOCAL_APP_MODE) {
    return [LOCAL_APP_TEAM];
  }

  return Team.find({}, fields);
}

export function getTeam<const F extends readonly (keyof ITeam)[]>(
  id: string | ObjectId,
  fields: F,
): mongoose.Query<
  mongoose.HydratedDocument<Pick<ITeam, F[number]>> | null,
  any
>;
export function getTeam(
  id: string | ObjectId,
): mongoose.Query<TeamDocument | null, any>;
export function getTeam(id: string | ObjectId, fields?: readonly string[]) {
  if (config.IS_LOCAL_APP_MODE) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion
    return LOCAL_APP_TEAM as any;
  }

  return Team.findById(id, fields);
}

export function getTeamByApiKey(apiKey: string) {
  if (config.IS_LOCAL_APP_MODE) {
    return LOCAL_APP_TEAM;
  }

  return Team.findOne({ apiKey });
}

export function rotateTeamApiKey(teamId: ObjectId) {
  return Team.findByIdAndUpdate(teamId, { apiKey: uuidv4() }, { new: true });
}

export function setTeamName(teamId: ObjectId, name: string) {
  return Team.findByIdAndUpdate(teamId, { name }, { new: true });
}

export function updateTeamClickhouseSettings(
  teamId: ObjectId,
  settings: TeamClickHouseSettingsUpdate,
) {
  const $set: Record<string, any> = {};
  const $unset: Record<string, any> = {};

  for (const [key, value] of Object.entries(settings)) {
    if (value === null) {
      $unset[key] = '';
    } else if (value !== undefined) {
      $set[key] = value;
    }
  }

  const update: Record<string, any> = {};
  if (Object.keys($set).length > 0) update.$set = $set;
  if (Object.keys($unset).length > 0) update.$unset = $unset;

  return Team.findByIdAndUpdate(teamId, update, { new: true });
}

function getCollectionsWithTags(
  resourceType?: TagResourceType,
): Pick<mongoose.Model<unknown>, 'aggregate'>[] {
  if (resourceType == null) {
    return [Alert, Dashboard, SavedSearch];
  }

  switch (resourceType) {
    case 'alert':
      return [Alert];
    case 'dashboard':
      return [Dashboard];
    case 'savedSearch':
      return [SavedSearch];
    default:
      resourceType satisfies never;
      throw new Error(`${resourceType} is not a valid TagResourceType`);
  }
}

/**
 * Distinct tags applied to the team's entities. Scoped to one kind of entity
 * when `resourceType` is given.
 */
export async function getTags(
  teamId: ObjectId,
  resourceType?: TagResourceType,
) {
  const distinctTagsPipeline: mongoose.PipelineStage[] = [
    { $match: { team: teamId } },
    { $unwind: '$tags' },
    { $group: { _id: '$tags' } },
  ];

  const tagGroups = await Promise.all(
    getCollectionsWithTags(resourceType).map(collection =>
      collection.aggregate<{ _id: string }>(distinctTagsPipeline),
    ),
  );

  return [...new Set(tagGroups.flat().map(t => t._id))];
}
