import { type Team } from '@hyperdx/common-utils/dist/types';
import mongoose, { Schema } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';

type ObjectId = mongoose.Types.ObjectId;

export interface ITeam extends Team {
  _id: ObjectId;
  createdAt: Date;
  updatedAt: Date;
  // The OIDC group this team is provisioned from. Unset for teams created by
  // password registration until an OIDC login binds them by name.
  oidcGroup?: string;
}

export type TeamDocument = mongoose.HydratedDocument<ITeam>;

const TeamSchema = new Schema<ITeam>(
  {
    name: String,
    allowedAuthMethods: [String],
    oidcGroup: String,
    hookId: {
      type: String,
      default: function genUUID() {
        return uuidv4();
      },
    },
    apiKey: {
      type: String,
      default: function genUUID() {
        return uuidv4();
      },
    },
    collectorAuthenticationEnforced: {
      type: Boolean,
      default: false,
    },
    isMetricsSeriesTableEnabled: {
      type: Boolean,
      default: false,
    },
    // TODO: maybe add these to a top level Mixed type
    // CH Client Settings
    metadataMaxRowsToRead: Number,
    searchRowLimit: Number,
    queryTimeout: Number,
    fieldMetadataDisabled: Boolean,
    parallelizeWhenPossible: Boolean,
    filterKeysFetchLimit: Number,
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  },
);

TeamSchema.index(
  { oidcGroup: 1 },
  { unique: true, partialFilterExpression: { oidcGroup: { $type: 'string' } } },
);

export default mongoose.model<ITeam>('Team', TeamSchema);
