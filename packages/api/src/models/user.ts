import {
  ONBOARDING_TASK_IDS,
  type OnboardingData,
} from '@hyperdx/common-utils/dist/types';
// @ts-expect-error don't install the @types for this package, as it conflicts with mongoose
import passportLocalMongoose from '@hyperdx/passport-local-mongoose';
import mongoose, { Schema } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';

type ObjectId = mongoose.Types.ObjectId;

export interface IUser {
  _id: ObjectId;
  accessKey: string;
  createdAt: Date;
  email: string;
  name: string;
  // Set for users who signed in through OIDC: the provider's issuer and the
  // stable subject identifier it assigned the user.
  oidcIssuer?: string;
  oidcSubject?: string;
  // Last time the IdP vouched for this user, at login or by refresh. Sessions
  // and the access key stop working once it is older than
  // OIDC_IDENTITY_MAX_AGE_HOURS, and it is cleared when the IdP refuses them.
  oidcVerifiedAt?: Date | null;
  // Encrypted envelope (utils/tokenEncryption.ts), used to re-check the user
  // with the IdP in the background.
  oidcRefreshToken?: string;
  // Lease held by the API replica currently revalidating this user.
  oidcRevalidationLockedUntil?: Date;
  // Optional for docs predating this field; the `me` route defaults it.
  onboardingData?: OnboardingData;
  team: ObjectId;
}

export type UserDocument = mongoose.HydratedDocument<IUser>;

const UserSchema = new Schema(
  {
    name: String,
    email: {
      type: String,
      required: true,
    },
    team: { type: mongoose.Schema.Types.ObjectId, ref: 'Team' },
    oidcIssuer: String,
    oidcSubject: String,
    oidcVerifiedAt: Date,
    oidcRefreshToken: { type: String, select: false },
    oidcRevalidationLockedUntil: Date,
    accessKey: {
      type: String,
      default: function genUUID() {
        return uuidv4();
      },
    },
    onboardingData: {
      type: new Schema<OnboardingData>(
        {
          completedTasks: {
            type: [String],
            enum: ONBOARDING_TASK_IDS,
            default: [],
          },
          isDismissed: { type: Boolean, default: false },
        },
        { _id: false },
      ),
      default: () => ({ completedTasks: [], isDismissed: false }),
    },
  },
  {
    timestamps: true,
  },
);

UserSchema.virtual('hasPasswordAuth').get(function (this: IUser) {
  return true;
});

UserSchema.plugin(passportLocalMongoose, {
  usernameField: 'email',
  usernameLowerCase: true,
  usernameCaseInsensitive: true,
});

UserSchema.index({ email: 1 }, { unique: true });
UserSchema.index({ accessKey: 1 }, { unique: true });
// Serves the revalidation sweep's "who is due" query.
UserSchema.index(
  { oidcVerifiedAt: 1 },
  { partialFilterExpression: { oidcSubject: { $type: 'string' } } },
);
UserSchema.index(
  { oidcIssuer: 1, oidcSubject: 1 },
  {
    unique: true,
    partialFilterExpression: { oidcSubject: { $type: 'string' } },
  },
);

export default mongoose.model<IUser>('User', UserSchema);
