import { Schema, model, type Document, type Model } from "mongoose";

export interface IInstallation extends Document {
  installationId: number;
  owner: string;
  email: string | null;
  installedAt: Date;
  uninstalledAt: Date | null;
  // Marketplace fields
  marketplacePlan: string | null;
  billingCycle: "monthly" | "yearly" | null;
  onFreeTrial: boolean;
  freeTrialEndsOn: Date | null;
  marketplaceUpdatedAt: Date | null;
  marketplaceCancelledAt: Date | null;
}

const InstallationSchema = new Schema<IInstallation>(
  {
    installationId: {
      type: Number,
      required: true,
      unique: true,
      index: true,
    },
    owner: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: false,
      default: null,
    },
    installedAt: {
      type: Date,
      required: true,
      default: Date.now,
    },
    uninstalledAt: {
      type: Date,
      default: null,
    },
    marketplacePlan: {
      type: String,
      default: null,
    },
    billingCycle: {
      type: String,
      enum: ["monthly", "yearly", null],
      default: null,
    },
    onFreeTrial: {
      type: Boolean,
      default: false,
    },
    freeTrialEndsOn: {
      type: Date,
      default: null,
    },
    marketplaceUpdatedAt: {
      type: Date,
      default: null,
    },
    marketplaceCancelledAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true },
);

export const Installation: Model<IInstallation> = model<IInstallation>(
  "Installation",
  InstallationSchema,
);
