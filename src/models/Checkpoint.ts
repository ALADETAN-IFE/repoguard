import { Schema, model, type Document, type Model } from "mongoose";

export interface ICheckpoint extends Document {
  installationKey: string;
  installationId: number;
  owner: string;
  totalRepos: string[];
  scanned: string[];
  startedAt: Date;
  updatedAt: Date;
}

const CheckpointSchema = new Schema<ICheckpoint>(
  {
    installationKey: { type: String, required: true, unique: true, index: true },
    installationId: { type: Number, required: true },
    owner: { type: String, required: true },
    totalRepos: { type: [String], required: true, default: [] },
    scanned: { type: [String], required: true, default: [] },
    startedAt: { type: Date, required: true, default: Date.now },
  },
  {
    timestamps: true, // adds createdAt and updatedAt automatically
  }
);

export const Checkpoint: Model<ICheckpoint> = model<ICheckpoint>(
  "Checkpoint",
  CheckpointSchema
);