import { Schema, model, type Document, type Model } from "mongoose";

export type ScanStatus = "pending" | "in_progress" | "complete" | "failed";

export interface IScan extends Document {
  installationId: number;
  owner: string;
  repo: string;
  branch: string;
  commitSha: string;
  status: ScanStatus;
  startedAt: Date;
  completedAt: Date | null;
  durationMs: number | null;
  findingsCount: number;
  filesScanned: number;
  trigger: "installation" | "push" | "manual";
}

const ScanSchema = new Schema<IScan>(
  {
    installationId: { type: Number, required: true, index: true },
    owner: { type: String, required: true },
    repo: { type: String, required: true },
    branch: { type: String, default: "main" },
    commitSha: { type: String, default: "" },
    status: {
      type: String,
      enum: ["pending", "in_progress", "complete", "failed"],
      required: true,
      default: "pending",
    },
    startedAt: { type: Date, required: true, default: Date.now },
    completedAt: { type: Date, default: null },
    durationMs: { type: Number, default: 0 },
    findingsCount: { type: Number, required: true, default: 0 },
    filesScanned: { type: Number, default: 0 },
    trigger: {
      type: String,
      enum: ["installation", "push", "manual"],
      required: true,
    },
  },
  { timestamps: true },
);

// Compound index — common query: all scans for a repo
ScanSchema.index({ installationId: 1, repo: 1 });

export const Scan: Model<IScan> = model<IScan>("Scan", ScanSchema);
