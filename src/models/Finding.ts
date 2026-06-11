import { Schema, model, type Document, type Model, type Types } from "mongoose";
import type { Severity } from "../types";

export interface IFinding extends Document {
  scanId: Types.ObjectId;
  installationId: number;
  owner: string;
  repo: string;
  rule: string;
  severity: Severity;
  message: string;
  file: string | null;
  detectedAt: Date;
  resolvedAt: Date | null;
}

const FindingSchema = new Schema<IFinding>(
  {
    scanId: { type: Schema.Types.ObjectId, ref: "Scan", required: true, index: true },
    installationId: { type: Number, required: true, index: true },
    owner: { type: String, required: true },
    repo: { type: String, required: true },
    rule: { type: String, required: true },
    severity: {
      type: String,
      enum: ["critical", "high", "medium", "low"],
      required: true,
    },
    message: { type: String, required: true },
    file: { type: String, default: null },
    detectedAt: { type: Date, required: true, default: Date.now },
    resolvedAt: { type: Date, default: null },
  },
  { timestamps: true }
);

// Common queries: all findings for a repo, all unresolved critical findings
FindingSchema.index({ installationId: 1, repo: 1 });
FindingSchema.index({ severity: 1, resolvedAt: 1 });

export const Finding: Model<IFinding> = model<IFinding>("Finding", FindingSchema);