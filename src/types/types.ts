import type { Octokit } from "@octokit/rest";

// ─── Severity ────────────────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low";

// ─── Scanner ─────────────────────────────────────────────────────────────────

export interface ScanRule {
  id: string;
  severity: Severity;
  description: string;
  test: (content: string, filePath?: string) => boolean;
}

export interface Finding {
  rule: string;
  severity: Severity;
  message: string;
  file: string | null;
}

export interface ScanCommitOptions {
  octokit: Octokit;
  owner: string;
  repo: string;
  sha: string;
  addedFiles: string[];
  modifiedFiles: string[];
}

// ─── Checks ──────────────────────────────────────────────────────────────────

export interface CreateCheckRunOptions {
  octokit: Octokit;
  owner: string;
  repo: string;
  headSha: string;
  name: string;
  status: "queued" | "in_progress" | "completed";
}

export interface UpdateCheckRunOptions {
  octokit: Octokit;
  owner: string;
  repo: string;
  checkRunId: number;
  conclusion: "success" | "failure" | "neutral" | "cancelled" | "skipped" | "timed_out";
  findings: Finding[];
  summary?: string;
}

// ─── Alerts ──────────────────────────────────────────────────────────────────

export type AlertContext = "push" | "workflow_file" | "branch_create";

export interface AlertOptions {
  owner: string;
  repo: string;
  ref: string;
  pusher: string;
  headSha: string | null;
  findings: Finding[];
  context?: AlertContext;
}

export interface AlertPayload {
  timestamp: string;
  repository: string;
  ref: string;
  pusher: string;
  commit: string;
  context: AlertContext;
  summary: string;
  findings: Finding[];
}
