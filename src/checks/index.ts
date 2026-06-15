import type { CreateCheckRunOptions, UpdateCheckRunOptions, Finding } from "../types";
import logger from "../utils/logger";

export async function createCheckRun({
  octokit,
  owner,
  repo,
  headSha,
  name,
  status,
}: CreateCheckRunOptions): Promise<number | null> {
  try {
    const { data } = await octokit.request("POST /repos/{owner}/{repo}/check-runs", {
      owner,
      repo,
      name,
      head_sha: headSha,
      status,
      started_at: new Date().toISOString(),
    });
    return data.id;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to create check run: ${message}`);
    return null;
  }
}

export async function updateCheckRun({
  octokit,
  owner,
  repo,
  checkRunId,
  conclusion,
  findings,
  summary,
}: UpdateCheckRunOptions): Promise<void> {
  const passed = conclusion === "success";
  const totalFindings = findings.length;

  const defaultSummary = passed
    ? "✅ No security issues detected."
    : `🚨 ${totalFindings} security issue${totalFindings > 1 ? "s" : ""} found. Push blocked.`;

  const text = findings
    .map(
      (f: Finding) =>
        `### ${severityEmoji(f.severity)} \`${f.rule}\` — ${f.severity.toUpperCase()}\n` +
        `**File:** \`${f.file ?? "N/A"}\`\n` +
        `${f.message}\n`,
    )
    .join("\n---\n");

  try {
    await octokit.request("PATCH /repos/{owner}/{repo}/check-runs/{check_run_id}", {
      owner,
      repo,
      check_run_id: checkRunId,
      status: "completed",
      conclusion,
      completed_at: new Date().toISOString(),
      output: {
        title: passed ? "RepoGuard: Clean" : "RepoGuard: Issues Found",
        summary: summary ?? defaultSummary,
        text: text || undefined,
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to update check run ${checkRunId}: ${message}`);
  }
}

function severityEmoji(severity: string): string {
  const map: Record<string, string> = {
    critical: "🔴",
    high: "🟠",
    medium: "🟡",
    low: "🟢",
  };
  return map[severity] ?? "⚪";
}