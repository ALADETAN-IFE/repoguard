import type { App } from "@octokit/app";
import { scanCommit } from "../scanner";
import { createCheckRun, updateCheckRun } from "../checks";
import { sendAlert } from "../alerts";
import { closeRepoGuardPRsAndIssues } from "../pullRequest";
import { normaliseOctokit } from "../utils/normaliseOctokit"; // ← add
import logger from "../utils/logger";
import type { WebhookEvent, PushEventPayload } from "../types/index";

export function handlePush(_app: App): (event: WebhookEvent<PushEventPayload>) => Promise<void> {
  return async ({ octokit, payload }) => {
    const { repository, commits, pusher, ref, after: headSha } = payload;
    const owner = repository.owner.login ?? repository.owner.name ?? "unknown";
    const repo = repository.name;
    const totalCommits = commits.length;

    if (headSha === "0000000000000000000000000000000000000000") {
      logger.info(`[push] ${owner}/${repo} — branch deletion ignored`);
      return;
    }

    const client = normaliseOctokit(octokit);

    // ── Debug: log the client structure ──
    logger.info(`[push] client keys: ${Object.keys(client).join(", ")}`);
    logger.info(`[push] client.rest exists: ${!!(client).rest}`);
    logger.info(`[push] client.rest?.checks exists: ${!!(client).rest?.checks}`);

    logger.info(
      `[push] ${owner}/${repo} — ${totalCommits} commit${totalCommits > 1 ? "s" : ""} by ${pusher.name}`,
    );

    const checkRunId = await createCheckRun({
      octokit: client, // ← use client
      owner,
      repo,
      headSha,
      name: "RepoGuard Security Scan",
      status: "in_progress",
    });

    if (!checkRunId) return;

    try {
      const findings = (
        await Promise.all(
          commits.map((commit) =>
            scanCommit({
              octokit: client, // ← use client
              owner,
              repo,
              sha: commit.id,
              addedFiles: commit.added ?? [],
              modifiedFiles: commit.modified ?? [],
            }),
          ),
        )
      ).flat();

      const passed = findings.length === 0;

      await updateCheckRun({
        octokit: client, // ← use client
        owner,
        repo,
        checkRunId,
        conclusion: passed ? "success" : "failure",
        findings,
      });

      if (!passed) {
        await sendAlert({
          owner,
          repo,
          ref,
          pusher: pusher.name,
          headSha,
          findings,
          context: "push",
        });
        logger.warn(
          `[push] BLOCKED — ${findings.length} finding${findings.length > 1 ? "s" : ""} in ${owner}/${repo}`,
        );
      } else {
        logger.info(`[push] CLEAN — ${owner}/${repo}@${headSha.slice(0, 7)}`);
        const defaultBranch = repository.default_branch || "main";
        if (ref === `refs/heads/${defaultBranch}`) {
          await closeRepoGuardPRsAndIssues(client, owner, repo); // ← use client
        }
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`[push] Error scanning ${owner}/${repo}: ${message}`);
      await updateCheckRun({
        octokit: client, // ← use client
        owner,
        repo,
        checkRunId,
        conclusion: "neutral",
        findings: [],
        summary: `Scan error: ${message}`,
      });
    }
  };
}