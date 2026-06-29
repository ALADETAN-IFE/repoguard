import type { App } from "@octokit/app";
import { scanCommit } from "../scanner";
import { createCheckRun, updateCheckRun } from "../checks";
import { sendAlert } from "../alerts";
import {
  closeRepoGuardPRsAndIssues,
  hasOpenRepoGuardFixPR,
  openFixPR,
  postReviewComments,
} from "../pullRequest";
import { normaliseOctokit } from "../utils/normaliseOctokit";
import { scanFullRepoForPush } from "./installation";
import logger from "../utils/logger";
import type { WebhookEvent, PushEventPayload, Finding } from "../types/index";

export function handlePush(
  _app: App,
): (event: WebhookEvent<PushEventPayload>) => Promise<void> {
  return async ({ octokit, payload }) => {
    const { repository, commits, pusher, ref, after: headSha } = payload;
    const owner = repository.owner.login ?? repository.owner.name ?? "unknown";
    const repo = repository.name;
    const totalCommits = commits.length;

    // Ignore branch deletion events
    if (headSha === "0000000000000000000000000000000000000000") {
      logger.info(`[push] ${owner}/${repo} — branch deletion ignored`);
      return;
    }

    const isForcePush = payload.forced === true;
    const isDefaultBranch =
      ref === `refs/heads/${repository.default_branch || "main"}`;
    const client = normaliseOctokit(octokit);

    logger.info(
      `[push] ${owner}/${repo} — ${totalCommits} commit${totalCommits > 1 ? "s" : ""} by ${pusher.name}${isForcePush ? " (force push)" : ""}`,
    );

    const checkRunId = await createCheckRun({
      octokit: client,
      owner,
      repo,
      headSha,
      name: "RepoGuard Security Scan",
      status: "in_progress",
    });

    if (!checkRunId) return;

    try {
      let findings: Finding[] = [];

      if (isForcePush && isDefaultBranch) {
        // ✅ Force push on default branch — scan entire repo, not just diff
        logger.warn(
          `[push] Force push detected on ${owner}/${repo} — running full repo scan`,
        );
        findings = await scanFullRepoForPush(client, owner, repo);
      } else {
        // Normal push — scan only changed files
        findings = (
          await Promise.all(
            commits.map((commit) =>
              scanCommit({
                octokit: client,
                owner,
                repo,
                sha: commit.id,
                addedFiles: commit.added ?? [],
                modifiedFiles: commit.modified ?? [],
              }),
            ),
          )
        ).flat();
      }

      const passed = findings.length === 0;

      await updateCheckRun({
        octokit: client,
        owner,
        repo,
        checkRunId,
        conclusion: passed ? "success" : "failure",
        findings,
      });

      if (!passed) {
        // Check if there's an open PR for this branch and post inline comments
        try {
          const branch = ref.replace("refs/heads/", "");
          logger.info(`[push] Looking for open PR on branch: ${branch}`);
          const { data: pulls } = await client.request(
            "GET /repos/{owner}/{repo}/pulls",
            { owner, repo, state: "open", head: `${owner}:${branch}` },
          );
          logger.info(`[push] Found ${(pulls as unknown[]).length} open PR(s)`);

          if ((pulls as unknown[]).length > 0) {
            const pr = (pulls as Array<{ number: number }>)[0];
            const patchedMap = new Map<string, string>();
            await postReviewComments(
              client,
              owner,
              repo,
              pr.number,
              headSha,
              findings,
              patchedMap,
            );
          }
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          logger.warn(`[push] Could not find/comment on open PR: ${message}`);
        }

        await sendAlert({
          owner,
          repo,
          ref,
          pusher: pusher.name,
          headSha,
          findings,
          context: "push",
        });

        if (isDefaultBranch) {
          const hasFixPR = await hasOpenRepoGuardFixPR(client, owner, repo);
          if (hasFixPR) {
            logger.info(
              `[push] Open RepoGuard fix PR already exists for ${owner}/${repo} — skipping`,
            );
          } else {
            logger.warn(
              `[push] ${findings.length} finding${findings.length > 1 ? "s" : ""} on default branch — opening fix PR`,
            );
            await openFixPR(client, { owner, repo, findings });
          }
        }

        logger.warn(
          `[push] BLOCKED — ${findings.length} finding${findings.length > 1 ? "s" : ""} in ${owner}/${repo}`,
        );
      } else {
        logger.info(`[push] CLEAN — ${owner}/${repo}@${headSha.slice(0, 7)}`);
        if (isDefaultBranch) {
          await closeRepoGuardPRsAndIssues(client, owner, repo);
        }
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`[push] Error scanning ${owner}/${repo}: ${message}`);
      await updateCheckRun({
        octokit: client,
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
