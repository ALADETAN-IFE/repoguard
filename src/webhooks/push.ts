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
import { getPushChangedFiles } from "../utils/pushChangedFiles";
import { scanFullRepoForPush } from "./installation";
import logger from "../utils/logger";
import type {
  WebhookEvent,
  PushEventPayload,
  Finding,
  OctokitClient,
} from "../types/index";

// ─── Check if this branch's open PR had previous RepoGuard findings ───────────

async function hasOpenPRWithPreviousFindings(
  client: OctokitClient,
  owner: string,
  repo: string,
  branch: string,
): Promise<{ hasPrevious: boolean; prNumber: number | null }> {
  try {
    const { data: pulls } = await client.request(
      "GET /repos/{owner}/{repo}/pulls",
      { owner, repo, state: "open", head: `${owner}:${branch}` },
    );

    if ((pulls as unknown[]).length === 0) {
      return { hasPrevious: false, prNumber: null };
    }

    const pr = (pulls as Array<{ number: number }>)[0];

    // Check if any previous review from the bot flagged issues
    const { data: reviews } = await client.request(
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews",
      { owner, repo, pull_number: pr.number },
    );

    const hadFindings = (
      reviews as Array<{ user?: { login?: string }; body?: string }>
    ).some(
      (review) =>
        review.user?.login?.includes("[bot]") &&
        review.body?.includes("RepoGuard detected"),
    );

    return { hasPrevious: hadFindings, prNumber: pr.number };
  } catch {
    return { hasPrevious: false, prNumber: null };
  }
}

export function handlePush(
  _app: App,
): (event: WebhookEvent<PushEventPayload>) => Promise<void> {
  return async ({ octokit, payload }) => {
    const {
      repository,
      commits,
      pusher,
      ref,
      before,
      after: headSha,
    } = payload;
    const owner = repository.owner.login ?? repository.owner.name ?? "unknown";
    const repo = repository.name;
    const totalCommits = commits.length;

    // Ignore branch deletion events
    if (headSha === "0000000000000000000000000000000000000000") {
      logger.info(`[push] ${owner}/${repo} — branch deletion ignored`);
      return;
    }

    // Ignore no-op push events (0 commits and SHA unchanged)
    if (before === headSha && totalCommits === 0) {
      logger.info(
        `[push] ${owner}/${repo} — no-op push event ignored (before === after)`,
      );
      return;
    }

    const isForcePush = payload.forced === true;
    const isDefaultBranch =
      ref === `refs/heads/${repository.default_branch || "main"}`;
    const branch = ref.replace("refs/heads/", "");
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
        // Force push on default branch — scan entire repo, not just diff
        logger.warn(
          `[push] Force push detected on ${owner}/${repo} — running full repo scan`,
        );
        findings = await scanFullRepoForPush(client, owner, repo);
      } else {
        const { added, modified, removed } = await getPushChangedFiles(
          client,
          owner,
          repo,
          before,
          headSha,
          commits,
        );

        findings = await scanCommit({
          octokit: client,
          owner,
          repo,
          sha: headSha,
          addedFiles: added,
          modifiedFiles: modified,
          removedFiles: removed,
        });
      }

      const passed = findings.length === 0;

      if (!passed) {
        // ── Current push has findings ────────────────────────────────────────
        await updateCheckRun({
          octokit: client,
          owner,
          repo,
          checkRunId,
          conclusion: "failure",
          findings,
        });

        // Post inline review comments on open PR if one exists
        try {
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
          logger.warn(`[push] Could not post PR review comments: ${message}`);
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
        // ── Current push is clean ────────────────────────────────────────────
        logger.info(`[push] CLEAN — ${owner}/${repo}@${headSha.slice(0, 7)}`);

        // Check if there's an open PR on this branch with previous findings
        const { hasPrevious, prNumber } = await hasOpenPRWithPreviousFindings(
          client,
          owner,
          repo,
          branch,
        );

        if (hasPrevious && prNumber) {
          // ── Previous push on this PR was malicious — fail the check and warn
          logger.warn(
            `[push] PR #${prNumber} has previous flagged commits — failing check despite clean push`,
          );

          await updateCheckRun({
            octokit: client,
            owner,
            repo,
            checkRunId,
            conclusion: "failure",
            findings: [],
            summary: [
              "⚠️ This push is clean, but earlier commits in this PR were flagged for security issues.",
              "",
              "RepoGuard cannot confirm the malicious code has been fully removed from the PR history.",
              "",
              "**To resolve this:**",
              "- Squash all commits into a single clean commit and force-push",
              "- Or ensure all RepoGuard review comments have been resolved",
              "",
              `See PR #${prNumber} for previous findings.`,
            ].join("\n"),
          });

          // Post a comment on the PR explaining why the check failed
          try {
            await client.request(
              "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
              {
                owner,
                repo,
                issue_number: prNumber,
                body: [
                  "## ⚠️ RepoGuard: Latest push is clean — but this PR has flagged history",
                  "",
                  "The most recent push passed the security scan, but **earlier commits in this PR were flagged** for security issues. The check run has been marked as **failed** until the history is resolved.",
                  "",
                  "**To pass the check:**",
                  "1. Squash all commits into one clean commit and force-push, **or**",
                  "2. Resolve all RepoGuard review comments and request a re-review",
                  "",
                  "This ensures no malicious code remains anywhere in the PR's commit history before merging.",
                  "",
                  "---",
                  "_RepoGuard · The check will pass once the history is clean._",
                ].join("\n"),
              },
            );
          } catch (commentErr) {
            const msg =
              commentErr instanceof Error
                ? commentErr.message
                : String(commentErr);
            logger.warn(
              `[push] Could not post history warning on PR #${prNumber}: ${msg}`,
            );
          }
        } else {
          // ── Fully clean — no previous findings either ──────────────────────
          await updateCheckRun({
            octokit: client,
            owner,
            repo,
            checkRunId,
            conclusion: "success",
            findings: [],
          });

          if (isDefaultBranch) {
            await closeRepoGuardPRsAndIssues(client, owner, repo);
          }
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
