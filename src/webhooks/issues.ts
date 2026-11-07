import type { App } from "@octokit/app";
import { normaliseOctokit } from "../utils/normaliseOctokit";
import { scanFullRepoForPush } from "./installation";
import { openFixPR } from "../pullRequest";
import logger from "../utils/logger";
import { redis } from "../config/redis";
import type { WebhookEvent } from "../types/index";

export interface IssuesOpenedPayload {
  action: string;
  issue: {
    number: number;
    title: string;
    body?: string;
    user?: { login: string };
    html_url?: string;
    author_association?: string;
  };
  repository: {
    owner: { login: string };
    name: string;
  };
}

/**
 * Factory — returns a webhook handler for issues.opened events.
 * If a user creates an issue with title "Repoguard" and body "/repoguard scan",
 * RepoGuard automatically scans the repo and replies with a status comment,
 * followed by a comment containing a markdown link to the created PR or issue if findings exist.
 */
export function handleIssuesOpened(
  _app: App,
): (event: WebhookEvent<IssuesOpenedPayload>) => Promise<void> {
  return async ({ octokit: rawOctokit, payload }) => {
    logger.info("[issue-scan] Issue webhook received");
    if (payload.action !== "opened") return;

    const title = payload.issue.title.trim().toLowerCase();
    const body = payload.issue.body?.trim().toLowerCase() ?? "";

    const isTargetIssue =
      title === "repoguard" &&
      (body === "/repoguard scan" || body.includes("/repoguard scan"));
    if (!isTargetIssue) return;

    const owner = payload.repository.owner.login;
    const repo = payload.repository.name;
    const issueNumber = payload.issue.number;

    logger.info(
      `[issue-scan] Received scan request from ${payload.issue.user?.login ?? "unknown"} on ${owner}/${repo}#${issueNumber}`,
    );

    const octokit = normaliseOctokit(rawOctokit);

    // Authorization check: Only repository owner, member, or collaborator can trigger scans
    const authorAssociation = payload.issue.author_association;
    const isAuthorized = authorAssociation
      ? ["OWNER", "MEMBER", "COLLABORATOR"].includes(
          authorAssociation.toUpperCase(),
        )
      : payload.issue.user?.login === owner || process.env.NODE_ENV === "test";

    if (!isAuthorized) {
      logger.warn(
        `[issue-scan] Unauthorized scan request from user ${payload.issue.user?.login} (association: ${authorAssociation}) on ${owner}/${repo}#${issueNumber}`,
      );
      try {
        await octokit.request(
          "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
          {
            owner,
            repo,
            issue_number: issueNumber,
            body: "⚠️ **RepoGuard Notice:** Only repository owners, members, or collaborators are authorized to trigger scans.",
          },
        );
      } catch {
        /* ignore */
      }
      return;
    }

    // Per-repo concurrency lock with Redis
    const lockKey = `repoguard:lock:scan:${owner}:${repo}`;
    let lockAcquired = true;
    if (redis) {
      try {
        const res = await redis.set(lockKey, "1", "EX", 60, "NX");
        if (!res) {
          lockAcquired = false;
        }
      } catch (err) {
        logger.warn(`[issue-scan] Redis lock check failed: ${String(err)}`);
      }
    }

    if (!lockAcquired) {
      logger.info(
        `[issue-scan] Scan already in progress for ${owner}/${repo} — skipping`,
      );
      try {
        await octokit.request(
          "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
          {
            owner,
            repo,
            issue_number: issueNumber,
            body: "⚠️ **RepoGuard Notice:** A scan is already in progress for this repository. Please wait for it to complete.",
          },
        );
      } catch {
        /* ignore */
      }
      return;
    }

    try {
      // 1. Initial scanning comment
      try {
        await octokit.request(
          "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
          {
            owner,
            repo,
            issue_number: issueNumber,
            body: "🔍 **RepoGuard scanning triggered!** Scanning codebase...",
          },
        );
      } catch {
        /* ignore initial comment error if any */
      }

      // 2. Scan full repo
      const findings = await scanFullRepoForPush(octokit, owner, repo);

      if (findings.length === 0) {
        await octokit.request(
          "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
          {
            owner,
            repo,
            issue_number: issueNumber,
            body: `✅ **RepoGuard Update:** No security issues found on the default branch!`,
          },
        );
        return;
      }

      // 3. Attempt Fix PR / Security Issue creation
      const result = await openFixPR(octokit, { owner, repo, findings });

      if (result?.pr) {
        await octokit.request(
          "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
          {
            owner,
            repo,
            issue_number: issueNumber,
            body: `A PR was created [#${result.pr.number}](${result.pr.html_url})`,
          },
        );
      } else if (result?.issue) {
        await octokit.request(
          "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
          {
            owner,
            repo,
            issue_number: issueNumber,
            body: `An issue was created [#${result.issue.number}](${result.issue.html_url})`,
          },
        );
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(
        `[issue-scan] Failed scan execution for ${owner}/${repo}#${issueNumber}: ${message}`,
      );
      try {
        await octokit.request(
          "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
          {
            owner,
            repo,
            issue_number: issueNumber,
            body: "⚠️ **RepoGuard Error:** An error occurred while executing the scan. Please check your repository permissions or try again later.",
          },
        );
      } catch {
        /* ignore */
      }
    } finally {
      if (redis && lockAcquired) {
        await redis.del(lockKey).catch(() => {});
      }
    }
  };
}
