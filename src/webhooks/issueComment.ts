import type { App } from "@octokit/app";
import { normaliseOctokit } from "../utils/normaliseOctokit";
import { scanFullRepoForPush } from "./installation";
import { openFixPR } from "../pullRequest";
import logger from "../utils/logger";
import type { WebhookEvent } from "../types/index";

export interface IssueCommentPayload {
  action: string;
  issue: {
    number: number;
    title: string;
    body?: string;
    user?: { login: string };
  };
  comment: {
    id: number;
    body: string;
    user: { login: string };
  };
  repository: {
    owner: { login: string };
    name: string;
  };
}

/**
 * Factory — returns a webhook handler for issue_comment.created events.
 * If a user comments `/fix` or `@repoguard fix` on a RepoGuard security issue,
 * RepoGuard automatically rescans the repo and attempts to generate a Fix PR.
 */
export function handleIssueComment(
  _app: App,
): (event: WebhookEvent<IssueCommentPayload>) => Promise<void> {
  return async ({ octokit: rawOctokit, payload }) => {
    const octokit = normaliseOctokit(rawOctokit);
    if (payload.action !== "created") return;

    const commentText = payload.comment.body.trim().toLowerCase();
    const isFixCommand =
      commentText === "/fix" ||
      commentText.startsWith("/fix ") ||
      commentText.includes("@repoguard fix");

    if (!isFixCommand) return;

    const isRepoGuardIssue =
      payload.issue.title.includes("RepoGuard") ||
      (payload.issue.body?.includes("RepoGuard") ?? false);

    if (!isRepoGuardIssue) return;

    const owner = payload.repository.owner.login;
    const repo = payload.repository.name;
    const issueNumber = payload.issue.number;

    logger.info(
      `[issue-command] Received /fix command from ${payload.comment.user.login} on ${owner}/${repo}#${issueNumber}`,
    );

    // 1. React with rocket emoji to indicate processing
    try {
      await octokit.request(
        "POST /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions",
        {
          owner,
          repo,
          comment_id: payload.comment.id,
          content: "rocket",
        },
      );
    } catch {
      /* ignore reaction error — not fatal */
    }

    try {
      // 2. Scan full repo to get active findings
      const findings = await scanFullRepoForPush(octokit, owner, repo);

      if (findings.length === 0) {
        await octokit.request(
          "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
          {
            owner,
            repo,
            issue_number: issueNumber,
            body: `✅ **RepoGuard Update:** No security issues remain on the default branch! You can safely close this issue.`,
          },
        );
        return;
      }

      // 3. Attempt Fix PR creation
      await openFixPR(octokit, { owner, repo, findings });

      await octokit.request(
        "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
        {
          owner,
          repo,
          issue_number: issueNumber,
          body: `🚀 **RepoGuard Fix Triggered!** An automated Fix PR or updated remediation branch has been generated. Check your repository's Pull Requests!`,
        },
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(
        `[issue-command] Failed to generate fix for ${owner}/${repo}#${issueNumber}: ${message}`,
      );
      try {
        await octokit.request(
          "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
          {
            owner,
            repo,
            issue_number: issueNumber,
            body: `⚠️ **RepoGuard Error:** Failed to generate an automated fix: ${message}`,
          },
        );
      } catch {
        /* ignore */
      }
    }
  };
}
