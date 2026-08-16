import type { App } from "@octokit/app";
import { normaliseOctokit } from "../utils/normaliseOctokit";
import { scanFullRepoForPush } from "./installation";
import { openFixPR } from "../pullRequest";
import logger from "../utils/logger";
import type { WebhookEvent } from "../types/index";

export interface IssuesOpenedPayload {
  action: string;
  issue: {
    number: number;
    title: string;
    body?: string;
    user?: { login: string };
    html_url?: string;
  };
  repository: {
    owner: { login: string };
    name: string;
  };
}

/**
 * Factory — returns a webhook handler for issues.opened events.
 * If a user creates an issue with title "Repoguard" and body "@repoguard scan",
 * RepoGuard automatically scans the repo and replies with a status comment,
 * followed by a comment containing a markdown link to the created PR or issue if findings exist.
 */
export function handleIssuesOpened(
  _app: App,
): (event: WebhookEvent<IssuesOpenedPayload>) => Promise<void> {
  return async ({ octokit: rawOctokit, payload }) => {
    if (payload.action !== "opened") return;

    const title = payload.issue.title.trim();
    const body = payload.issue.body?.trim() ?? "";

    const isTargetIssue = title === "Repoguard" && body === "@repoguard scan";
    if (!isTargetIssue) return;

    const owner = payload.repository.owner.login;
    const repo = payload.repository.name;
    const issueNumber = payload.issue.number;

    logger.info(
      `[issue-scan] Received scan request from ${payload.issue.user?.login ?? "unknown"} on ${owner}/${repo}#${issueNumber}`,
    );

    const octokit = normaliseOctokit(rawOctokit);

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

    try {
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
            body: `A pr was created [PR${result.pr.number}](${result.pr.html_url})`,
          },
        );
      } else if (result?.issue) {
        await octokit.request(
          "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
          {
            owner,
            repo,
            issue_number: issueNumber,
            body: `An issue was created [PR${result.issue.number}](${result.issue.html_url})`,
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
            body: `⚠️ **RepoGuard Error:** Failed to execute scan: ${message}`,
          },
        );
      } catch {
        /* ignore */
      }
    }
  };
}
