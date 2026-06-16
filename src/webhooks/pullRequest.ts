import type { App } from "@octokit/app";
import { scanCommit } from "../scanner";
import { postReviewComments } from "../pullRequest";
import { normaliseOctokit } from "../utils/normaliseOctokit";
import logger from "../utils/logger";
import type { WebhookEvent } from "../types/index";

export function handlePullRequestOpened(
  _app: App,
): (event: WebhookEvent<any>) => Promise<void> {
  return async ({ octokit, payload }) => {
    const { pull_request, repository } = payload as {
      pull_request: {
        number: number;
        head: { sha: string; ref: string };
        changed_files: number;
      };
      repository: { name: string; owner: { login: string } };
    };

    const owner = repository.owner.login;
    const repo = repository.name;
    const headSha = pull_request.head.sha;
    const prNumber = pull_request.number;

    logger.info(`[pr] Scanning PR #${prNumber} in ${owner}/${repo}`);

    const client = normaliseOctokit(octokit);

    // Get the files changed in this PR
    try {
      const { data: files } = await client.request(
        "GET /repos/{owner}/{repo}/pulls/{pull_number}/files",
        { owner, repo, pull_number: prNumber },
      );

      const addedFiles = files
        .filter((f: { status: string }) => f.status === "added")
        .map((f: { filename: string }) => f.filename);

      const modifiedFiles = files
        .filter((f: { status: string }) => f.status === "modified")
        .map((f: { filename: string }) => f.filename);

      const findings = await scanCommit({
        octokit: client,
        owner,
        repo,
        sha: headSha,
        addedFiles,
        modifiedFiles,
      });

      if (findings.length > 0) {
        logger.warn(
          `[pr] ${findings.length} finding(s) in PR #${prNumber} — posting review comments`,
        );
        await postReviewComments(
          client,
          owner,
          repo,
          prNumber,
          headSha,
          findings,
          new Map(),
        );
      } else {
        logger.info(`[pr] PR #${prNumber} is clean`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`[pr] Error scanning PR #${prNumber}: ${message}`);
    }
  };
}