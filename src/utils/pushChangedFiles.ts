import type { GitHubCommit } from "../types/github";
import type { OctokitClient } from "../types";
import logger from "./logger";

const EMPTY_SHA = "0000000000000000000000000000000000000000";

export interface PushChangedFiles {
  added: string[];
  modified: string[];
  removed: string[];
}

function aggregateFromWebhookCommits(
  commits: GitHubCommit[],
): PushChangedFiles {
  const added = new Set<string>();
  const modified = new Set<string>();
  const removed = new Set<string>();

  for (const commit of commits) {
    for (const file of commit.added ?? []) added.add(file);
    for (const file of commit.modified ?? []) modified.add(file);
    for (const file of commit.removed ?? []) removed.add(file);
  }

  return {
    added: [...added],
    modified: [...modified],
    removed: [...removed],
  };
}

/** Resolve changed files for a push using GitHub compare, with webhook fallback. */
export async function getPushChangedFiles(
  octokit: OctokitClient,
  owner: string,
  repo: string,
  before: string | undefined,
  after: string,
  commits: GitHubCommit[],
): Promise<PushChangedFiles> {
  const webhookFiles = aggregateFromWebhookCommits(commits);

  if (before && before !== EMPTY_SHA) {
    try {
      const { data } = await octokit.request(
        "GET /repos/{owner}/{repo}/compare/{basehead}",
        { owner, repo, basehead: `${before}...${after}` },
      );

      const added = new Set<string>();
      const modified = new Set<string>();
      const removed = new Set<string>();

      for (const file of data.files ?? []) {
        switch (file.status) {
          case "added":
            added.add(file.filename);
            break;
          case "modified":
          case "changed":
            modified.add(file.filename);
            break;
          case "removed":
            removed.add(file.filename);
            break;
          case "renamed":
          case "copied":
            if (file.filename) modified.add(file.filename);
            if (file.previous_filename) removed.add(file.previous_filename);
            break;
          default:
            break;
        }
      }

      const compareCount = added.size + modified.size + removed.size;
      if (compareCount > 0) {
        return {
          added: [...added],
          modified: [...modified],
          removed: [...removed],
        };
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.warn(
        `[push] Compare API failed for ${owner}/${repo}, using webhook file lists: ${message}`,
      );
    }
  }

  return webhookFiles;
}
