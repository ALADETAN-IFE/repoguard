import type { App } from "@octokit/app";
import { scanFileContent, scanWorkflowContent } from "../scanner";
import { postReviewComments } from "../pullRequest";
import { normaliseOctokit } from "../utils/normaliseOctokit";
import { shouldSkipPath } from "../utils/skipPaths";
import { isBinaryPath, looksLikeJavaScript } from "../utils/binaryPath";
import logger from "../utils/logger";
import type { WebhookEvent, Finding, OctokitClient } from "../types/index";

interface PullRequestOpenedPayload {
  action: string;
  pull_request: {
    number: number;
    head: { sha: string; ref: string };
    changed_files: number;
  };
  repository: {
    name: string;
    owner: { login: string };
  };
}

// ─── Scan all files changed across the entire PR (not just the latest push) ──

async function scanFullPRDiff(
  client: OctokitClient,
  owner: string,
  repo: string,
  prNumber: number,
  headSha: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Paginate through all PR files (GitHub returns max 30 per page)
  let page = 1;
  const allFiles: Array<{ filename: string; status: string }> = [];

  while (true) {
    const { data: files } = await client.request(
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/files",
      { owner, repo, pull_number: prNumber, per_page: 100, page },
    );

    if (files.length === 0) break;
    allFiles.push(...files);
    if (files.length < 100) break;
    page++;
  }

  const filesToScan = allFiles.filter(
    (f) => f.status !== "removed" && !shouldSkipPath(f.filename),
  );

  logger.info(
    `[pr] Scanning ${filesToScan.length} file(s) across PR #${prNumber}`,
  );

  // Fetch and scan in batches of 10 to keep memory low
  const BATCH_SIZE = 10;
  for (let i = 0; i < filesToScan.length; i += BATCH_SIZE) {
    const batch = filesToScan.slice(i, i + BATCH_SIZE);

    await Promise.all(
      batch.map(async (file) => {
        const binary = isBinaryPath(file.filename);
        try {
          const { data } = await client.request(
            "GET /repos/{owner}/{repo}/contents/{path}",
            { owner, repo, path: file.filename, ref: headSha },
          );

          if (
            Array.isArray(data) ||
            data.type !== "file" ||
            !("content" in data)
          )
            return;

          const content = Buffer.from(
            data.content as string,
            "base64",
          ).toString("utf8");

          if (binary && !looksLikeJavaScript(content)) return;

          const isWorkflow =
            file.filename.toLowerCase().startsWith(".github/workflows/") &&
            (file.filename.endsWith(".yml") || file.filename.endsWith(".yaml"));

          if (isWorkflow) {
            findings.push(...scanFileContent(content, file.filename));
            findings.push(...scanWorkflowContent(content, file.filename));
          } else {
            findings.push(...scanFileContent(content, file.filename));
          }
        } catch {
          // File inaccessible — skip
        }
      }),
    );
  }

  return findings;
}

// ─── Check if this PR had a previous RepoGuard review with findings ───────────

async function getPreviousRepoGuardFindings(
  client: OctokitClient,
  owner: string,
  repo: string,
  prNumber: number,
): Promise<boolean> {
  try {
    const { data: reviews } = await client.request(
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews",
      { owner, repo, pull_number: prNumber },
    );

    return (
      reviews as Array<{ user?: { login?: string }; body?: string }>
    ).some(
      (review) =>
        review.user?.login?.includes("[bot]") &&
        review.body?.includes("RepoGuard detected"),
    );
  } catch {
    return false;
  }
}

// ─── Webhook handler (handles both opened and synchronize) ───────────────────

export function handlePullRequestOpened(
  _app: App,
): (event: WebhookEvent<PullRequestOpenedPayload>) => Promise<void> {
  return async ({ octokit, payload }) => {
    const { pull_request, repository, action } = payload;
    const owner = repository.owner.login;
    const repo = repository.name;
    const headSha = pull_request.head.sha;
    const prNumber = pull_request.number;
    const isSynchronize = action === "synchronize";

    logger.info(
      `[pr] PR #${prNumber} ${action} in ${owner}/${repo} — scanning full diff`,
    );

    const client = normaliseOctokit(octokit);

    try {
      // ── Scan ALL files changed in the PR, not just the latest push ─────────
      const findings = await scanFullPRDiff(
        client,
        owner,
        repo,
        prNumber,
        headSha,
      );

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
          new Map(), // no pre-patched content for PR scans
        );
      } else {
        logger.info(`[pr] PR #${prNumber} is clean`);

        // ── If this is a new push (synchronize) and previous pushes had
        //    findings, warn that the PR history still contains flagged code ───
        if (isSynchronize) {
          const hadPreviousFindings = await getPreviousRepoGuardFindings(
            client,
            owner,
            repo,
            prNumber,
          );

          if (hadPreviousFindings) {
            try {
              await client.request(
                "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
                {
                  owner,
                  repo,
                  issue_number: prNumber,
                  body: [
                    "## ⚠️ RepoGuard: Latest push is clean — but this PR has a history of flagged code",
                    "",
                    "The most recent push passed the security scan, but **earlier commits in this PR were flagged** for security issues.",
                    "",
                    "Before merging, please ensure:",
                    "- The flagged code has been fully removed (not just overwritten in a later commit)",
                    "- No malicious code exists anywhere in the PR's commit history",
                    "- You have reviewed and resolved all previous RepoGuard review comments",
                    "",
                    "You can squash the commits before merging to ensure a clean history.",
                    "",
                    "---",
                    "_RepoGuard · This warning is informational — it does not block the merge._",
                  ].join("\n"),
                },
              );
              logger.info(
                `[pr] Posted history warning on PR #${prNumber} — previous findings existed`,
              );
            } catch (commentErr) {
              const msg =
                commentErr instanceof Error
                  ? commentErr.message
                  : String(commentErr);
              logger.warn(
                `[pr] Could not post history warning on PR #${prNumber}: ${msg}`,
              );
            }
          }
        }
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`[pr] Error scanning PR #${prNumber}: ${message}`);
    }
  };
}
