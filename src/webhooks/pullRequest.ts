import type { App } from "@octokit/app";
import {
  scanFileContent,
  scanWorkflowContent,
  shouldSkipPath,
  isBinaryPath,
  looksLikeJavaScript,
} from "@repoguard/scanner";
import { postReviewComments, getOpenRepoGuardIssue } from "../pullRequest";
import { normaliseOctokit } from "../utils/normaliseOctokit";
import logger from "../utils/logger";
import { isAuthorizedFixBranchPusher } from "../utils/botAuth";
import type { WebhookEvent, Finding, OctokitClient } from "../types/index";

interface PullRequestOpenedPayload {
  action: string;
  pull_request: {
    number: number;
    head: { sha: string; ref: string };
    changed_files: number;
    html_url?: string;
  };
  repository: {
    name: string;
    owner: { login: string };
  };
  sender?: { login: string; type?: string };
}

interface PRDiffScanResult {
  findings: Finding[];
  totalChangedFiles: number;
}

// ─── Scan all files changed across the entire PR (not just the latest push) ──

async function scanFullPRDiff(
  client: OctokitClient,
  owner: string,
  repo: string,
  prNumber: number,
  headSha: string,
): Promise<PRDiffScanResult> {
  const findings: Finding[] = [];

  // Paginate through all PR files (GitHub returns max 100 per page)
  let page = 1;
  const allFiles: Array<{ filename: string; status: string }> = [];
  let lastPageCount = 0;

  do {
    const { data: files } = await client.request(
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/files",
      { owner, repo, pull_number: prNumber, per_page: 100, page },
    );

    if (files.length === 0) break;
    allFiles.push(...files);
    lastPageCount = files.length;
    page++;
  } while (lastPageCount === 100);

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

          const content = Buffer.from(data.content, "base64").toString("utf8");

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

  return { findings, totalChangedFiles: allFiles.length };
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
    const isFixBranch = pull_request.head.ref.startsWith("repoguard/fixes-");

    // ── Safeguard: Prevent unauthorized tampering with RepoGuard Fix PRs ────────
    if (
      isFixBranch &&
      isSynchronize &&
      payload.sender &&
      !isAuthorizedFixBranchPusher(
        undefined,
        payload.sender.login,
        payload.sender.type,
      )
    ) {
      logger.warn(
        `[pr] TAMPERING DETECTED: Unauthorized synchronize on fix PR #${prNumber} (${pull_request.head.ref}) by "${payload.sender.login}" in ${owner}/${repo}`,
      );

      try {
        await client.request(
          "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
          {
            owner,
            repo,
            issue_number: prNumber,
            body: [
              "🚨 **RepoGuard Security Alert: Fix Branch Tampering Detected**",
              "",
              `An unauthorized synchronize/push event was initiated by **${payload.sender.login}** on automated remediation branch \`${pull_request.head.ref}\`.`,
              "",
              "RepoGuard fix branches are exclusively managed by the RepoGuard bot to prevent unverified code injections.",
              "Closing this PR and deleting the branch to protect repository integrity.",
            ].join("\n"),
          },
        );

        await client.request(
          "PATCH /repos/{owner}/{repo}/pulls/{pull_number}",
          {
            owner,
            repo,
            pull_number: prNumber,
            state: "closed",
          },
        );

        try {
          await client.request("DELETE /repos/{owner}/{repo}/git/refs/{ref}", {
            owner,
            repo,
            ref: `heads/${pull_request.head.ref}`,
          });
          logger.info(
            `[pr] Deleted tampered branch ${pull_request.head.ref} in ${owner}/${repo}`,
          );
        } catch {
          // ignore
        }
      } catch (err) {
        logger.warn(
          `[pr] Could not close tampered PR #${prNumber}: ${String(err)}`,
        );
      }

      return;
    }

    try {
      // ── Scan ALL files changed in the PR, not just the latest push ─────────
      const { findings, totalChangedFiles } = await scanFullPRDiff(
        client,
        owner,
        repo,
        prNumber,
        headSha,
      );

      // ── Safeguard: Automatically close obsolete Fix PRs with 0 diff ────────
      if (isFixBranch && totalChangedFiles === 0) {
        logger.info(
          `[pr] Fix PR #${prNumber} (${pull_request.head.ref}) has 0 changed files relative to base branch — closing as obsolete`,
        );

        try {
          await client.request(
            "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
            {
              owner,
              repo,
              issue_number: prNumber,
              body: [
                "ℹ️ **RepoGuard Notice: Remediation PR is Obsolete**",
                "",
                "This pull request no longer contains any file changes relative to the base branch (`0 files changed`).",
                "",
                "The proposed security remediation has either been reverted, already applied directly to the base branch, or overwritten.",
                "Closing this PR and cleaning up the branch.",
              ].join("\n"),
            },
          );

          await client.request(
            "PATCH /repos/{owner}/{repo}/pulls/{pull_number}",
            {
              owner,
              repo,
              pull_number: prNumber,
              state: "closed",
            },
          );

          try {
            await client.request(
              "DELETE /repos/{owner}/{repo}/git/refs/{ref}",
              {
                owner,
                repo,
                ref: `heads/${pull_request.head.ref}`,
              },
            );
            logger.info(
              `[pr] Deleted obsolete branch ${pull_request.head.ref} in ${owner}/${repo}`,
            );
          } catch {
            // ignore
          }
        } catch (err) {
          logger.warn(
            `[pr] Could not close obsolete PR #${prNumber}: ${String(err)}`,
          );
        }

        return;
      }

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

export interface PullRequestClosedPayload {
  action: string;
  pull_request: {
    number: number;
    merged: boolean;
    body?: string;
    html_url?: string;
    head: { sha: string; ref: string };
  };
  repository: {
    name: string;
    owner: { login: string };
    default_branch?: string;
  };
  sender?: { login: string; type?: string };
}

const INFECTED_PR_TRIGGER = "infected pr";

export function handlePullRequestClosed(
  _app: App,
): (event: WebhookEvent<PullRequestClosedPayload>) => Promise<void> {
  return async ({ octokit, payload }) => {
    const { pull_request, repository, action } = payload;
    if (action !== "closed") return;

    const owner = repository.owner.login;
    const repo = repository.name;
    const branchRef = pull_request.head.ref;
    const client = normaliseOctokit(octokit);
    const isFixBranch = branchRef.startsWith("repoguard/fixes-");
    const wasMerged = pull_request.merged;

    // ── 1. Always clean up the fix branch ──────────────────────────────────
    if (isFixBranch) {
      try {
        await client.request("DELETE /repos/{owner}/{repo}/git/refs/{ref}", {
          owner,
          repo,
          ref: `heads/${branchRef}`,
        });
        logger.info(
          `[pr] Deleted branch ${branchRef} in ${owner}/${repo} after PR #${pull_request.number} was ${wasMerged ? "merged" : "closed"}`,
        );
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        logger.warn(
          `[pr] Could not delete branch ${branchRef} in ${owner}/${repo}: ${message}`,
        );
      }
    }

    // ── 2. If merged: close any linked security issues ──────────────────────
    if (wasMerged) {
      try {
        const bodyText = pull_request.body || "";
        const issueMatches = [
          ...bodyText.matchAll(
            /(?:Fixes|Closes|Resolves|Fix|Close|Resolve|Issue)\s+#(\d+)/gi,
          ),
        ].map((m) => parseInt(m[1], 10));

        const targetIssueNumbers = new Set(issueMatches);

        const openIssue = await getOpenRepoGuardIssue(client, owner, repo);
        if (openIssue) {
          targetIssueNumbers.add(openIssue.number);
        }

        for (const issueNum of targetIssueNumbers) {
          logger.info(
            `[pr] PR #${pull_request.number} merged — closing linked issue #${issueNum} with remark`,
          );
          await client.request(
            "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
            {
              owner,
              repo,
              issue_number: issueNum,
              body: `🎉 **RepoGuard Update:** Fix PR [#${pull_request.number}](${pull_request.html_url || `https://github.com/${owner}/${repo}/pull/${pull_request.number}`}) has been merged into the default branch. Closing this security issue as resolved.`,
            },
          );
          await client.request(
            "PATCH /repos/{owner}/{repo}/issues/{issue_number}",
            {
              owner,
              repo,
              issue_number: issueNum,
              state: "closed",
              state_reason: "completed",
            },
          );
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        logger.warn(
          `[pr] Could not close linked issue for merged PR #${pull_request.number}: ${message}`,
        );
      }

      return; // merged → done
    }

    // ── 3. Closed WITHOUT merging — rescan and respond ─────────────────────
    if (!isFixBranch) return; // only care about our own fix branches

    logger.warn(
      `[pr] RepoGuard Fix PR #${pull_request.number} was closed without merging in ${owner}/${repo} — rescanning`,
    );

    try {
      // Check if the last comment on the PR contains "infected pr"
      let isInfectedPRTrigger = false;
      try {
        const { data: comments } = await client.request(
          "GET /repos/{owner}/{repo}/issues/{issue_number}/comments",
          { owner, repo, issue_number: pull_request.number, per_page: 100 },
        );
        const allComments = comments as Array<{
          body?: string;
          user?: { type?: string; login?: string };
        }>;
        // Look through all comments (excluding bot comments) for "infected pr"
        isInfectedPRTrigger = allComments
          .filter((c) => c.user?.type !== "Bot")
          .some((c) => c.body?.toLowerCase().includes(INFECTED_PR_TRIGGER));
      } catch {
        /* if we can't fetch comments, proceed without the trigger */
      }

      // Full repo scan on the default branch
      const { scanFullRepoForPush } = await import("./installation");
      const findings = await scanFullRepoForPush(client, owner, repo);

      if (findings.length === 0) {
        // Repo is now clean — close any linked security issue
        logger.info(
          `[pr] Post-close rescan: ${owner}/${repo} is clean — no action needed`,
        );
        const openIssue = await getOpenRepoGuardIssue(client, owner, repo);
        if (openIssue) {
          await client.request(
            "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
            {
              owner,
              repo,
              issue_number: openIssue.number,
              body: `✅ **RepoGuard Update:** Fix PR #${pull_request.number} was closed, but a rescan of the default branch shows **no security issues remain**. Closing this issue as resolved.`,
            },
          );
          await client.request(
            "PATCH /repos/{owner}/{repo}/issues/{issue_number}",
            {
              owner,
              repo,
              issue_number: openIssue.number,
              state: "closed",
              state_reason: "completed",
            },
          );
        }
        return;
      }

      // Threats still present after close
      logger.warn(
        `[pr] Post-close rescan: ${findings.length} finding(s) still active in ${owner}/${repo}`,
      );

      if (isInfectedPRTrigger) {
        // ── "infected pr" comment detected → open a fresh Fix PR ─────────────
        logger.info(
          `[pr] "infected pr" trigger detected on closed PR #${pull_request.number} — generating new Fix PR`,
        );

        const { openFixPR } = await import("../pullRequest");
        const openIssue = await getOpenRepoGuardIssue(client, owner, repo);
        const result = await openFixPR(client, {
          owner,
          repo,
          findings,
          issueNumber: openIssue?.number,
        });

        if (result?.pr) {
          logger.info(
            `[pr] Opened fresh Fix PR #${result.pr.number} in ${owner}/${repo} after "infected pr" trigger`,
          );
          // Comment on the closed PR linking the new one
          try {
            await client.request(
              "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
              {
                owner,
                repo,
                issue_number: pull_request.number,
                body: [
                  `🔄 **RepoGuard:** "infected pr" trigger received.`,
                  ``,
                  `A rescan confirmed **${findings.length} security issue(s) still active** on the default branch.`,
                  `A new automated Fix PR has been opened: [#${result.pr.number}](${result.pr.html_url})`,
                ].join("\n"),
              },
            );
          } catch {
            /* non-fatal */
          }
        }
      } else {
        // ── Standard close without "infected pr" → open/update security issue ─
        const { openFixPR } = await import("../pullRequest");
        const openIssue = await getOpenRepoGuardIssue(client, owner, repo);

        if (openIssue) {
          // Update existing issue
          await client.request(
            "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
            {
              owner,
              repo,
              issue_number: openIssue.number,
              body: [
                `⚠️ **RepoGuard Alert:** Fix PR #${pull_request.number} was closed without merging.`,
                ``,
                `A rescan of the default branch found **${findings.length} security issue(s) still active**.`,
                ``,
                `Comment \`/fix\` to generate a new automated Fix PR, or remediate the findings manually.`,
              ].join("\n"),
            },
          );
          // Reopen if closed
          await client.request(
            "PATCH /repos/{owner}/{repo}/issues/{issue_number}",
            { owner, repo, issue_number: openIssue.number, state: "open" },
          );
        } else {
          // No open issue — open a fresh one via openFixPR fallback
          await openFixPR(client, { owner, repo, findings });
        }
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(
        `[pr] Post-close rescan failed for ${owner}/${repo}: ${message}`,
      );
    }
  };
}
