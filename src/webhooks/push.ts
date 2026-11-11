import type { App } from "@octokit/app";
import { Types } from "mongoose";
import { scanCommit } from "@repoguard/scanner";
import { createCheckRun, updateCheckRun } from "../checks";
import { sendAlert } from "../alerts";
import {
  closeRepoGuardPRsAndIssues,
  getExistingRepoGuardFixPR,
  getOpenRepoGuardIssue,
  openFixPR,
  postReviewComments,
} from "../pullRequest";
import { normaliseOctokit } from "../utils/normaliseOctokit";
import { getPushChangedFiles } from "../utils/pushChangedFiles";
import { scanFullRepoForPush, scanFullRepoWithDetails } from "./installation";
import { safeWrite } from "../utils/writeQueue";
import { Scan, Installation } from "../models";
import logger from "../utils/logger";
import {
  hasFixBranchWritePermission,
  isAuthorizedFixBranchPusher,
} from "../utils/botAuth";
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

    const startTime = Date.now();
    const scanId = new Types.ObjectId();
    let installationId = (payload as { installation?: { id: number } })
      .installation?.id;
    if (!installationId) {
      try {
        const inst = await Installation.findOne({
          owner: new RegExp(`^${owner}$`, "i"),
          uninstalledAt: null,
        }).lean();
        installationId = inst?.installationId;
      } catch {
        // ignore
      }
    }

    await safeWrite(`Scan.create:${owner}/${repo}:${headSha.slice(0, 7)}`, {
      type: "CREATE_SCAN",
      data: {
        scanId: scanId.toHexString(),
        installationId,
        owner,
        repo,
        branch,
        commitSha: headSha,
        status: "in_progress",
        trigger: "push",
        startedAt: new Date(startTime).toISOString(),
      },
    });

    const checkRunId = await createCheckRun({
      octokit: client,
      owner,
      repo,
      headSha,
      name: "RepoGuard Security Scan",
      status: "in_progress",
    });

    if (!checkRunId) return;

    // ── Safeguard: Prevent unauthorized tampering with RepoGuard Fix branches ──
    const isFixBranch = branch.startsWith("repoguard/fixes-");
    if (isFixBranch) {
      const actorName = payload.sender?.login || pusher?.name || "unknown";
      const isBot = isAuthorizedFixBranchPusher(
        pusher?.name,
        payload.sender?.login,
        payload.sender?.type,
      );
      const hasWriteAccess =
        isBot ||
        (await hasFixBranchWritePermission(client, owner, repo, actorName));

      if (!isBot && hasWriteAccess) {
        // Authorized repository user — allow without blocking or deleting branch
        logger.info(
          `[push] Authorized user push to fix branch "${branch}" by "${actorName}" in ${owner}/${repo} — allowed, scanning diff`,
        );
        // Fall through — continue scanning the pushed commit normally.
        // The pull_request (synchronize) webhook handler manages posting the warning comment to the PR.
      } else if (!isBot && !hasWriteAccess) {
        // Unauthorized third party — block
        logger.warn(
          `[push] TAMPERING DETECTED: Unauthorized push to automated remediation branch "${branch}" by "${actorName}" in ${owner}/${repo}`,
        );

        await updateCheckRun({
          octokit: client,
          owner,
          repo,
          checkRunId,
          conclusion: "failure",
          findings: [
            {
              rule: "unauthorized-fix-branch-modification",
              severity: "critical",
              message: `Unauthorized push detected on automated remediation branch "${branch}" by "${actorName}". RepoGuard fix branches cannot be modified by external contributors.`,
              file: null,
            },
          ],
          summary: [
            "🚨 **SECURITY ALERT: Unauthorized Fix Branch Modification**",
            "",
            `The automated remediation branch \`${branch}\` was pushed to by **${actorName}**.`,
            "",
            "RepoGuard remediation branches are strictly managed by the RepoGuard bot to guarantee patch authenticity.",
            "External commits or force-pushes to fix branches invalidate the remediation state.",
            "",
            "**Actions Taken:**",
            "- Failed security status check.",
            "- Associated pull request closed.",
            "- Compromised branch deleted.",
          ].join("\n"),
        });

        // Close open PR on this branch
        try {
          const { data: pulls } = await client.request(
            "GET /repos/{owner}/{repo}/pulls",
            { owner, repo, state: "open", head: `${owner}:${branch}` },
          );

          if ((pulls as unknown[]).length > 0) {
            const pr = (pulls as Array<{ number: number }>)[0];
            await client.request(
              "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
              {
                owner,
                repo,
                issue_number: pr.number,
                body: [
                  "🚨 **RepoGuard Security Alert: Fix Branch Tampering Detected**",
                  "",
                  `An unauthorized push by **${actorName}** was detected on this remediation branch (\`${branch}\`).`,
                  "",
                  "Automated remediation pull requests must not be modified directly by external contributors or force-pushes.",
                  "Closing this PR and deleting the branch to protect repository integrity. If vulnerabilities remain on the default branch, RepoGuard will generate a fresh remediation.",
                ].join("\n"),
              },
            );

            await client.request(
              "PATCH /repos/{owner}/{repo}/pulls/{pull_number}",
              {
                owner,
                repo,
                pull_number: pr.number,
                state: "closed",
              },
            );
            logger.info(
              `[push] Closed tampered PR #${pr.number} in ${owner}/${repo}`,
            );
          }
        } catch (prErr) {
          logger.warn(
            `[push] Could not close tampered PR: ${prErr instanceof Error ? prErr.message : String(prErr)}`,
          );
        }

        // Delete the tampered branch
        try {
          await client.request("DELETE /repos/{owner}/{repo}/git/refs/{ref}", {
            owner,
            repo,
            ref: `heads/${branch}`,
          });
          logger.info(
            `[push] Deleted tampered branch ${branch} in ${owner}/${repo}`,
          );
        } catch (delErr) {
          logger.warn(
            `[push] Could not delete tampered branch: ${delErr instanceof Error ? delErr.message : String(delErr)}`,
          );
        }

        await sendAlert({
          owner,
          repo,
          ref,
          pusher: actorName,
          headSha,
          findings: [
            {
              rule: "unauthorized-fix-branch-modification",
              severity: "critical",
              message: `Unauthorized push to remediation branch ${branch} by ${actorName}`,
              file: null,
            },
          ],
          context: "push",
        });

        await safeWrite(
          `Scan.complete:${owner}/${repo}:${headSha.slice(0, 7)}`,
          {
            type: "COMPLETE_SCAN",
            data: {
              scanId: scanId.toHexString(),
              findingsCount: 1,
              filesScanned: 0,
              durationMs: Date.now() - startTime,
              completedAt: new Date().toISOString(),
            },
          },
        );

        return;
      }
    }

    try {
      let findings: Finding[] = [];
      let filesScannedCount = 0;
      const revertFiles = new Map<string, string>();

      if (isForcePush && isDefaultBranch) {
        // Force push on default branch — scan entire repo, not just diff
        logger.warn(
          `[push] Force push detected on ${owner}/${repo} — running full repo scan`,
        );
        const result = await scanFullRepoWithDetails(client, owner, repo);
        findings = result.findings;
        filesScannedCount = result.filesScanned;
      } else {
        const { added, modified, removed } = await getPushChangedFiles(
          client,
          owner,
          repo,
          before,
          headSha,
          commits,
        );

        filesScannedCount = added.length + modified.length;

        findings = await scanCommit({
          octokit: client,
          owner,
          repo,
          sha: headSha,
          addedFiles: added,
          modifiedFiles: modified,
          removedFiles: removed,
        });

        // ── Detect Dockerfiles modified alongside malware ──────────────────────
        const hasMalwareFindings = findings.some((f) =>
          [
            "obfuscated-malware-pattern",
            "obfuscated-base64",
            "js-obfuscated-charcode",
            "js-obfuscated-hex",
            "js-obfuscated-constructors",
            "reverse-shell",
            "curl-pipe-bash",
            "wget-pipe-shell",
          ].includes(f.rule),
        );

        const isNullSha = before === "0000000000000000000000000000000000000000";

        if (hasMalwareFindings && !isNullSha && modified.length > 0) {
          const coModifiedDockerfiles = modified.filter((f) => {
            const name = f.split("/").pop()?.toLowerCase() ?? "";
            return (
              (name.startsWith("dockerfile") || name.endsWith(".dockerfile")) &&
              !findings.some((finding) => finding.file === f)
            );
          });

          for (const df of coModifiedDockerfiles) {
            try {
              const { data: prevData } = await client.request(
                "GET /repos/{owner}/{repo}/contents/{path}",
                { owner, repo, path: df, ref: before },
              );
              if (
                !Array.isArray(prevData) &&
                (prevData as { type?: string }).type === "file" &&
                "content" in (prevData as Record<string, unknown>)
              ) {
                const prevContent = Buffer.from(
                  (prevData as { content: string }).content || "",
                  "base64",
                ).toString("utf8");
                revertFiles.set(df, prevContent);
                logger.info(
                  `[push] Dockerfile ${df} modified alongside malware — queuing for revert`,
                );
              }
            } catch {
              /* File didn't exist before this commit — skip */
            }
          }
        }
      }

      // Persist findings to MongoDB
      if (findings.length > 0) {
        await safeWrite(
          `FindingModel.insertMany:${owner}/${repo}:${headSha.slice(0, 7)}`,
          {
            type: "INSERT_FINDINGS",
            data: {
              findings: findings.map((f) => ({
                scanId: scanId.toHexString(),
                installationId,
                owner,
                repo,
                rule: f.rule,
                severity: f.severity,
                message: f.message,
                file: f.file,
                detectedAt: new Date().toISOString(),
              })),
            },
          },
        );
      }

      // Mark scan complete
      await safeWrite(`Scan.complete:${owner}/${repo}:${headSha.slice(0, 7)}`, {
        type: "COMPLETE_SCAN",
        data: {
          scanId: scanId.toHexString(),
          findingsCount: findings.length,
          filesScanned: filesScannedCount,
          durationMs: Date.now() - startTime,
          completedAt: new Date().toISOString(),
        },
      });

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
          const openIssue = await getOpenRepoGuardIssue(client, owner, repo);
          if (openIssue) {
            const newFindingsList = findings
              .map(
                (f) =>
                  `- **[${f.severity.toUpperCase()}]** \`${f.rule}\` in \`${f.file ?? "unknown"}\`: ${f.message}`,
              )
              .join("\n");

            try {
              await client.request(
                "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
                {
                  owner,
                  repo,
                  issue_number: openIssue.number,
                  body: [
                    `⚠️ **RepoGuard Alert:** Additional security findings detected in commit \`${headSha.slice(0, 7)}\` by ${pusher.name}:`,
                    "",
                    newFindingsList,
                  ].join("\n"),
                },
              );
              logger.info(
                `[push] Posted new findings comment on existing open issue #${openIssue.number}`,
              );
            } catch (err) {
              logger.warn(
                `[push] Could not comment on open issue #${openIssue.number}: ${String(err)}`,
              );
            }
          } else {
            const existingPR = await getExistingRepoGuardFixPR(
              client,
              owner,
              repo,
            );
            if (existingPR) {
              let shouldRecreate = payload.forced === true;
              if (!shouldRecreate) {
                try {
                  const { data: prDetails } = await client.request(
                    "GET /repos/{owner}/{repo}/pulls/{pull_number}",
                    { owner, repo, pull_number: existingPR.number },
                  );
                  const isConflicted =
                    (
                      prDetails as {
                        mergeable?: boolean;
                        mergeable_state?: string;
                      }
                    ).mergeable === false ||
                    (
                      prDetails as {
                        mergeable?: boolean;
                        mergeable_state?: string;
                      }
                    ).mergeable_state === "dirty";
                  if (isConflicted) {
                    shouldRecreate = true;
                  }
                } catch {
                  // ignore
                }
              }

              if (shouldRecreate) {
                logger.warn(
                  `[push] Fix PR #${existingPR.number} is stale, conflicted, or base branch was force-pushed — resetting PR and branch`,
                );
                try {
                  await client.request(
                    "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
                    {
                      owner,
                      repo,
                      issue_number: existingPR.number,
                      body: [
                        "⚠️ **RepoGuard Notice: Remediation PR Reset Due to Base Branch Update**",
                        "",
                        payload.forced
                          ? "The default branch was force-pushed, causing this automated remediation branch to be out of sync or conflicted."
                          : "This automated remediation branch has merge conflicts with the default branch.",
                        "",
                        "Closing this PR and regenerating a clean, conflict-free remediation PR against current HEAD.",
                      ].join("\n"),
                    },
                  );
                  await client.request(
                    "PATCH /repos/{owner}/{repo}/pulls/{pull_number}",
                    {
                      owner,
                      repo,
                      pull_number: existingPR.number,
                      state: "closed",
                    },
                  );
                  try {
                    await client.request(
                      "DELETE /repos/{owner}/{repo}/git/refs/{ref}",
                      {
                        owner,
                        repo,
                        ref: `heads/${existingPR.head.ref}`,
                      },
                    );
                  } catch {
                    // ignore
                  }
                } catch (err) {
                  logger.warn(
                    `[push] Could not cleanly close stale fix PR #${existingPR.number}: ${String(err)}`,
                  );
                }

                logger.warn(
                  `[push] ${findings.length} finding${findings.length > 1 ? "s" : ""} on default branch — opening fresh fix PR`,
                );
                await openFixPR(client, { owner, repo, findings, revertFiles });
              } else {
                logger.info(
                  `[push] Open RepoGuard fix PR #${existingPR.number} already exists and is healthy for ${owner}/${repo} — skipping`,
                );
              }
            } else {
              const issue = await getOpenRepoGuardIssue(client, owner, repo);
              if (issue) {
                logger.info(
                  `[push] Open RepoGuard issue #${issue.number} already exists for ${owner}/${repo} — skipping`,
                );
              } else {
                logger.warn(
                  `[push] ${findings.length} finding${findings.length > 1 ? "s" : ""} on default branch — opening fix PR`,
                );
                await openFixPR(client, { owner, repo, findings, revertFiles });
              }
            }
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
            const fullRepoFindings = await scanFullRepoForPush(
              client,
              owner,
              repo,
            );
            if (fullRepoFindings.length === 0) {
              await closeRepoGuardPRsAndIssues(client, owner, repo);
            } else {
              logger.info(
                `[push] Default branch still has ${fullRepoFindings.length} finding(s) requiring manual review — keeping open security issues active`,
              );
            }
          }
        }
      }
    } catch (err) {
      const durationMs = Date.now() - startTime;
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`[push] Error scanning ${owner}/${repo}: ${message}`);

      await Scan.updateOne(
        { _id: scanId },
        { $set: { status: "failed", completedAt: new Date(), durationMs } },
      ).catch(() => {});

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
