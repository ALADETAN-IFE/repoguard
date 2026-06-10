import type { Finding, OctokitClient } from "../types/index";
import logger from "../utils/logger";

interface OpenFixPROptions {
  owner: string;
  repo: string;
  findings: Finding[];
}

// ─── Permission error detection ───────────────────────────────────────────────

function isPermissionError(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return (
    message.includes("Resource not accessible by integration") ||
    message.includes("403") ||
    message.includes("Must have admin rights") ||
    message.includes("not have permission")
  );
}

export async function openFixPR(
  octokit: OctokitClient,
  { owner, repo, findings }: OpenFixPROptions,
): Promise<void> {
  try {
    // ── 1. Fetch each affected file and see if there are actual patches ──────────
    const affectedFiles = [
      ...new Set(findings.map((f) => f.file).filter(Boolean)),
    ] as string[];

    const filesToPatch: Array<{
      filePath: string;
      originalContent: string;
      patchedContent: string;
      fileSha: string;
      fileFindings: Finding[];
      patchedFindings: Finding[];
    }> = [];

    const allPatchedFindings: Finding[] = [];
    const allUnpatchedFindings: Finding[] = [];

    for (const filePath of affectedFiles) {
      try {
        // Fetch content from default branch
        const { data } = await octokit.request(
          "GET /repos/{owner}/{repo}/contents/{path}",
          { owner, repo, path: filePath },
        );

        if (
          Array.isArray(data) ||
          data.type !== "file" ||
          !("content" in data)
        )
          continue;

        const originalContent = Buffer.from(
          data.content || "",
          "base64",
        ).toString("utf8");
        const fileSha: string = data.sha;

        const fileFindings = findings.filter((f) => f.file === filePath);
        const { patchedContent, patchedFindings } = applyPatches(
          originalContent,
          fileFindings,
          filePath,
        );

        const fileUnpatched = fileFindings.filter(
          (f) => !patchedFindings.includes(f),
        );
        allPatchedFindings.push(...patchedFindings);
        allUnpatchedFindings.push(...fileUnpatched);

        if (patchedFindings.length > 0) {
          filesToPatch.push({
            filePath,
            originalContent,
            patchedContent,
            fileSha,
            fileFindings,
            patchedFindings,
          });
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        logger.warn(`[pr] Could not fetch/process ${filePath} for patching: ${message}`);
        const fileFindings = findings.filter((f) => f.file === filePath);
        allUnpatchedFindings.push(...fileFindings);
      }
    }

    // Add any findings without files to unpatched
    const findingsWithoutFiles = findings.filter((f) => !f.file);
    allUnpatchedFindings.push(...findingsWithoutFiles);

    // ── 2. Fall back to security issue if no files have functional changes ───────
    if (filesToPatch.length === 0) {
      logger.info(
        `[pr] No auto-patchable findings in ${owner}/${repo} — opening manual review security issue`,
      );
      await openSecurityIssue(octokit, { owner, repo, findings }, "manual_review_required");
      return;
    }

    // ── 3. Get default branch & base SHA for branch creation ────────────────────
    const { data: repoData } = await octokit.request(
      "GET /repos/{owner}/{repo}",
      { owner, repo },
    );
    const defaultBranch: string = repoData.default_branch || "main";

    const { data: refData } = await octokit.request(
      "GET /repos/{owner}/{repo}/git/ref/{ref}",
      { owner, repo, ref: `heads/${defaultBranch}` },
    );
    const baseSha: string = refData.object.sha;

    const branch = `repoguard/fixes-${Date.now()}`;

    // ── 4. Create the fix branch ────────────────────────────────────────────
    try {
      await octokit.request("POST /repos/{owner}/{repo}/git/refs", {
        owner,
        repo,
        ref: `refs/heads/${branch}`,
        sha: baseSha,
      });
    } catch (err) {
      if (isPermissionError(err)) {
        logger.warn(
          `[pr] No write access to ${owner}/${repo} — falling back to security issue`,
        );
        await openSecurityIssue(octokit, { owner, repo, findings }, "no_write_permission");
        return;
      }
      throw err;
    }

    logger.info(`[pr] Created branch ${branch} in ${owner}/${repo}`);

    // ── 5. Commit each modified file ─────────────────────────────────────────
    for (const file of filesToPatch) {
      // Only add a header comment block when there are findings that STILL need
      // manual review in this file. Fully auto-patched files don't get a header
      // — the inline replacement comments ("// REMOVED BY REPOGUARD: …") are
      // already self-documenting.
      const fileUnpatched = file.fileFindings.filter(
        (f) => !file.patchedFindings.includes(f),
      );
      const header = fileUnpatched.length > 0
        ? buildFileHeader(fileUnpatched, file.filePath)
        : "";
      const finalContent = header + file.patchedContent;

      await octokit.request("PUT /repos/{owner}/{repo}/contents/{path}", {
        owner,
        repo,
        path: file.filePath,
        message: `fix(security): remove malicious content from ${file.filePath}\n\nDetected by RepoGuard:\n${file.patchedFindings.map((f) => `- ${f.rule}: ${f.message}`).join("\n")}`,
        content: Buffer.from(finalContent).toString("base64"),
        sha: file.fileSha,
        branch,
      });

      logger.info(`[pr] Patched ${file.filePath}`);
    }

    // ── 6. Open the PR ──────────────────────────────────────────────────────
    const totalAllPatchedFindings = allPatchedFindings.length
    const { data: pr } = await octokit.request(
      "POST /repos/{owner}/{repo}/pulls",
      {
        owner,
        repo,
        title: `🔒 RepoGuard: Security fixes — ${totalAllPatchedFindings} issue${totalAllPatchedFindings > 1 ? "s" : ""} resolved`,
        body: buildPRBody(findings, allPatchedFindings, allUnpatchedFindings),
        head: branch,
        base: defaultBranch,
      },
    );

    logger.info(`[pr] Opened PR #${pr.number} in ${owner}/${repo}`);

    // ── 7. Request review from admins ───────────────────────────────────────
    const reviewers = await getAdminLogins(octokit, owner, repo);

    if (reviewers.length > 0) {
      await octokit.request(
        "POST /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers",
        { owner, repo, pull_number: pr.number, reviewers },
      );
      logger.info(`[pr] Requested review from: ${reviewers.join(", ")}`);
    }

    // ── 8. Add labels only if they already exist in the repo ───────────────
    await applyExistingLabels(octokit, owner, repo, pr.number, [
      "repoguard",
      "security",
      "automated-fix",
    ]);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`[pr] Failed to open fix PR in ${owner}/${repo}: ${message}`);
    throw err;
  }
}

// ─── Fallback: open a security issue when write access is unavailable ─────────
//
// Used when the GitHub App installation lacks Contents: write permission.
// The issue explains the findings and instructs the repo owner to either
// grant the permission or fix the issues manually.

async function openSecurityIssue(
  octokit: OctokitClient,
  { owner, repo, findings }: OpenFixPROptions,
  reason: "no_write_permission" | "manual_review_required" = "no_write_permission",
): Promise<void> {
  try {
    const criticalCount = findings.filter(
      (f) => f.severity === "critical",
    ).length;
    const highCount = findings.filter((f) => f.severity === "high").length;

    const findingsList = findings
      .map(
        (f) =>
          `- **[${f.severity.toUpperCase()}]** \`${f.rule}\` in \`${f.file ?? "unknown"}\`: ${f.message}`,
      )
      .join("\n");

    const issueTitle = reason === "no_write_permission"
      ? `⚠️ RepoGuard: Security issues found — manual review required (${findings.length} finding${findings.length !== 1 ? "s" : ""})`
      : `⚠️ RepoGuard: Security findings requiring manual review (${findings.length} finding${findings.length !== 1 ? "s" : ""})`;

    const description = reason === "no_write_permission"
      ? [
          "> RepoGuard detected security issues in this repository but could not open an automatic fix PR because the app does not have **Contents: write** permission.",
          "",
          "## How to enable automatic fixes",
          "",
          "Go to your GitHub App installation settings and grant **Repository contents: Read & write** permission. RepoGuard will then be able to open fix PRs automatically on future scans.",
        ]
      : [
          "> RepoGuard detected security issues in this repository that cannot be resolved automatically. Manual review and remediation are required.",
        ];

    const bodyParts = [
      "## ⚠️ RepoGuard Security Alert",
      "",
      ...description,
      "",
      "## Findings",
      "",
      `| 🔴 Critical | 🟠 High |`,
      `|-------------|---------|`,
      `| ${criticalCount} | ${highCount} |`,
      "",
      findingsList,
      "",
      "## What to do now",
      "",
      "1. **Rotate any exposed secrets immediately** — treat them as compromised",
      "2. **Remove or fix the flagged code** manually in the files listed above",
      "3. **Audit recent commits** to understand how this code was introduced",
      "",
      "---",
      "_Opened by RepoGuard · This issue will not auto-close — resolve it manually._",
    ];

    const { data: issue } = await octokit.request(
      "POST /repos/{owner}/{repo}/issues",
      {
        owner,
        repo,
        title: issueTitle,
        body: bodyParts.join("\n"),
      },
    );

    logger.info(
      `[pr] Opened security issue #${issue.number} in ${owner}/${repo} (${reason === "no_write_permission" ? "no write access" : "manual review"})`,
    );
  } catch (issueErr) {
    const message =
      issueErr instanceof Error ? issueErr.message : String(issueErr);
    logger.error(
      `[pr] Could not open security issue in ${owner}/{repo}: ${message}`,
    );
    // Do not re-throw — a failed issue is non-fatal; installation scan continues
  }
}

// ─── Patch strategies per rule ────────────────────────────────────────────────

export function applyPatches(
  content: string,
  findings: Finding[],
  filePath: string,
): { patchedContent: string; patchedFindings: Finding[] } {
  let patched = content;
  const patchedFindings: Finding[] = [];

  for (const finding of findings) {
    let nextPatched = patched;
    switch (finding.rule) {
      case "curl-pipe-bash":
      case "wget-pipe-shell":
        nextPatched = nextPatched.replace(
          /curl\s.+\|\s*(ba)?sh/g,
          "# REMOVED BY REPOGUARD: curl|bash remote execution",
        );
        nextPatched = nextPatched.replace(
          /wget\s.+\|\s*(ba)?sh/g,
          "# REMOVED BY REPOGUARD: wget|shell remote execution",
        );
        break;
      case "reverse-shell":
        nextPatched = nextPatched.replace(
          /bash\s+-i\s+>&\s+\/dev\/tcp[^\n]*/g,
          "# REMOVED BY REPOGUARD: reverse shell",
        );
        nextPatched = nextPatched.replace(
          /nc\s+-e\s+\/bin\/(ba)?sh[^\n]*/g,
          "# REMOVED BY REPOGUARD: netcat reverse shell",
        );
        break;
      case "obfuscated-base64":
        nextPatched = nextPatched.replace(
          /eval\s*\([^)]*fromCharCode[^)]*\)/g,
          "// REMOVED BY REPOGUARD: obfuscated eval",
        );
        nextPatched = nextPatched.replace(
          /eval\s*\(Buffer\.from\([^)]+\)\.toString\(\)\)/g,
          "// REMOVED BY REPOGUARD: base64 obfuscated payload",
        );
        break;
      case "obfuscated-malware-pattern":
        nextPatched = nextPatched.replace(
          /global\[['"]!['"]\][\s\S]*/g,
          "// REMOVED BY REPOGUARD: obfuscated malware payload",
        );
        nextPatched = nextPatched.replace(
          /var _\$_\w+\s*=\s*\(?function[\s\S]*/g,
          "// REMOVED BY REPOGUARD: obfuscated malware payload",
        );
        nextPatched = nextPatched.replace(
          /import\s*\{\s*createRequire\s*\}\s*from\s*['"]module['"];?/g,
          "// REMOVED BY REPOGUARD: createRequire import for malware",
        );
        nextPatched = nextPatched.replace(
          /const\s+require\s*=\s*createRequire\s*\(\s*import\.meta\.url\s*\);?/g,
          "// REMOVED BY REPOGUARD: require definition for malware",
        );
        break;
      case "suspicious-npm-postinstall":
        if (filePath.endsWith("package.json")) {
          try {
            const json = JSON.parse(nextPatched) as Record<string, unknown>;
            const scripts = json.scripts as Record<string, string> | undefined;
            if (scripts?.postinstall) {
              scripts.postinstall =
                "# REMOVED BY REPOGUARD: suspicious postinstall script";
              nextPatched = JSON.stringify(json, null, 2);
            }
          } catch {
            /* leave as-is */
          }
        }
        break;
      case "crypto-miner-keywords":
        nextPatched = nextPatched.replace(
          /xmrig[^\n]*/g,
          "# REMOVED BY REPOGUARD: crypto miner",
        );
        break;
      default:
        break;
    }

    if (nextPatched !== patched) {
      patched = nextPatched;
      patchedFindings.push(finding);
    }
  }

  return { patchedContent: patched, patchedFindings };
}

// ─── PR body builder ──────────────────────────────────────────────────────────

export function buildPRBody(
  findings: Finding[],
  patchedFindings: Finding[],
  unpatchedFindings: Finding[],
): string {
  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const mediumCount = findings.filter((f) => f.severity === "medium").length;

  const groupedByFile = findings.reduce<Record<string, Finding[]>>((acc, f) => {
    const key = f.file ?? "unknown";
    acc[key] = [...(acc[key] ?? []), f];
    return acc;
  }, {});

  const fileDetails = Object.entries(groupedByFile)
    .map(([file, fileFindings]) => {
      const rows = fileFindings
        .map((f) => {
          const isPatched = patchedFindings.includes(f);
          const status = isPatched ? "✅ Patched" : "⚠️ Requires Manual Review";
          return `| ${severityEmoji(f.severity)} ${f.severity} | \`${f.rule}\` | ${f.message} | ${status} |`;
        })
        .join("\n");
      return [
        `### 📄 \`${file}\``,
        "",
        "| Severity | Rule | Description | Status |",
        "|----------|------|-------------|--------|",
        rows,
        "",
      ].join("\n");
    })
    .join("\n");

  // Dynamically build "What was done" based on patched rules
  const PATCH_SUMMARIES: Record<string, string> = {
    "curl-pipe-bash": "Malicious shell execution patterns (`curl|bash`) replaced with comments",
    "wget-pipe-shell": "Malicious shell execution patterns (`wget|sh`) replaced with comments",
    "reverse-shell": "Reverse shell patterns removed",
    "obfuscated-base64": "Obfuscated `eval` payloads removed",
    "obfuscated-malware-pattern": "Obfuscated string array malware payloads and createRequire bypasses commented out",
    "suspicious-npm-postinstall": "Suspicious `postinstall` scripts in package.json neutralized",
    "crypto-miner-keywords": "Cryptocurrency miner indicators removed",
  };

  const uniquePatchedRules = [...new Set(patchedFindings.map((f) => f.rule))];
  const whatWasDone = uniquePatchedRules
    .map((rule) => `- ${PATCH_SUMMARIES[rule] ?? `Rule \`${rule}\` patched`}`)
    .join("\n");

  // Dynamically build "What requires manual review"
  const MANUAL_REVIEW_SUMMARIES: Record<string, string> = {
    "env-exfiltration": "**Env exfiltration** — audit any network calls that reference env variables",
    "hardcoded-secret": "**Hardcoded secrets** — rotate any exposed credentials immediately",
    "workflow-unpinned-action": "**Unpinned Actions** — pin third-party GitHub Actions to a full commit SHA",
    "workflow-curl-pipe-bash": "**Workflow curl|bash** — verify if curl/wget is required in workflow",
    "workflow-exfiltrate-secrets": "**Workflow secrets exfiltration** — check if secrets are sent externally",
    "workflow-suspicious-trigger": "**Workflow broad trigger** — restrict the triggers in workflow file",
  };

  const uniqueUnpatchedRules = [...new Set(unpatchedFindings.map((f) => f.rule))];
  const whatRequiresManualReview = uniqueUnpatchedRules
    .map((rule) => `- ${MANUAL_REVIEW_SUMMARIES[rule] ?? `Rule \`${rule}\` requires manual verification`}`)
    .join("\n") || "_None! All detected issues were automatically patched._";
  
  const totalPatchedFindings = patchedFindings.length;
  const totalUnpatchedFindings = unpatchedFindings.length;

  return [
    "## 🔒 RepoGuard Security Report",
    "",
    "> This PR was opened automatically by RepoGuard after scanning your codebase.",
    "> Each affected file has been patched where possible. Please review all changes carefully before merging.",
    "",
    "## Summary",
    "",
    "| 🔴 Critical | 🟠 High | 🟡 Medium |",
    "|-------------|---------|-----------|",
    `| ${criticalCount} | ${highCount} | ${mediumCount} |`,
    "",
    `* **Resolved (Patched):** ${totalPatchedFindings} finding${totalPatchedFindings > 1 ? "s" : ""}`,
    `* **Remaining (Requires Manual Review):** ${totalUnpatchedFindings} finding${totalUnpatchedFindings > 1 ? "s" : ""}`,
    "",
    "## Findings by File",
    "",
    fileDetails,
    "## What was done",
    "",
    whatWasDone,
    "",
    "## What requires manual review",
    "",
    whatRequiresManualReview,
    "",
    "## How the malware likely re-infected your repo",
    "",
    "1. **A compromised PAT or OAuth token** — revoke all personal access tokens and re-issue them",
    "2. **A malicious GitHub Actions workflow** — check `.github/workflows/` for unexpected changes",
    "3. **A compromised collaborator account** — audit your org's active sessions",
    "",
    "---",
    "_Opened by RepoGuard · Do not ignore this PR_",
  ].join("\n");
}

function buildFileHeader(findings: Finding[], filePath: string): string {
  return [
    `# ============================================================`,
    `# REPOGUARD — MANUAL REVIEW REQUIRED: ${filePath}`,
    `# Scanned: ${new Date().toISOString()}`,
    `# The following findings could NOT be automatically patched:`,
    ...findings.map(
      (f) => `#   [${f.severity.toUpperCase()}] ${f.rule}: ${f.message}`,
    ),
    `# ============================================================`,
    ``,
    ``,
  ].join("\n");
}

// ─── Get repo admin logins ────────────────────────────────────────────────────

async function getAdminLogins(
  octokit: OctokitClient,
  owner: string,
  repo: string,
): Promise<string[]> {
  try {
    const { data: collaborators } = await octokit.request(
      "GET /repos/{owner}/{repo}/collaborators",
      { owner, repo, permission: "admin" },
    );
    return (collaborators as Array<{ login: string; permissions?: { admin: boolean } }>)
      .filter((c) => c.permissions?.admin)
      .map((c) => c.login)
      .slice(0, 5);
  } catch {
    return [];
  }
}

// ─── Apply labels that already exist (never create) ──────────────────────────

async function applyExistingLabels(
  octokit: OctokitClient,
  owner: string,
  repo: string,
  issueNumber: number,
  desiredLabels: string[],
): Promise<void> {
  try {
    const { data: repoLabels } = await octokit.request(
      "GET /repos/{owner}/{repo}/labels",
      { owner, repo, per_page: 100 },
    );
    const existing = new Set(
      (repoLabels as Array<{ name: string }>).map((l) => l.name),
    );
    const toApply = desiredLabels.filter((l) => existing.has(l));
    if (toApply.length === 0) return;

    await octokit.request(
      "POST /repos/{owner}/{repo}/issues/{issue_number}/labels",
      { owner, repo, issue_number: issueNumber, labels: toApply },
    );
  } catch {
    // Labels are non-critical — skip silently
  }
}

function severityEmoji(severity: string): string {
  return (
    { critical: "🔴", high: "🟠", medium: "🟡", low: "🟢" }[severity] ?? "⚪"
  );
}

interface GitHubPullRequest {
  number: number;
  title: string;
  head: {
    ref: string;
  };
}

interface GitHubIssue {
  number: number;
  title: string;
  pull_request?: unknown;
  labels?: Array<{ name: string }>;
}

export async function closeRepoGuardPRsAndIssues(
  octokit: OctokitClient,
  owner: string,
  repo: string,
): Promise<void> {
  try {
    // 1. Fetch all open PRs
    const { data: pulls } = await octokit.request(
      "GET /repos/{owner}/{repo}/pulls",
      { owner, repo, state: "open", per_page: 100 },
    );

    const pullRequests = pulls as GitHubPullRequest[];

    for (const pr of pullRequests) {
      const isRepoGuardPR =
        pr.head.ref.startsWith("repoguard/fixes-") ||
        pr.title.includes("RepoGuard:");

      if (isRepoGuardPR) {
        logger.info(
          `[pr] Closing RepoGuard PR #${pr.number} in ${owner}/${repo}`,
        );

        await octokit.request(
          "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
          {
            owner,
            repo,
            issue_number: pr.number,
            body: "ℹ️ RepoGuard has detected that the security issues have been resolved or reverted. Closing this PR as it is no longer needed.",
          },
        );

        await octokit.request(
          "PATCH /repos/{owner}/{repo}/pulls/{pull_number}",
          {
            owner,
            repo,
            pull_number: pr.number,
            state: "closed",
          },
        );

        // Try to delete branch
        try {
          await octokit.request("DELETE /repos/{owner}/{repo}/git/refs/{ref}", {
            owner,
            repo,
            ref: `heads/${pr.head.ref}`,
          });
          logger.info(`[pr] Deleted branch ${pr.head.ref} in ${owner}/${repo}`);
        } catch (branchErr) {
          logger.warn(
            `[pr] Could not delete branch ${pr.head.ref}: ${String(branchErr)}`,
          );
        }
      }
    }

    // 2. Fetch all open issues
    const { data: issues } = await octokit.request(
      "GET /repos/{owner}/{repo}/issues",
      { owner, repo, state: "open", per_page: 100 },
    );

    const issueList = issues as GitHubIssue[];

    for (const issue of issueList) {
      if (issue.pull_request) continue;

      const isRepoGuardIssue =
        issue.title.includes("RepoGuard:") ||
        (issue.labels || []).some((l) => l.name === "repoguard");

      if (isRepoGuardIssue) {
        logger.info(
          `[pr] Closing RepoGuard Issue #${issue.number} in ${owner}/${repo}`,
        );

        await octokit.request(
          "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
          {
            owner,
            repo,
            issue_number: issue.number,
            body: "ℹ️ RepoGuard has detected that the security issues have been resolved or reverted. Closing this issue as it is no longer needed.",
          },
        );

        await octokit.request(
          "PATCH /repos/{owner}/{repo}/issues/{issue_number}",
          {
            owner,
            repo,
            issue_number: issue.number,
            state: "closed",
          },
        );
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      `[pr] Failed to close RepoGuard PRs/issues in ${owner}/${repo}: ${message}`,
    );
  }
}
