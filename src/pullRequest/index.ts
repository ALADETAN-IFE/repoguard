import type { Finding, OctokitClient } from "../types/index";
import logger from "../utils/logger";
import prettier from "prettier";
import {
  removeMalwareArtifactIgnoreLines,
  KNOWN_NPM_TYPOSQUATS,
  KNOWN_PYPI_TYPOSQUATS,
} from "@repoguard/scanner";

interface OpenFixPROptions {
  owner: string;
  repo: string;
  findings: Finding[];
}

export interface OpenFixPRResult {
  pr?: { number: number; html_url: string };
  issue?: { number: number; html_url: string };
}

// ─── Format content with Prettier ──────────────────────────────────────────────
async function formatContent(
  content: string,
  filePath: string,
): Promise<string> {
  try {
    const info = await prettier.getFileInfo(filePath);
    if (!info.inferredParser) return content;
    const formatted = await prettier.format(content, { filepath: filePath });
    return formatted.trimEnd() + "\n"; // trim AFTER prettier too
  } catch {
    return content.trimEnd() + "\n"; // trim even on prettier failure
  }
}

// ─── Check if file is effectively empty after patching ───────────────────────
// Runs prettier first so formatting normalises whitespace, then strips
// single-line comments (// … and # …) and block comments (/* … */) before
// checking whether any meaningful words remain.
async function isEffectivelyEmpty(
  content: string,
  filePath: string,
): Promise<boolean> {
  const formatted = await formatContent(content, filePath);

  const stripped = formatted
    // Remove block comments  /* … */
    .replace(/\/\*[\s\S]*?\*\//g, "")
    // Remove single-line // comments
    .replace(/\/\/[^\n]*/g, "")
    // Remove shell / Python # comments
    .replace(/#[^\n]*/g, "")
    // Collapse whitespace
    .replace(/\s+/g, " ")
    .trim();

  return stripped.length === 0;
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
): Promise<OpenFixPRResult | undefined> {
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
      shouldDelete: boolean;
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

        if (Array.isArray(data) || data.type !== "file" || !("content" in data))
          continue;

        const originalContent = Buffer.from(
          data.content || "",
          "base64",
        ).toString("utf8");
        const fileSha: string = data.sha;

        const fileFindings = findings.filter((f) => f.file === filePath);
        const { patchedContent, patchedFindings, shouldDelete } =
          await applyPatches(originalContent, fileFindings, filePath, octokit);

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
            shouldDelete,
          });
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        logger.warn(
          `[pr] Could not fetch/process ${filePath} for patching: ${message}`,
        );
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
      const issue = await openSecurityIssue(
        octokit,
        { owner, repo, findings },
        "manual_review_required",
      );
      return { issue };
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
        const issue = await openSecurityIssue(
          octokit,
          { owner, repo, findings },
          "no_write_permission",
        );
        return { issue };
      }
      throw err;
    }

    logger.info(`[pr] Created branch ${branch} in ${owner}/${repo}`);

    // ── 5. Commit each modified file (or delete if patching empties it) ─────
    for (const file of filesToPatch) {
      if (file.shouldDelete) {
        // The file would be left with nothing but REPOGUARD comment tombstones
        // after patching — delete it entirely instead.
        await octokit.request("DELETE /repos/{owner}/{repo}/contents/{path}", {
          owner,
          repo,
          path: file.filePath,
          message: `fix(security): delete fully-malicious file ${file.filePath}\n\nDetected by RepoGuard:\n${file.patchedFindings.map((f) => `- ${f.rule}: ${f.message}`).join("\n")}`,
          sha: file.fileSha,
          branch,
        });
        logger.info(
          `[pr] Deleted fully-malicious file ${file.filePath} (would have been empty after patching)`,
        );
        continue;
      }

      // Only add a header comment block when there are findings that STILL need
      // manual review in this file. Fully auto-patched files don't get a header
      // — the inline replacement comments ("// REMOVED BY REPOGUARD: …") are
      // already self-documenting.
      const fileUnpatched = file.fileFindings.filter(
        (f) => !file.patchedFindings.includes(f),
      );
      const header =
        fileUnpatched.length > 0
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
    const totalAllPatchedFindings = allPatchedFindings.length;
    const deletedFiles = filesToPatch
      .filter((f) => f.shouldDelete)
      .map((f) => f.filePath);
    const { data: pr } = await octokit.request(
      "POST /repos/{owner}/{repo}/pulls",
      {
        owner,
        repo,
        title: `🔒 RepoGuard: Security fixes — ${totalAllPatchedFindings} issue${totalAllPatchedFindings > 1 ? "s" : ""} resolved`,
        body: buildPRBody(
          findings,
          allPatchedFindings,
          allUnpatchedFindings,
          deletedFiles,
        ),
        head: branch,
        base: defaultBranch,
      },
    );

    // ✅ Post inline review comments (exclude deleted files)
    const patchedMap = new Map(
      filesToPatch
        .filter((f) => !f.shouldDelete)
        .map((f) => [f.filePath, f.patchedContent]),
    );
    await postReviewComments(
      octokit,
      owner,
      repo,
      pr.number,
      pr.head?.sha || baseSha,
      findings,
      patchedMap,
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

    // ── 8. Ensure labels exist with brand colours, then apply them ──────────
    await ensureAndApplyLabels(octokit, owner, repo, pr.number, [
      "repoguard",
      "security",
      "automated-fix",
    ]);

    return { pr: { number: pr.number, html_url: pr.html_url } };
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
  reason:
    | "no_write_permission"
    | "manual_review_required" = "no_write_permission",
): Promise<{ number: number; html_url: string } | undefined> {
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

    const issueTitle =
      reason === "no_write_permission"
        ? `⚠️ RepoGuard: Security issues found — manual review required (${findings.length} finding${findings.length !== 1 ? "s" : ""})`
        : `⚠️ RepoGuard: Security findings requiring manual review (${findings.length} finding${findings.length !== 1 ? "s" : ""})`;

    const description =
      reason === "no_write_permission"
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
      "## ⚡ Trigger Automated Fix PR",
      "",
      "Comment `/fix` or `/repoguard fix` on this issue to trigger an automated Fix PR attempt.",
      "",
      "---",
      "_Opened by RepoGuard · Reply with `/fix` to generate an automated PR fix._",
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

    return { number: issue.number, html_url: issue.html_url };
  } catch (issueErr) {
    const message =
      issueErr instanceof Error ? issueErr.message : String(issueErr);
    logger.error(
      `[pr] Could not open security issue in ${owner}/{repo}: ${message}`,
    );
    // Do not re-throw — a failed issue is non-fatal; installation scan continues
  }
}

export async function applyPatches(
  content: string,
  findings: Finding[],
  filePath: string,
  octokit?: OctokitClient,
): Promise<{
  patchedContent: string;
  patchedFindings: Finding[];
  shouldDelete: boolean;
}> {
  const baseName = filePath.split("/").pop()?.toLowerCase() ?? "";

  // Safe template/example env files that should never be auto-deleted
  const SAFE_ENV_SUFFIXES = [".example", ".sample", ".template", ".test"];
  const isSafeEnvFile = SAFE_ENV_SUFFIXES.some((suffix) =>
    baseName.endsWith(suffix),
  );

  const isEnvFile =
    !isSafeEnvFile &&
    (baseName === ".env" ||
      baseName.startsWith(".env.") ||
      findings.some((f) => f.rule === "committed-env-file"));

  if (isEnvFile) {
    logger.info(
      `[pr] Committed env file ${filePath} detected — flagging for auto-deletion`,
    );
    const envFindings = findings.filter(
      (f) =>
        f.rule === "committed-env-file" ||
        baseName === ".env" ||
        baseName.startsWith(".env."),
    );
    return {
      patchedContent: "",
      patchedFindings: envFindings.length > 0 ? envFindings : findings,
      shouldDelete: true,
    };
  }

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
          /\n?import\s*\{\s*createRequire\s*\}\s*from\s*['"]module['"];?/g,
          "// REMOVED BY REPOGUARD: createRequire import for malware",
        );
        nextPatched = nextPatched.replace(
          /\n?const\s+require\s*=\s*createRequire\s*\(\s*import\.meta\.url\s*\);?/g,
          "// REMOVED BY REPOGUARD: require definition for malware",
        );
        nextPatched = nextPatched.replace(
          /(?:;\s*|\s+)global(?:\.(?:i|r|m)|\[['"](?:!|i|r|m)['"]\]|\[_\$_\w+\[\d+\]\])\s*=[\s\S]*/g,
          ";\n// REMOVED BY REPOGUARD: obfuscated malware payload",
        );
        nextPatched = nextPatched.replace(
          /\n?global\[['"]!['"\]][\s\S]*/g,
          "\n// REMOVED BY REPOGUARD: obfuscated malware payload",
        );
        nextPatched = nextPatched.replace(
          /\n?global\[_\$_\w+\[\d+\]\]\s*=\s*require[\s\S]*/g,
          "\n// REMOVED BY REPOGUARD: obfuscated malware payload",
        );
        nextPatched = nextPatched.replace(
          /\n?var _\$_\w+\s*=\s*\(?function[\s\S]*/g,
          "\n// REMOVED BY REPOGUARD: obfuscated malware payload",
        );

        // Clean up leftover blank lines
        nextPatched = nextPatched.replace(/\n{3,}/g, "\n\n").trimEnd() + "\n";
        break;
      case "js-obfuscated-charcode":
        nextPatched = nextPatched.replace(
          /String\.fromCharCode\s*\([^)]+\)/g,
          "/* REMOVED BY REPOGUARD: obfuscated charCode payload */ ''",
        );
        break;
      case "js-obfuscated-constructors":
        nextPatched = nextPatched.replace(
          /\[\s*['"]filter['"]\s*\]\s*\[\s*['"]constructor['"]\s*\]/g,
          "/* REMOVED BY REPOGUARD: obfuscated constructor payload */",
        );
        nextPatched = nextPatched.replace(
          /constructor\s*\(\s*['"]eval['"]\s*\)/g,
          "/* REMOVED BY REPOGUARD: obfuscated constructor payload */",
        );
        nextPatched = nextPatched.replace(
          /Reflect\.apply[^\n]*/g,
          "// REMOVED BY REPOGUARD: Reflect.apply abuse",
        );
        break;
      case "js-obfuscated-hex":
        nextPatched = nextPatched.replace(
          /(\\x[0-9a-fA-F]{2}){8,}/g,
          "/* REMOVED BY REPOGUARD: obfuscated hex payload */ ''",
        );
        break;
      case "python-exec-compile":
        nextPatched = nextPatched.replace(
          /exec\s*\(\s*(compile|__import__)\s*\([^\n]*/g,
          "# REMOVED BY REPOGUARD: python exec compile payload",
        );
        break;
      case "python-obfuscated-base64-exec":
        nextPatched = nextPatched.replace(
          /exec\s*\(\s*(base64\.b64decode|__import__\s*\(\s*['"]base64['"]\s*\)\.b64decode)[^\n]*/g,
          "# REMOVED BY REPOGUARD: python base64 exec payload",
        );
        break;
      case "python-subprocess-network":
        nextPatched = nextPatched.replace(
          /subprocess\.(run|call|Popen|check_output)\s*\([^)]*(curl|wget)[^)]*\)/g,
          "# REMOVED BY REPOGUARD: python subprocess remote execution",
        );
        break;
      case "powershell-encoded-command":
        nextPatched = nextPatched.replace(
          /powershell.*-[Ee](nc(odedCommand)?)?\s+[A-Za-z0-9+/=]+/g,
          "# REMOVED BY REPOGUARD: powershell encoded command",
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
      case "suspicious-gitignore-entry": {
        const name = filePath.split("/").pop()?.toLowerCase() ?? "";
        if (name === ".gitignore" || name === ".repoguardignore") {
          nextPatched = removeMalwareArtifactIgnoreLines(nextPatched);
        }
        break;
      }
      case "npm-typosquatted-package":
        if (filePath.endsWith("package.json")) {
          try {
            const pkg = JSON.parse(nextPatched) as Record<string, unknown>;
            let changed = false;
            for (const section of [
              "dependencies",
              "devDependencies",
            ] as const) {
              const deps = pkg[section] as Record<string, string> | undefined;
              if (!deps) continue;
              for (const [name, version] of Object.entries(deps)) {
                const legitimate = KNOWN_NPM_TYPOSQUATS[name];
                if (legitimate) {
                  // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
                  delete deps[name];
                  deps[legitimate] = version;
                  changed = true;
                  logger.info(
                    `[pr] Replaced typosquatted npm package '${name}' → '${legitimate}'`,
                  );
                }
              }
            }
            if (changed) nextPatched = JSON.stringify(pkg, null, 2);
          } catch {
            /* leave as-is */
          }
        }
        break;
      case "pypi-typosquatted-package":
        if (
          filePath.endsWith("requirements.txt") ||
          filePath.endsWith("requirements-dev.txt") ||
          filePath.endsWith("requirements-test.txt")
        ) {
          const lines = nextPatched.split("\n");
          const replaced = lines.map((line) => {
            const stripped = line
              .trim()
              .toLowerCase()
              .split(/[=><!@[]/)[0]
              .trim();
            const legitimate = KNOWN_PYPI_TYPOSQUATS[stripped];
            if (legitimate) {
              const suffix = line.trim().slice(stripped.length);
              logger.info(
                `[pr] Replaced typosquatted PyPI package '${stripped}' → '${legitimate}'`,
              );
              return legitimate + suffix;
            }
            return line;
          });
          nextPatched = replaced.join("\n");
        }
        break;
      case "workflow-unpinned-action":
        if (
          filePath.startsWith(".github/workflows/") &&
          (filePath.endsWith(".yml") || filePath.endsWith(".yaml"))
        ) {
          const unpinnedRegex =
            /uses:\s+([a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+)@(?![\da-f]{40})([^\s#]+)/g;
          let match: RegExpExecArray | null;
          let updated = nextPatched;
          while ((match = unpinnedRegex.exec(nextPatched)) !== null) {
            const fullMatch = match[0];
            const actionRepo = match[1];
            const tag = match[2];
            let resolvedSha: string | null = null;

            if (octokit) {
              try {
                const [actionOwner, actionName] = actionRepo.split("/");
                const { data: commitData } = await octokit.request(
                  "GET /repos/{owner}/{repo}/commits/{ref}",
                  { owner: actionOwner, repo: actionName, ref: tag },
                );
                if (commitData?.sha && typeof commitData.sha === "string") {
                  resolvedSha = commitData.sha;
                }
              } catch {
                /* fallback if tag resolution fails */
              }
            }

            if (resolvedSha) {
              updated = updated.replace(
                fullMatch,
                `uses: ${actionRepo}@${resolvedSha} # ${tag}`,
              );
            } else {
              updated = updated.replace(
                fullMatch,
                `uses: ${actionRepo}@${tag} # REPOGUARD: PIN TO COMMIT SHA`,
              );
            }
          }
          nextPatched = updated;
        }
        break;
      default:
        break;
    }

    if (nextPatched !== patched) {
      patched = nextPatched;
      patchedFindings.push(finding);
    }
  }

  if (patchedFindings.length > 0) {
    // ── Empty-file guard ────────────────────────────────────────────────────
    // Run prettier on the candidate patched content, then check whether
    // any meaningful (non-comment, non-whitespace) content remains.
    // If the file would be left with only REPOGUARD comment tombstones,
    // delete it entirely rather than committing a comment-only file.
    const wouldBeEmpty = await isEffectivelyEmpty(patched, filePath);
    if (wouldBeEmpty) {
      logger.info(
        `[pr] Patching ${filePath} would leave it empty — flagging for deletion`,
      );
      return { patchedContent: patched, patchedFindings, shouldDelete: true };
    }

    patched = await formatContent(patched, filePath);
  }

  return { patchedContent: patched, patchedFindings, shouldDelete: false };
}

// ─── PR body builder ──────────────────────────────────────────────────────────

export function buildPRBody(
  findings: Finding[],
  patchedFindings: Finding[],
  unpatchedFindings: Finding[],
  deletedFiles: string[] = [],
): string {
  const criticalCount = findings.filter(
    (f) => f.severity === "critical",
  ).length;
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
          const isDeleted = deletedFiles.includes(file);
          const status = isDeleted
            ? "🗑️ Deleted"
            : isPatched
              ? "✅ Patched"
              : "⚠️ Requires Manual Review";
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
    "curl-pipe-bash":
      "Malicious shell execution patterns (`curl|bash`) replaced with comments",
    "wget-pipe-shell":
      "Malicious shell execution patterns (`wget|sh`) replaced with comments",
    "reverse-shell": "Reverse shell patterns removed",
    "obfuscated-base64": "Obfuscated `eval` payloads removed",
    "obfuscated-malware-pattern":
      "Obfuscated string array malware payloads and createRequire bypasses commented out",
    "js-obfuscated-charcode":
      "Obfuscated charCode array dynamic execution payloads removed",
    "js-obfuscated-constructors":
      "Obfuscated constructor dynamic execution payloads removed",
    "js-obfuscated-hex": "Obfuscated hex escape payload strings removed",
    "python-exec-compile":
      "Python `exec(compile())` dynamic execution payloads removed",
    "python-obfuscated-base64-exec":
      "Python base64-decoded dynamic execution payloads removed",
    "python-subprocess-network":
      "Python subprocess remote execution calls removed",
    "powershell-encoded-command": "Encoded PowerShell commands removed",
    "suspicious-npm-postinstall":
      "Suspicious `postinstall` scripts in package.json neutralized",
    "crypto-miner-keywords": "Cryptocurrency miner indicators removed",
    "suspicious-gitignore-entry":
      "Known malware artifact entries removed from ignore file",
    "committed-env-file":
      "Committed environment configuration file(s) (`.env`) auto-deleted from repository",
    "npm-typosquatted-package":
      "Typosquatted npm package name(s) replaced with legitimate counterparts in `package.json`",
    "pypi-typosquatted-package":
      "Typosquatted PyPI package name(s) replaced with legitimate counterparts in `requirements.txt`",
    "workflow-unpinned-action":
      "Unpinned GitHub Action(s) resolved and pinned to immutable commit SHA with version tag comment",
  };

  const uniquePatchedRules = [...new Set(patchedFindings.map((f) => f.rule))];
  const whatWasDoneList = uniquePatchedRules.map(
    (rule) => `- ${PATCH_SUMMARIES[rule] ?? `Rule \`${rule}\` patched`}`,
  );

  if (deletedFiles.length > 0) {
    whatWasDoneList.push(
      `- Fully-malicious files deleted: ${deletedFiles.map((f) => `\`${f}\``).join(", ")}`,
    );
  }
  const whatWasDone = whatWasDoneList.join("\n") || "_None_";

  // Dynamically build "What requires manual review"
  const MANUAL_REVIEW_SUMMARIES: Record<string, string> = {
    "env-exfiltration":
      "**Env exfiltration** — audit any network calls that reference env variables",
    "hardcoded-secret":
      "**Hardcoded secrets** — rotate any exposed credentials immediately",
    "workflow-unpinned-action":
      "**Unpinned Actions** — pin third-party GitHub Actions to a full commit SHA",
    "workflow-curl-pipe-bash":
      "**Workflow curl|bash** — verify if curl/wget is required in workflow",
    "workflow-exfiltrate-secrets":
      "**Workflow secrets exfiltration** — check if secrets are sent externally",
    "workflow-suspicious-trigger":
      "**Workflow broad trigger** — restrict the triggers in workflow file",
  };

  const uniqueUnpatchedRules = [
    ...new Set(unpatchedFindings.map((f) => f.rule)),
  ];
  const whatRequiresManualReview = uniqueUnpatchedRules
    .map(
      (rule) =>
        `- ${MANUAL_REVIEW_SUMMARIES[rule] ?? `Rule \`${rule}\` requires manual verification`}`,
    )
    .join("\n");

  const totalPatchedFindings = patchedFindings.length;
  const totalUnpatchedFindings = unpatchedFindings.length;

  const bodyParts = [
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
  ];

  if (totalUnpatchedFindings > 0) {
    bodyParts.push(
      "",
      "## What requires manual review",
      "",
      whatRequiresManualReview,
    );
  }

  bodyParts.push(
    "",
    "## How the malware likely re-infected your repo",
    "",
    "1. **A compromised PAT or OAuth token** — revoke all personal access tokens and re-issue them",
    "2. **A malicious GitHub Actions workflow** — check `.github/workflows/` for unexpected changes",
    "3. **A compromised collaborator account** — audit your org's active sessions",
    "",
    "---",
    "_Opened by RepoGuard · Do not ignore this PR_",
  );

  return bodyParts.join("\n");
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
    return (
      collaborators as Array<{
        login: string;
        permissions?: { admin: boolean };
      }>
    )
      .filter((c) => c.permissions?.admin)
      .map((c) => c.login)
      .slice(0, 5);
  } catch {
    return [];
  }
}

// ─── Label management: ensure brand-coloured labels exist, then apply ────────

// Label definitions: name → { color (hex, no #), description }
const LABEL_DEFS: Record<string, { color: string; description: string }> = {
  repoguard: {
    color: "2080e8", // Brand blue — matches repoguard-site --color-blue-accent
    description: "Opened or flagged by RepoGuard security bot",
  },
  security: {
    color: "b60205", // Deep red — GitHub's standard security label colour
    description: "Security vulnerability or finding",
  },
  "automated-fix": {
    color: "0075ca", // GitHub's default "documentation" blue — neutral but readable
    description: "Fix applied automatically by RepoGuard",
  },
};

/**
 * Ensures each desired label exists in the repo (creating it with brand colours
 * if absent), then applies all of them to the given issue / PR.
 */
async function ensureAndApplyLabels(
  octokit: OctokitClient,
  owner: string,
  repo: string,
  issueNumber: number,
  desiredLabels: string[],
): Promise<void> {
  try {
    // Fetch existing labels
    const { data: repoLabels } = await octokit.request(
      "GET /repos/{owner}/{repo}/labels",
      { owner, repo, per_page: 100 },
    );
    const existingMap = new Map(
      (repoLabels as Array<{ name: string; color: string }>).map((l) => [
        l.name,
        l.color,
      ]),
    );

    // Create or update each desired label
    for (const name of desiredLabels) {
      const def = LABEL_DEFS[name];
      if (!def) continue; // unknown label — skip

      if (!existingMap.has(name)) {
        // Create brand-new label
        await octokit.request("POST /repos/{owner}/{repo}/labels", {
          owner,
          repo,
          name,
          color: def.color,
          description: def.description,
        });
      } else if (existingMap.get(name) !== def.color) {
        // Update colour if it drifted from the brand colour
        await octokit.request("PATCH /repos/{owner}/{repo}/labels/{name}", {
          owner,
          repo,
          name,
          color: def.color,
          description: def.description,
        });
      }
    }

    // Apply all labels to the issue / PR
    await octokit.request(
      "POST /repos/{owner}/{repo}/issues/{issue_number}/labels",
      { owner, repo, issue_number: issueNumber, labels: desiredLabels },
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
  html_url?: string;
  head: {
    ref: string;
  };
}

interface GitHubIssue {
  number: number;
  title: string;
  html_url?: string;
  pull_request?: unknown;
  labels?: Array<{ name: string }>;
}

export async function getOpenRepoGuardIssue(
  octokit: OctokitClient,
  owner: string,
  repo: string,
): Promise<{ number: number; html_url: string } | undefined> {
  try {
    const { data: issues } = await octokit.request(
      "GET /repos/{owner}/{repo}/issues",
      { owner, repo, state: "open", per_page: 100 },
    );

    const issue = (issues as GitHubIssue[]).find(
      (i) =>
        !i.pull_request &&
        (i.title.toLowerCase().includes("repoguard:") ||
          (i.labels || []).some((l) => l.name === "repoguard")),
    );

    if (issue) {
      return {
        number: issue.number,
        html_url:
          issue.html_url ||
          `https://github.com/${owner}/${repo}/issues/${issue.number}`,
      };
    }
  } catch {
    /* ignore */
  }
  return undefined;
}

export async function hasOpenRepoGuardFixPR(
  octokit: OctokitClient,
  owner: string,
  repo: string,
): Promise<boolean> {
  const { data: pulls } = await octokit.request(
    "GET /repos/{owner}/{repo}/pulls",
    { owner, repo, state: "open", per_page: 100 },
  );

  const hasPR = (pulls as GitHubPullRequest[]).some(
    (pr) =>
      pr.head.ref.startsWith("repoguard/fixes-") ||
      pr.title.includes("RepoGuard:"),
  );

  if (hasPR) return true;

  const issue = await getOpenRepoGuardIssue(octokit, owner, repo);
  return issue !== undefined;
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

interface ReviewComment {
  path: string;
  line: number;
  side: string;
  body: string;
}

// ─── Rule-based fix suggestions ──────────────────────────────────────────────
const RULE_SUGGESTIONS: Record<string, (line: string) => string> = {
  "obfuscated-malware-pattern": () =>
    "// REMOVED BY REPOGUARD: obfuscated malware payload",
  "curl-pipe-bash": (line) =>
    line.replace(
      /curl\s.+\|\s*(ba)?sh/g,
      "# REMOVED BY REPOGUARD: curl|bash remote execution",
    ),
  "wget-pipe-shell": (line) =>
    line.replace(
      /wget\s.+\|\s*(ba)?sh/g,
      "# REMOVED BY REPOGUARD: wget|shell remote execution",
    ),
  "reverse-shell": (line) =>
    line
      .replace(
        /bash\s+-i\s+>&\s+\/dev\/tcp[^\n]*/g,
        "# REMOVED BY REPOGUARD: reverse shell",
      )
      .replace(
        /nc\s+-e\s+\/bin\/(ba)?sh[^\n]*/g,
        "# REMOVED BY REPOGUARD: netcat reverse shell",
      ),
  "crypto-miner-keywords": (line) =>
    line.replace(/xmrig[^\n]*/g, "# REMOVED BY REPOGUARD: crypto miner"),
  "obfuscated-base64": (line) =>
    line.replace(
      /eval\s*\([^)]*fromCharCode[^)]*\)/g,
      "// REMOVED BY REPOGUARD: obfuscated eval",
    ),
};

export async function postReviewComments(
  octokit: OctokitClient,
  owner: string,
  repo: string,
  prNumber: number,
  headSha: string,
  findings: Finding[],
  patchedContent: Map<string, string>, // filePath → patched content
): Promise<void> {
  const comments: ReviewComment[] = [];

  for (const finding of findings) {
    if (!finding.file || !finding.line) continue;

    // Skip if the file was deleted (not present in patchedContent map)
    if (!patchedContent.has(finding.file)) continue;

    const patched = patchedContent.get(finding.file);
    const originalLine = patched
      ? (patched.split("\n")[finding.line - 1] ?? "")
      : "";

    // Try rule-based suggestion first, then patched content, then manual review
    const suggestionFn = RULE_SUGGESTIONS[finding.rule];
    const suggestedLine = suggestionFn
      ? suggestionFn(originalLine)
      : patched
        ? getFixedLine(patched, finding.line)
        : null;

    const body = suggestedLine
      ? [
          `**RepoGuard** detected \`${finding.rule}\` (${finding.severity})`,
          `> ${finding.message}`,
          ``,
          `<details>`,
          `<summary>📋 Committable suggestion</summary>`,
          ``,
          `> ‼️ [!IMPORTANT]`,
          `> Carefully review the code before committing. Ensure that it accurately replaces the highlighted code, contains no missing lines, and has no issues with indentation. Thoroughly test & benchmark the code to ensure it meets the requirements.`,
          ``,
          `\`\`\`suggestion`,
          suggestedLine,
          `\`\`\``,
          `</details>`,
          `<details>`,
          `<summary>💡 Suggested commit message:</summary>`,
          ``,
          `>  \`fix(security): remove ${finding.rule} from ${finding.file ?? "file"}\``,
          `</details>`,
        ].join("\n")
      : [
          `**RepoGuard** detected \`${finding.rule}\` (${finding.severity})`,
          `> ${finding.message}`,
          ``,
          `<details>`,
          `<summary>⚠️ Manual review required</summary>`,
          ``,
          `This finding cannot be automatically fixed. Please review and remediate manually.`,
          `</details>`,
        ].join("\n");

    comments.push({
      path: finding.file,
      line: finding.line,
      side: "RIGHT",
      body,
    });
  }

  if (comments.length === 0) return;

  try {
    await octokit.request(
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews",
      {
        owner,
        repo,
        pull_number: prNumber,
        commit_id: headSha,
        event: "COMMENT",
        comments,
      },
    );
    logger.info(
      `[pr] Posted ${comments.length} inline review comment(s) on PR #${prNumber}`,
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`[pr] Failed to post inline review comments: ${message}. Falling back to PR comment...`);
    try {
      const summaryText = comments
        .map((c) => `### 📄 \`${c.path}\` (line ${c.line})\n\n${c.body}`)
        .join("\n\n---\n\n");
      await octokit.request(
        "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
        {
          owner,
          repo,
          issue_number: prNumber,
          body: `## 🛡️ RepoGuard Security Findings & Remediation\n\n${summaryText}`,
        },
      );
      logger.info(`[pr] Fallback: Posted security findings comment on PR #${prNumber}`);
    } catch (fallbackErr) {
      const fallbackMsg = fallbackErr instanceof Error ? fallbackErr.message : String(fallbackErr);
      logger.error(`[pr] Failed fallback comment on PR #${prNumber}: ${fallbackMsg}`);
    }
  }
}

function getFixedLine(patchedContent: string, lineNumber: number): string {
  const lines = patchedContent.split("\n");
  return lines[lineNumber - 1] ?? "";
}
