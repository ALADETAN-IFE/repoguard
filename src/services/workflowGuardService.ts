import yaml from "js-yaml";
import logger from "../utils/logger";
import { Installation } from "../models";
import type { OctokitClient } from "../types";

export interface SuggestActionResult {
  owner: string;
  repo: string;
  prNumber?: number;
  prUrl?: string;
  status:
    | "created"
    | "updated"
    | "already_configured"
    | "pr_already_open"
    | "no_repos"
    | "error";
  message?: string;
}

export const REPO_GUARD_ACTION_NAME = ["ALADETAN-IFE", "repoguard-action"].join(
  "/",
);
export const REPO_GUARD_ACTION_TAG = "v1";
export const FALLBACK_ACTION_SHA = "1f0c45f68e3b43f3d4fa14029868574cac0a08ad";

let cachedActionSha: { sha: string; expiresAt: number } | null = null;

/**
 * Resolves the latest full commit SHA for the RepoGuard GitHub Action tag (v1),
 * caching the result in memory for 10 minutes to minimize API calls.
 */
export async function resolveActionSha(
  octokit?: OctokitClient,
): Promise<string> {
  const now = Date.now();
  if (cachedActionSha && cachedActionSha.expiresAt > now) {
    return cachedActionSha.sha;
  }

  if (octokit) {
    try {
      const [actionOwner, actionName] = REPO_GUARD_ACTION_NAME.split("/");
      const { data: commitData } = await octokit.request(
        "GET /repos/{owner}/{repo}/commits/{ref}",
        { owner: actionOwner, repo: actionName, ref: REPO_GUARD_ACTION_TAG },
      );
      if (
        commitData?.sha &&
        typeof commitData.sha === "string" &&
        /^[0-9a-f]{40}$/i.test(commitData.sha)
      ) {
        cachedActionSha = {
          sha: commitData.sha,
          expiresAt: now + 10 * 60 * 1000,
        };
        return commitData.sha;
      }
    } catch (err) {
      logger.warn(
        `[workflow-guard] Failed to fetch commit SHA for ${REPO_GUARD_ACTION_NAME}@${REPO_GUARD_ACTION_TAG}: ${err instanceof Error ? err.message : String(err)}. Using fallback.`,
      );
    }
  }

  return FALLBACK_ACTION_SHA;
}

/**
 * Generates an immutable, SHA-pinned action 'uses' string with tag comment reference.
 * e.g. ALADETAN-IFE/repoguard-action@1f0c45f68e3b43f3d4fa14029868574cac0a08ad # v1
 */
export function buildActionUsesString(
  sha: string = FALLBACK_ACTION_SHA,
): string {
  return `${REPO_GUARD_ACTION_NAME}@${sha} # ${REPO_GUARD_ACTION_TAG}`;
}

export const STANDALONE_WORKFLOW_PATH = ".github/workflows/repoguard.yml";

export function buildStandaloneWorkflowContent(actionUses?: string): string {
  const usesString = actionUses || buildActionUsesString(FALLBACK_ACTION_SHA);
  return `# RepoGuard Pre-Execution Security Gate
# Automatically scans code, dependencies, and PR diffs for malware, backdoors, and secrets
# before arbitrary build or test scripts are executed in CI.
# https://github.com/marketplace/actions/repoguard-security-scan

name: "RepoGuard Security Gate"

on:
  push:
    branches: ["main", "master"]
  pull_request:
    branches: ["main", "master"]

jobs:
  repoguard-security-scan:
    name: RepoGuard Pre-Execution Security Gate
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Checkout Code
        uses: actions/checkout@v6

      - name: Run RepoGuard Security Check
        uses: ${usesString}
        with:
          minimum-severity: "medium"
          fail-on: "high"
`;
}

export const STANDALONE_WORKFLOW_CONTENT = buildStandaloneWorkflowContent();

/**
 * Checks if a workflow file already contains RepoGuard and, if not,
 * surgically injects the repoguard-security-scan job and wires it into entry-point jobs via 'needs',
 * preserving 100% of existing comments, formatting, and triggers (e.g. workflow_dispatch).
 */
export function injectRepoGuardIntoWorkflow(
  yamlContent: string,
  actionUses?: string,
): {
  modified: boolean;
  alreadyConfigured: boolean;
  newContent?: string;
  reason?: string;
} {
  const usesString = actionUses || buildActionUsesString(FALLBACK_ACTION_SHA);

  // 1. Detect if RepoGuard is already configured
  const actionRegex =
    /uses:\s+ALADETAN-IFE\/repoguard-action@[^\s#]+(\s*#[^\n]*)?/;

  if (
    yamlContent.includes(REPO_GUARD_ACTION_NAME) ||
    yamlContent.includes("@repoguard/scanner") ||
    yamlContent.includes("repoguard-security-scan")
  ) {
    if (yamlContent.includes(`uses: ${usesString}`)) {
      return {
        modified: false,
        alreadyConfigured: true,
        reason:
          "Workflow already contains RepoGuard Action pinned to the latest commit SHA.",
      };
    }

    if (actionRegex.test(yamlContent)) {
      // Surgically update to the latest pinned SHA without altering any other lines
      const updated = yamlContent.replace(
        /uses:\s+ALADETAN-IFE\/repoguard-action@[^\s#]+(\s*#[^\n]*)?/g,
        `uses: ${usesString}`,
      );
      return {
        modified: true,
        alreadyConfigured: false,
        newContent: updated,
        reason: "Updated RepoGuard Action to the latest pinned commit SHA.",
      };
    }

    if (yamlContent.includes("@repoguard/scanner")) {
      return {
        modified: false,
        alreadyConfigured: true,
        reason: "Workflow already contains RepoGuard scanner.",
      };
    }
  }

  let doc: Record<string, unknown>;
  try {
    const loaded = yaml.load(yamlContent);
    if (!loaded || typeof loaded !== "object" || Array.isArray(loaded)) {
      return {
        modified: false,
        alreadyConfigured: false,
        reason: "Invalid workflow YAML format.",
      };
    }
    doc = loaded as Record<string, unknown>;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      modified: false,
      alreadyConfigured: false,
      reason: `Failed to parse YAML: ${msg}`,
    };
  }

  if (!doc.jobs || typeof doc.jobs !== "object" || Array.isArray(doc.jobs)) {
    return {
      modified: false,
      alreadyConfigured: false,
      reason: "Workflow has no jobs defined.",
    };
  }

  const jobs = doc.jobs as Record<string, Record<string, unknown>>;
  const jobEntries = Object.entries(jobs);

  if (jobEntries.length === 0) {
    return {
      modified: false,
      alreadyConfigured: false,
      reason: "Workflow contains 0 jobs.",
    };
  }

  const gateJobId = "repoguard-security-scan";

  // Find all root entry-point jobs dynamically (any job without 'needs' or with empty 'needs')
  const rootJobNames: string[] = [];
  for (const [id, jobDef] of jobEntries) {
    if (id === gateJobId || !jobDef || typeof jobDef !== "object") continue;

    if (
      !jobDef.needs ||
      (Array.isArray(jobDef.needs) && jobDef.needs.length === 0)
    ) {
      rootJobNames.push(id);
    }
  }

  if (rootJobNames.length === 0 && jobEntries.length > 0) {
    rootJobNames.push(jobEntries[0][0]);
  }

  const lines = yamlContent.split(/\r?\n/);
  const jobsLineIndex = lines.findIndex((l) => /^\s*jobs:\s*$/.test(l));

  if (jobsLineIndex === -1) {
    return {
      modified: false,
      alreadyConfigured: false,
      reason: "Could not locate 'jobs:' block in workflow text.",
    };
  }

  // Determine standard indentation under jobs: (inspect first job line indentation or default to 2 spaces)
  let jobIndent = "  ";
  for (let i = jobsLineIndex + 1; i < lines.length; i++) {
    const m = lines[i].match(/^(\s+)[a-zA-Z0-9_-]+:\s*$/);
    if (m && !lines[i].trim().startsWith("#")) {
      jobIndent = m[1];
      break;
    }
  }

  const propIndent = jobIndent + "  ";
  const stepIndent = propIndent + "  ";
  const stepPropIndent = stepIndent + "  ";

  const securityJobLines = [
    `${jobIndent}repoguard-security-scan:`,
    `${propIndent}name: RepoGuard Pre-Execution Security Gate`,
    `${propIndent}runs-on: ubuntu-latest`,
    `${propIndent}permissions:`,
    `${stepIndent}contents: read`,
    `${propIndent}steps:`,
    `${stepIndent}- name: Checkout code`,
    `${stepPropIndent}uses: actions/checkout@v6`,
    `${stepIndent}- name: Run RepoGuard Security Check`,
    `${stepPropIndent}uses: ${usesString}`,
    `${stepPropIndent}with:`,
    `${stepPropIndent}  minimum-severity: medium`,
    `${stepPropIndent}  fail-on: high`,
  ];

  // Insert the security scan job right after `jobs:`
  lines.splice(jobsLineIndex + 1, 0, ...securityJobLines);

  // Attach `needs: [repoguard-security-scan]` to each detected root job surgically
  let attachedCount = 0;
  for (const rootJob of rootJobNames) {
    const escaped = rootJob.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const jobRegex = new RegExp(`^(\\s*)['"]?${escaped}['"]?:\\s*$`);

    const startIndex = jobsLineIndex + 1 + securityJobLines.length;
    for (let i = startIndex; i < lines.length; i++) {
      const match = lines[i].match(jobRegex);
      if (match) {
        const currentJobIndent = match[1];
        const innerPropIndent = currentJobIndent + "  ";

        let foundExistingEmptyNeeds = false;
        for (let j = i + 1; j < Math.min(i + 10, lines.length); j++) {
          const trimmed = lines[j].trim();
          if (!trimmed || trimmed.startsWith("#")) continue;
          if (
            new RegExp(`^${innerPropIndent}needs:\\s*(\\[\\s*\\])?$`).test(
              lines[j],
            )
          ) {
            lines[j] = `${innerPropIndent}needs: [repoguard-security-scan]`;
            foundExistingEmptyNeeds = true;
            attachedCount++;
            break;
          }
          if (lines[j].startsWith(innerPropIndent)) break;
        }

        if (!foundExistingEmptyNeeds) {
          lines.splice(
            i + 1,
            0,
            `${innerPropIndent}needs: [repoguard-security-scan]`,
          );
          attachedCount++;
        }
        break;
      }
    }
  }

  const newContent = lines.join("\n");

  return {
    modified: true,
    alreadyConfigured: false,
    newContent,
    reason: `Injected security gate and attached needs to ${attachedCount} entry job(s).`,
  };
}

/**
 * Builds the Markdown description for the Suggestion Pull Request.
 */
export function buildSuggestPRBody(
  repo: string,
  modifiedFile: string,
  isNewFile: boolean,
  actionUsesString: string = buildActionUsesString(),
): string {
  return `## 🛡️ RepoGuard Pre-Execution Security Gate

### Why is this Pull Request needed?
In modern software development, **supply chain attacks** frequently target CI/CD pipelines:
* Attackers submit pull requests containing typosquatted packages or malicious \`postinstall\` lifecycle scripts.
* Standard CI workflows trigger immediately on pull request, running \`npm install\` or test scripts **before** human code review.
* The runner executes the malicious script, exfiltrating CI environment secrets (\`GITHUB_TOKEN\`, deployment keys, cloud credentials) or launching crypto-miners.

### How does this PR protect \`${repo}\`?
This pull request configures the official [**ALADETAN-IFE/repoguard-action**](https://github.com/marketplace/actions/repoguard-security-scan):
1. **Runs First:** RepoGuard performs an instantaneous static security scan across all changed code and dependencies **before** any build or test commands execute.
2. **Hard-Fails Attacks:** If high or critical severity malicious payloads, backdoors, or leaked secrets are detected, the gate fails immediately (\`fail-on: "high"\`), automatically cancelling downstream jobs.
3. **Tamper-Resistant & Pinned:** The action is pinned to an immutable full commit SHA to protect against supply chain tampering, and securely resolves security configuration from the **default branch** using GitHub's built-in token.

---

### Changes Included:
* **Workflow:** \`${modifiedFile}\` (${isNewFile ? "New security workflow" : "Injected pre-execution security gate with \`needs: [repoguard-security-scan]\`"})
* **Action:** \`${actionUsesString}\`

Merge this PR to activate automated CI/CD pipeline protection. To adjust thresholds or customize scan rules, add a \`.repoguard.yml\` configuration file in the default branch.

📖 **Need more info?** Check out the [RepoGuard Security Scan on GitHub Marketplace](https://github.com/marketplace/actions/repoguard-security-scan) for full documentation, input specifications, and configuration guides.`;
}

/**
 * Builds the Markdown description for a SHA-Pinning Pull Request.
 */
export function buildPinPRBody(
  repo: string,
  modifiedFile: string,
  actionUsesString: string,
  sha: string,
): string {
  return `## 🛡️ RepoGuard Action: Supply Chain Pinning

### Why is this Pull Request needed?
In modern CI/CD security, referencing third-party GitHub Actions by mutable tags (such as \`@v1\`) creates supply chain attack risk if an upstream repository or tag is compromised or altered.

### How does this PR protect \`${repo}\`?
This pull request updates \`${modifiedFile}\` to pin \`ALADETAN-IFE/repoguard-action\` to its immutable full commit SHA:
\`\`\`yaml
      - name: Run RepoGuard Security Check
        uses: ${actionUsesString}
\`\`\`

* **Immutable Commit SHA (\`${sha}\`):** Guarantees that only the verified, exact action code executes in your workflows.
* **Full Scanner Compliance:** Satisfies RepoGuard's \`workflow-unpinned-action\` security rule, preventing check warnings in pull requests.

Merge this PR to ensure maximum supply chain integrity for your GitHub Actions.`;
}

/**
 * Inspects a repository and creates a Pull Request proposing RepoGuard Action protection.
 */
export async function suggestActionForRepo(
  octokit: OctokitClient,
  owner: string,
  repo: string,
): Promise<SuggestActionResult> {
  let createdBranchName: string | null = null;
  try {
    const actionSha = await resolveActionSha(octokit);
    const actionUses = buildActionUsesString(actionSha);

    // 1. Check if an open suggestion PR already exists
    const { data: openPRs } = await octokit.request(
      "GET /repos/{owner}/{repo}/pulls",
      {
        owner,
        repo,
        state: "open",
        per_page: 50,
      },
    );

    const existingPR = (
      openPRs as Array<{
        number: number;
        html_url: string;
        head: { ref: string };
        title: string;
      }>
    ).find(
      (pr) =>
        pr.head.ref.startsWith("repoguard/ci-protection") ||
        pr.head.ref.startsWith("repoguard/pin-ci-protection") ||
        pr.title
          .toLowerCase()
          .includes("repoguard pre-execution security gate") ||
        pr.title.toLowerCase().includes("pin repoguard action"),
    );

    if (existingPR) {
      // If a suggestion PR is already open, check if it needs updating to the pinned commit SHA
      try {
        const { data: prFiles } = await octokit.request(
          "GET /repos/{owner}/{repo}/pulls/{pull_number}/files",
          {
            owner,
            repo,
            pull_number: existingPR.number,
          },
        );

        const workflowFile = (
          prFiles as Array<{ filename: string; status: string }>
        ).find(
          (f) =>
            f.filename.startsWith(".github/workflows/") &&
            (f.filename.endsWith(".yml") || f.filename.endsWith(".yaml")),
        );

        if (workflowFile) {
          const { data: fileData } = await octokit.request(
            "GET /repos/{owner}/{repo}/contents/{path}",
            {
              owner,
              repo,
              path: workflowFile.filename,
              ref: existingPR.head.ref,
            },
          );

          if (!Array.isArray(fileData) && "content" in fileData) {
            const rawContent = Buffer.from(fileData.content, "base64").toString(
              "utf8",
            );
            const currentUses = `uses: ${actionUses}`;
            const actionRegex =
              /uses:\s+ALADETAN-IFE\/repoguard-action@[^\s#]+(\s*#[^\n]*)?/g;

            if (
              !rawContent.includes(currentUses) &&
              actionRegex.test(rawContent)
            ) {
              const updatedContent = rawContent.replace(
                actionRegex,
                currentUses,
              );

              await octokit.request(
                "PUT /repos/{owner}/{repo}/contents/{path}",
                {
                  owner,
                  repo,
                  path: workflowFile.filename,
                  message:
                    "ci(security): pin RepoGuard action to commit SHA to satisfy workflow-unpinned-action",
                  content: Buffer.from(updatedContent, "utf8").toString(
                    "base64",
                  ),
                  branch: existingPR.head.ref,
                  sha: fileData.sha,
                },
              );

              logger.info(
                `[workflow-guard] Updated existing PR #${existingPR.number} (${workflowFile.filename}) in ${owner}/${repo} to latest RepoGuard Action commit SHA`,
              );

              return {
                owner,
                repo,
                prNumber: existingPR.number,
                prUrl: existingPR.html_url,
                status: "updated",
                message: `Updated existing suggestion PR #${existingPR.number} with latest pinned commit SHA.`,
              };
            }
          }
        }
      } catch (prUpdateErr) {
        logger.warn(
          `[workflow-guard] Failed to inspect/update existing PR #${existingPR.number} files in ${owner}/${repo}: ${prUpdateErr instanceof Error ? prUpdateErr.message : String(prUpdateErr)}`,
        );
      }

      return {
        owner,
        repo,
        prNumber: existingPR.number,
        prUrl: existingPR.html_url,
        status: "pr_already_open",
        message: `A suggestion PR (#${existingPR.number}) is already open.`,
      };
    }

    // 2. Resolve default branch
    const { data: repoInfo } = await octokit.request(
      "GET /repos/{owner}/{repo}",
      { owner, repo },
    );
    const defaultBranch =
      (repoInfo as { default_branch?: string }).default_branch || "main";

    // 3. Inspect existing workflow files in .github/workflows
    let workflowFiles: Array<{ name: string; path: string; sha: string }> = [];
    try {
      const { data: contents } = await octokit.request(
        "GET /repos/{owner}/{repo}/contents/{path}",
        {
          owner,
          repo,
          path: ".github/workflows",
          ref: defaultBranch,
        },
      );

      if (Array.isArray(contents)) {
        workflowFiles = contents
          .filter((f) => f.name.endsWith(".yml") || f.name.endsWith(".yaml"))
          .map((f) => ({ name: f.name, path: f.path, sha: f.sha }));
      }
    } catch (err: unknown) {
      const status = (err as { status?: number }).status;
      if (status !== 404) {
        throw err;
      }
      // 404 means no .github/workflows directory exists yet
    }

    // 4. Check if RepoGuard is already configured in any existing workflow on default branch
    let workflowNeedsPinning: {
      path: string;
      sha: string;
      rawContent: string;
    } | null = null;
    let alreadyFullyPinned = false;

    for (const file of workflowFiles) {
      try {
        const { data: fileData } = await octokit.request(
          "GET /repos/{owner}/{repo}/contents/{path}",
          {
            owner,
            repo,
            path: file.path,
            ref: defaultBranch,
          },
        );

        const rawContent = Buffer.from(
          (fileData as { content: string }).content,
          "base64",
        ).toString("utf8");

        const currentUses = `uses: ${actionUses}`;
        const actionRegex =
          /uses:\s+ALADETAN-IFE\/repoguard-action@[^\s#]+(\s*#[^\n]*)?/;

        if (rawContent.includes(currentUses)) {
          alreadyFullyPinned = true;
          break;
        } else if (actionRegex.test(rawContent)) {
          workflowNeedsPinning = {
            path: file.path,
            sha: (fileData as { sha: string }).sha,
            rawContent,
          };
          break;
        } else if (rawContent.includes("@repoguard/scanner")) {
          alreadyFullyPinned = true;
        }
      } catch {
        // Skip unreadable files
      }
    }

    if (alreadyFullyPinned && !workflowNeedsPinning) {
      return {
        owner,
        repo,
        status: "already_configured",
        message: `RepoGuard Action is already configured and pinned in ${owner}/${repo}. Customizations preserved.`,
      };
    }

    // 5. Determine whether to inject into primary CI workflow, pin existing, or create a new file
    let targetFilePath = STANDALONE_WORKFLOW_PATH;
    let targetContent = buildStandaloneWorkflowContent(actionUses);
    let targetFileSha: string | undefined;
    let isNewFile = true;
    let isPinOnlyPR = false;

    if (workflowNeedsPinning) {
      // Pin existing unpinned action on default branch
      targetFilePath = workflowNeedsPinning.path;
      targetContent = workflowNeedsPinning.rawContent.replace(
        /uses:\s+ALADETAN-IFE\/repoguard-action@(?![\da-f]{40})[^\s#]+(\s*#[^\n]*)?/g,
        `uses: ${actionUses}`,
      );
      targetFileSha = workflowNeedsPinning.sha;
      isNewFile = false;
      isPinOnlyPR = true;
    } else {
      // Prefer injecting into standard CI workflow files if one exists
      const preferredCiNames = [
        "ci.yml",
        "ci.yaml",
        "test.yml",
        "test.yaml",
        "build.yml",
        "main.yml",
      ];
      const primaryWorkflow =
        workflowFiles.find((f) =>
          preferredCiNames.includes(f.name.toLowerCase()),
        ) || workflowFiles[0];

      if (primaryWorkflow) {
        try {
          const { data: fileData } = await octokit.request(
            "GET /repos/{owner}/{repo}/contents/{path}",
            {
              owner,
              repo,
              path: primaryWorkflow.path,
              ref: defaultBranch,
            },
          );

          const rawContent = Buffer.from(
            (fileData as { content: string }).content,
            "base64",
          ).toString("utf8");
          const injection = injectRepoGuardIntoWorkflow(rawContent, actionUses);

          if (injection.modified && injection.newContent) {
            targetFilePath = primaryWorkflow.path;
            targetContent = injection.newContent;
            targetFileSha = primaryWorkflow.sha;
            isNewFile = false;
          }
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          logger.warn(
            `[workflow-guard] Failed to parse primary workflow ${primaryWorkflow.path} in ${owner}/${repo}, falling back to standalone file: ${msg}`,
          );
        }
      }
    }

    // 6. Create Git Branch
    const branchName = isPinOnlyPR
      ? `repoguard/pin-ci-protection-${Date.now()}`
      : `repoguard/ci-protection-${Date.now()}`;

    // Clean up any stale orphaned ci-protection branches without PRs
    try {
      const { data: matchingRefs } = await octokit.request(
        "GET /repos/{owner}/{repo}/git/matching-refs/{ref}",
        {
          owner,
          repo,
          ref: "heads/repoguard/ci-protection",
        },
      );
      if (Array.isArray(matchingRefs)) {
        for (const item of matchingRefs as Array<{ ref: string }>) {
          const refShort = item.ref.replace(/^refs\//, "");
          try {
            await octokit.request(
              "DELETE /repos/{owner}/{repo}/git/refs/{ref}",
              {
                owner,
                repo,
                ref: refShort,
              },
            );
            logger.info(
              `[workflow-guard] Deleted stale orphaned branch ${item.ref} in ${owner}/${repo}`,
            );
          } catch {
            // Ignore deletion failures for stale branches
          }
        }
      }
    } catch {
      // Ignore if matching-refs API is unsupported or empty
    }

    const { data: refData } = await octokit.request(
      "GET /repos/{owner}/{repo}/git/ref/{ref}",
      {
        owner,
        repo,
        ref: `heads/${defaultBranch}`,
      },
    );

    const baseSha = (refData as { object: { sha: string } }).object.sha;

    await octokit.request("POST /repos/{owner}/{repo}/git/refs", {
      owner,
      repo,
      ref: `refs/heads/${branchName}`,
      sha: baseSha,
    });
    createdBranchName = branchName;

    // 7. Commit changes to branch
    const commitMsg = isPinOnlyPR
      ? "ci(security): pin RepoGuard action to commit SHA to satisfy workflow-unpinned-action"
      : "ci(security): add RepoGuard pre-execution security gate to block malware in CI";

    await octokit.request("PUT /repos/{owner}/{repo}/contents/{path}", {
      owner,
      repo,
      path: targetFilePath,
      message: commitMsg,
      content: Buffer.from(targetContent, "utf8").toString("base64"),
      branch: branchName,
      ...(targetFileSha ? { sha: targetFileSha } : {}),
    });

    // 8. Open Pull Request
    const prTitle = isPinOnlyPR
      ? `🛡️ Security: Pin RepoGuard Action to commit SHA in ${repo}`
      : "🛡️ Security: Protect CI/CD pipelines with RepoGuard Pre-Execution Security Gate";
    const prBody = isPinOnlyPR
      ? buildPinPRBody(repo, targetFilePath, actionUses, actionSha)
      : buildSuggestPRBody(repo, targetFilePath, isNewFile, actionUses);

    const { data: pr } = await octokit.request(
      "POST /repos/{owner}/{repo}/pulls",
      {
        owner,
        repo,
        title: prTitle,
        head: branchName,
        base: defaultBranch,
        body: prBody,
        maintainer_can_modify: true,
      },
    );

    logger.info(
      `[workflow-guard] Successfully opened CI protection PR #${(pr as { number: number }).number} in ${owner}/${repo} (pinOnly: ${isPinOnlyPR})`,
    );

    return {
      owner,
      repo,
      prNumber: (pr as { number: number }).number,
      prUrl: (pr as { html_url: string }).html_url,
      status: "created",
      message: isPinOnlyPR
        ? `Suggestion PR #${(pr as { number: number }).number} opened to pin RepoGuard Action commit SHA.`
        : `Suggestion PR #${(pr as { number: number }).number} opened successfully.`,
    };
  } catch (err) {
    if (createdBranchName) {
      try {
        await octokit.request("DELETE /repos/{owner}/{repo}/git/refs/{ref}", {
          owner,
          repo,
          ref: `heads/${createdBranchName}`,
        });
        logger.info(
          `[workflow-guard] Rolled back and deleted orphaned branch ${createdBranchName} in ${owner}/${repo}`,
        );
      } catch (cleanupErr) {
        logger.warn(
          `[workflow-guard] Failed to clean up branch ${createdBranchName} in ${owner}/${repo}: ${cleanupErr instanceof Error ? cleanupErr.message : String(cleanupErr)}`,
        );
      }
    }

    let msg = err instanceof Error ? err.message : String(err);
    if (
      msg.includes("Resource not accessible by integration") ||
      msg.includes(
        "refusing to allow a GitHub App to create or update workflow",
      )
    ) {
      msg =
        "GitHub permission error: The RepoGuard GitHub App requires 'Workflows: Read and write' repository permission to configure workflow files in .github/workflows/.";
    }

    logger.error(
      `[workflow-guard] Error creating suggestion PR for ${owner}/${repo}: ${msg}`,
    );
    return {
      owner,
      repo,
      status: "error",
      message: msg,
    };
  }
}

async function fetchTenantRepos(
  client: OctokitClient,
): Promise<Array<{ name: string; full_name?: string }>> {
  const allRepos: Array<{ name: string; full_name?: string }> = [];
  let page = 1;
  let hasMore = true;

  while (hasMore) {
    const { data } = await client.request("GET /installation/repositories", {
      per_page: 100,
      page,
    });

    const repositories = Array.isArray(data.repositories)
      ? (data.repositories as Array<{ name: string; full_name?: string }>)
      : [];

    allRepos.push(...repositories);
    hasMore =
      typeof data.total_count === "number" &&
      allRepos.length < data.total_count &&
      repositories.length === 100;
    page += 1;
  }

  return allRepos;
}

/**
 * Dispatches action suggestions across all (or selected) repositories for a tenant.
 */
export async function suggestActionForTenant(
  octokit: OctokitClient,
  owner: string,
  targetRepo?: string,
): Promise<SuggestActionResult[]> {
  logger.info(
    `[workflow-guard] Suggesting RepoGuard Action for tenant "${owner}" (targetRepo: ${targetRepo || "all"})`,
  );

  let reposToProcess: string[] = [];

  if (targetRepo) {
    reposToProcess = [targetRepo];
  } else {
    try {
      const allRepos = await fetchTenantRepos(octokit);
      reposToProcess = allRepos.map((r) => r.name);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(
        `[workflow-guard] Failed to fetch repositories for tenant ${owner}: ${msg}`,
      );
      return [
        {
          owner,
          repo: "*",
          status: "error",
          message: "Failed to fetch repositories for organization.",
        },
      ];
    }
  }

  if (reposToProcess.length === 0) {
    return [
      {
        owner,
        repo: "*",
        status: "no_repos",
        message: "No accessible repositories found for this installation.",
      },
    ];
  }

  const results: SuggestActionResult[] = [];
  let firstCreatedPRNumber: number | null = null;

  for (const repoName of reposToProcess) {
    const result = await suggestActionForRepo(octokit, owner, repoName);
    results.push(result);
    if (
      (result.status === "created" || result.status === "updated") &&
      result.prNumber &&
      !firstCreatedPRNumber
    ) {
      firstCreatedPRNumber = result.prNumber;
    }
  }

  // Update installation record tracking
  await Installation.findOneAndUpdate(
    { owner },
    {
      actionSuggestedAt: new Date(),
      ...(firstCreatedPRNumber ? { actionPRNumber: firstCreatedPRNumber } : {}),
    },
  );

  return results;
}
