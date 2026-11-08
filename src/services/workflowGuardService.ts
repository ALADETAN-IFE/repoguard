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
    | "already_configured"
    | "pr_already_open"
    | "no_repos"
    | "error";
  message?: string;
}

export const STANDALONE_WORKFLOW_PATH = ".github/workflows/repoguard.yml";

export const STANDALONE_WORKFLOW_CONTENT = `# RepoGuard Pre-Execution Security Gate
# Automatically scans code, dependencies, and PR diffs for malware, backdoors, and secrets
# before arbitrary build or test scripts are executed in CI.
# https://github.com/ALADETAN-IFE/repoguard-action

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
        uses: actions/checkout@v4

      - name: Run RepoGuard Security Check
        uses: ALADETAN-IFE/repoguard-action@v1
        with:
          minimum-severity: "medium"
          fail-on: "high"
`;

/**
 * Checks if a workflow file already contains RepoGuard and, if not,
 * injects the repoguard-security-scan job and wires it into entry-point jobs via 'needs'.
 */
export function injectRepoGuardIntoWorkflow(yamlContent: string): {
  modified: boolean;
  alreadyConfigured: boolean;
  newContent?: string;
  reason?: string;
} {
  // 1. Detect if RepoGuard is already configured
  if (
    yamlContent.includes("ALADETAN-IFE/repoguard-action") ||
    yamlContent.includes("@repoguard/scanner") ||
    yamlContent.includes("repoguard-security-scan")
  ) {
    return {
      modified: false,
      alreadyConfigured: true,
      reason:
        "Workflow already contains RepoGuard Action or security scan job.",
    };
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

  const gateJobDefinition: Record<string, unknown> = {
    name: "RepoGuard Pre-Execution Security Gate",
    "runs-on": "ubuntu-latest",
    permissions: {
      contents: "read",
    },
    steps: [
      {
        name: "Checkout code",
        uses: "actions/checkout@v4",
      },
      {
        name: "Run RepoGuard Security Check",
        uses: "ALADETAN-IFE/repoguard-action@v1",
        with: {
          "minimum-severity": "medium",
          "fail-on": "high",
        },
      },
    ],
  };

  // Find root entry-point jobs: jobs without a 'needs' or with an empty 'needs' array
  let entryPointCount = 0;
  for (const [id, jobDef] of jobEntries) {
    if (id === gateJobId || !jobDef || typeof jobDef !== "object") continue;

    if (
      !jobDef.needs ||
      (Array.isArray(jobDef.needs) && jobDef.needs.length === 0)
    ) {
      jobDef.needs = [gateJobId];
      entryPointCount++;
    }
  }

  // Prepend the security gate job to doc.jobs
  doc.jobs = {
    [gateJobId]: gateJobDefinition,
    ...jobs,
  };

  const newContent = yaml.dump(doc, {
    lineWidth: -1,
    noRefs: true,
    indent: 2,
  });

  return {
    modified: true,
    alreadyConfigured: false,
    newContent,
    reason: `Injected security gate and attached needs to ${entryPointCount} entry job(s).`,
  };
}

/**
 * Builds the Markdown description for the Suggestion Pull Request.
 */
export function buildSuggestPRBody(
  repo: string,
  modifiedFile: string,
  isNewFile: boolean,
): string {
  return `## 🛡️ RepoGuard Pre-Execution Security Gate

### Why is this Pull Request needed?
In modern software development, **supply chain attacks** frequently target CI/CD pipelines:
* Attackers submit pull requests containing typosquatted packages or malicious \`postinstall\` lifecycle scripts.
* Standard CI workflows trigger immediately on pull request, running \`npm install\` or test scripts **before** human code review.
* The runner executes the malicious script, exfiltrating CI environment secrets (\`GITHUB_TOKEN\`, deployment keys, cloud credentials) or launching crypto-miners.

### How does this PR protect \`${repo}\`?
This pull request configures the official [**ALADETAN-IFE/repoguard-action@v1**](https://github.com/ALADETAN-IFE/repoguard-action):
1. **Runs First:** RepoGuard performs an instantaneous static security scan across all changed code and dependencies **before** any build or test commands execute.
2. **Hard-Fails Attacks:** If high or critical severity malicious payloads, backdoors, or leaked secrets are detected, the gate fails immediately (\`fail-on: "high"\`), automatically cancelling downstream jobs.
3. **Tamper-Resistant:** The action securely resolves security configuration from the **default branch** using GitHub's built-in token, preventing an attacker from disabling rules in their own PR branch.

---

### Changes Included:
* **Workflow:** \`${modifiedFile}\` (${isNewFile ? "New security workflow" : "Injected pre-execution security gate with \`needs: [repoguard-security-scan]\`"})
* **Action:** \`ALADETAN-IFE/repoguard-action@v1\`

Merge this PR to activate automated CI/CD pipeline protection. To adjust thresholds or customize scan rules, add a \`.repoguard.yml\` configuration file in the default branch.`;
}

/**
 * Inspects a repository and creates a Pull Request proposing RepoGuard Action protection.
 */
export async function suggestActionForRepo(
  octokit: OctokitClient,
  owner: string,
  repo: string,
): Promise<SuggestActionResult> {
  try {
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
        pr.title
          .toLowerCase()
          .includes("repoguard pre-execution security gate"),
    );

    if (existingPR) {
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

    // 4. Check if RepoGuard is already configured in any existing workflow
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
        if (
          rawContent.includes("ALADETAN-IFE/repoguard-action") ||
          rawContent.includes("@repoguard/scanner") ||
          rawContent.includes("repoguard-security-scan")
        ) {
          return {
            owner,
            repo,
            status: "already_configured",
            message: `RepoGuard Action is already configured in ${file.path}. Customizations preserved.`,
          };
        }
      } catch {
        // Skip unreadable files
      }
    }

    // 5. Determine whether to inject into primary CI workflow or create a new file
    let targetFilePath = STANDALONE_WORKFLOW_PATH;
    let targetContent = STANDALONE_WORKFLOW_CONTENT;
    let targetFileSha: string | undefined;
    let isNewFile = true;

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
        const injection = injectRepoGuardIntoWorkflow(rawContent);

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

    // 6. Create Git Branch
    const branchName = `repoguard/ci-protection-${Date.now()}`;
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

    // 7. Commit changes to branch
    await octokit.request("PUT /repos/{owner}/{repo}/contents/{path}", {
      owner,
      repo,
      path: targetFilePath,
      message:
        "ci(security): add RepoGuard pre-execution security gate to block malware in CI",
      content: Buffer.from(targetContent, "utf8").toString("base64"),
      branch: branchName,
      ...(targetFileSha ? { sha: targetFileSha } : {}),
    });

    // 8. Open Pull Request
    const prBody = buildSuggestPRBody(repo, targetFilePath, isNewFile);
    const { data: pr } = await octokit.request(
      "POST /repos/{owner}/{repo}/pulls",
      {
        owner,
        repo,
        title:
          "🛡️ Security: Protect CI/CD pipelines with RepoGuard Pre-Execution Security Gate",
        head: branchName,
        base: defaultBranch,
        body: prBody,
        maintainer_can_modify: true,
      },
    );

    logger.info(
      `[workflow-guard] Successfully opened CI protection suggestion PR #${(pr as { number: number }).number} in ${owner}/${repo}`,
    );

    return {
      owner,
      repo,
      prNumber: (pr as { number: number }).number,
      prUrl: (pr as { html_url: string }).html_url,
      status: "created",
      message: `Suggestion PR #${(pr as { number: number }).number} opened successfully.`,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
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
      result.status === "created" &&
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
