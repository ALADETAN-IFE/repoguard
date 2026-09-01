import { type Request, type Response } from "express";
import { Scan, Finding, Installation } from "../models";
import { githubApp } from "../config/githubApp";
import { normaliseOctokit } from "../utils/normaliseOctokit";
import logger from "../utils/logger";
import { scanRepoList } from "../webhooks/installation";

/**
 * GET /api/stats
 * Returns high-level dashboard metrics for an owner or platform-wide
 */
export const getDashboardStats = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { owner } = req.query;
    const filter: Record<string, unknown> = {};
    if (owner && typeof owner === "string") {
      filter.owner = new RegExp(`^${owner}$`, "i");
    }

    const [
      totalScans,
      cleanScans,
      criticalFindings,
      highFindings,
      mediumFindings,
      lowFindings,
      recentScans,
    ] = await Promise.all([
      Scan.countDocuments(filter),
      Scan.countDocuments({ ...filter, findingsCount: 0 }),
      Finding.countDocuments({
        ...filter,
        severity: "critical",
        resolvedAt: null,
      }),
      Finding.countDocuments({ ...filter, severity: "high", resolvedAt: null }),
      Finding.countDocuments({
        ...filter,
        severity: "medium",
        resolvedAt: null,
      }),
      Finding.countDocuments({ ...filter, severity: "low", resolvedAt: null }),
      Scan.find(filter).sort({ startedAt: -1 }).limit(5).lean(),
    ]);

    const atRiskScans = totalScans - cleanScans;
    const totalOpenThreats =
      criticalFindings + highFindings + mediumFindings + lowFindings;

    // Calculate score (0 - 100)
    let score = 100;
    if (totalScans > 0) {
      const penalty =
        criticalFindings * 25 +
        highFindings * 15 +
        mediumFindings * 5 +
        lowFindings * 1;
      score = Math.max(0, Math.min(100, 100 - penalty));
    }

    let grade = "A";
    if (score < 60) grade = "F";
    else if (score < 70) grade = "D";
    else if (score < 80) grade = "C";
    else if (score < 90) grade = "B";

    res.json({
      score,
      grade,
      totalScans,
      cleanScans,
      atRiskScans,
      totalOpenThreats,
      findingsBySeverity: {
        critical: criticalFindings,
        high: highFindings,
        medium: mediumFindings,
        low: lowFindings,
      },
      recentScans,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`[dashboard] Failed to get stats: ${message}`);
    res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * GET /api/installations
 * Lists active GitHub App installations
 */
export const getInstallations = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { owner } = req.query;
    const filter: Record<string, unknown> = { uninstalledAt: null };
    if (owner && typeof owner === "string") {
      filter.owner = new RegExp(`^${owner}$`, "i");
    }

    const installations = await Installation.find(filter)
      .sort({ installedAt: -1 })
      .lean();

    res.json({ installations });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`[dashboard] Failed to get installations: ${message}`);
    res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * GET /api/installations/:owner/repos
 * Fetches monitored repos under an installation with last scan and finding tallies
 */
export const getInstallationRepos = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { owner } = req.params;
    const installation = await Installation.findOne({
      owner: new RegExp(`^${owner}$`, "i"),
      uninstalledAt: null,
    }).lean();

    if (!installation) {
      res
        .status(404)
        .json({ error: `Installation not found for owner '${owner}'` });
      return;
    }

    const octokit = await githubApp.getInstallationOctokit(
      installation.installationId,
    );
    const client = normaliseOctokit(octokit);

    const { data: reposData } = await client.request(
      "GET /installation/repositories",
      {
        per_page: 100,
      },
    );

    const reposWithStats = await Promise.all(
      reposData.repositories.map(
        async (r: {
          id: number;
          name: string;
          full_name: string;
          private: boolean;
          default_branch: string;
        }) => {
          const [latestScan, openFindingsCount] = await Promise.all([
            Scan.findOne({
              installationId: installation.installationId,
              repo: r.name,
            })
              .sort({ startedAt: -1 })
              .lean(),
            Finding.countDocuments({
              installationId: installation.installationId,
              repo: r.name,
              resolvedAt: null,
            }),
          ]);

          return {
            id: r.id,
            name: r.name,
            fullName: r.full_name,
            owner: installation.owner,
            isPrivate: r.private,
            defaultBranch: r.default_branch || "main",
            status: openFindingsCount > 0 ? "at_risk" : "clean",
            lastScanAt:
              latestScan?.completedAt || latestScan?.startedAt || null,
            findingsCount: openFindingsCount,
            openFixPrsCount: openFindingsCount > 0 ? 1 : 0,
          };
        },
      ),
    );

    res.json({ repositories: reposWithStats });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      `[dashboard] Failed to get installation repos for ${req.params.owner}: ${message}`,
    );
    res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * POST /api/repos/:owner/:repo/scan
 * Triggers an on-demand scan for a single repository
 */
export const scanSingleRepository = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { owner, repo } = req.params;
    const installation = await Installation.findOne({
      owner: new RegExp(`^${owner}$`, "i"),
      uninstalledAt: null,
    }).lean();

    if (!installation) {
      res
        .status(404)
        .json({ error: `Active installation not found for owner '${owner}'` });
      return;
    }

    const octokit = await githubApp.getInstallationOctokit(
      installation.installationId,
    );
    const client = normaliseOctokit(octokit);

    const installationKey = `${installation.owner}-${installation.installationId}`;
    const repoList = [{ full_name: `${owner}/${repo}`, name: repo }];

    // Fire scan
    void scanRepoList(client, installationKey, installation.owner, repoList);

    res.json({
      message: `Scan initiated for ${owner}/${repo}`,
      owner,
      repo,
      installationId: installation.installationId,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      `[dashboard] Failed to trigger scan for ${req.params.owner}/${req.params.repo}: ${message}`,
    );
    res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * GET /api/repos/:owner/:repo/pulls
 * Lists open Fix PRs created by RepoGuard for a repository
 */
export const getRepoFixPRs = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { owner, repo } = req.params;
    const installation = await Installation.findOne({
      owner: new RegExp(`^${owner}$`, "i"),
      uninstalledAt: null,
    }).lean();

    if (!installation) {
      res
        .status(404)
        .json({ error: `Installation not found for owner '${owner}'` });
      return;
    }

    const octokit = await githubApp.getInstallationOctokit(
      installation.installationId,
    );
    const client = normaliseOctokit(octokit);

    const { data: pulls } = await client.request(
      "GET /repos/{owner}/{repo}/pulls",
      {
        owner,
        repo,
        state: "open",
        per_page: 50,
      },
    );

    const repoGuardPulls = pulls.filter(
      (pr: { title: string; head: { ref: string } }) =>
        pr.title.includes("RepoGuard") || pr.head.ref.startsWith("repoguard/"),
    );

    res.json({ pulls: repoGuardPulls });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      `[dashboard] Failed to fetch PRs for ${req.params.owner}/${req.params.repo}: ${message}`,
    );
    res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * POST /api/repos/:owner/:repo/pulls/:pull_number/approve
 * Approves a RepoGuard Fix PR
 */
export const approveFixPR = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { owner, repo, pull_number } = req.params;
    const pullNumber = parseInt(pull_number, 10);

    const installation = await Installation.findOne({
      owner: new RegExp(`^${owner}$`, "i"),
      uninstalledAt: null,
    }).lean();

    if (!installation) {
      res
        .status(404)
        .json({ error: `Installation not found for owner '${owner}'` });
      return;
    }

    const octokit = await githubApp.getInstallationOctokit(
      installation.installationId,
    );
    const client = normaliseOctokit(octokit);

    await client.request(
      "POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews",
      {
        owner,
        repo,
        pull_number: pullNumber,
        event: "APPROVE",
        body: "✓ Approved via RepoGuard Security Console.",
      },
    );

    logger.info(`[dashboard] Approved PR #${pullNumber} in ${owner}/${repo}`);
    res.json({ message: `Pull Request #${pullNumber} approved successfully` });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      `[dashboard] Failed to approve PR #${req.params.pull_number}: ${message}`,
    );
    res.status(500).json({ error: message });
  }
};

/**
 * POST /api/repos/:owner/:repo/pulls/:pull_number/merge
 * Squashes & merges a RepoGuard Fix PR and resolves findings
 */
export const mergeFixPR = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { owner, repo, pull_number } = req.params;
    const pullNumber = parseInt(pull_number, 10);

    const installation = await Installation.findOne({
      owner: new RegExp(`^${owner}$`, "i"),
      uninstalledAt: null,
    }).lean();

    if (!installation) {
      res
        .status(404)
        .json({ error: `Installation not found for owner '${owner}'` });
      return;
    }

    const octokit = await githubApp.getInstallationOctokit(
      installation.installationId,
    );
    const client = normaliseOctokit(octokit);

    const { data: mergeResult } = await client.request(
      "PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge",
      {
        owner,
        repo,
        pull_number: pullNumber,
        merge_method: "squash",
        commit_title: `🔒 RepoGuard: Merged automated security fixes (PR #${pullNumber})`,
      },
    );

    // Mark open findings for this repo as resolved
    await Finding.updateMany(
      { installationId: installation.installationId, repo, resolvedAt: null },
      { $set: { resolvedAt: new Date() } },
    );

    logger.info(`[dashboard] Merged PR #${pullNumber} in ${owner}/${repo}`);
    res.json({
      message: `Pull Request #${pullNumber} merged successfully!`,
      mergeResult,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      `[dashboard] Failed to merge PR #${req.params.pull_number}: ${message}`,
    );
    res.status(500).json({ error: message });
  }
};
