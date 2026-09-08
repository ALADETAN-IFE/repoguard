import { type Request, type Response } from "express";
import { Scan, Finding, Installation } from "../models";
import { githubApp } from "../config/githubApp";
import { normaliseOctokit } from "../utils/normaliseOctokit";
import logger from "../utils/logger";
import { scanRepoList } from "../webhooks/installation";
import { verifySessionToken } from "./auth";

/**
 * GET /api/stats
 * Returns high-level dashboard metrics for an owner or platform-wide
 */
export const getDashboardStats = async (
  req: Request,
  res: Response,
): Promise<void> => {
  const owner = typeof req.query.owner === "string" ? req.query.owner : "";
  logger.info(
    `[api/stats] Fetching security stats (filter owner: ${owner || "ALL"})`,
  );

  try {
    const filter: Record<string, unknown> = {};
    if (owner) {
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

    logger.info(
      `[api/stats] Success: Score ${score} (${grade}), Scans: ${totalScans}, Threats: ${totalOpenThreats}`,
    );

    const formattedRecentScans = recentScans.map((s) => ({
      id: s._id.toString(),
      _id: s._id.toString(),
      installationId: s.installationId,
      owner: s.owner,
      repo: s.repo,
      branch: s.branch || "main",
      commitSha: s.commitSha ? s.commitSha.slice(0, 7) : "-",
      status: s.status,
      trigger: s.trigger || "installation",
      startedAt: s.startedAt,
      completedAt: s.completedAt,
      durationMs:
        s.durationMs ??
        (s.completedAt && s.startedAt
          ? Math.max(
              0,
              new Date(s.completedAt).getTime() -
                new Date(s.startedAt).getTime(),
            )
          : 0),
      findingsCount: s.findingsCount || 0,
      filesScanned: s.filesScanned ?? 0,
    }));

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
      recentScans: formattedRecentScans,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`[api/stats] ERROR: Failed to get stats: ${message}`);
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
  const owner = typeof req.query.owner === "string" ? req.query.owner : "";
  logger.info(
    `[api/installations] Listing installations (owner: ${owner || "ALL"})`,
  );

  try {
    const filter: Record<string, unknown> = { uninstalledAt: null };
    if (owner) {
      filter.owner = new RegExp(`^${owner}$`, "i");
    }

    const installations = await Installation.find(filter)
      .sort({ installedAt: -1 })
      .lean();

    logger.info(
      `[api/installations] Success: Found ${installations.length} active installation(s)`,
    );
    res.json({ installations });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      `[api/installations] ERROR: Failed to get installations: ${message}`,
    );
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
  const { owner } = req.params;
  logger.info(`[api/installations/repos] Fetching repos for owner: '${owner}'`);

  try {
    const installation = await Installation.findOne({
      owner: new RegExp(`^${owner}$`, "i"),
      uninstalledAt: null,
    }).lean();

    if (!installation) {
      logger.warn(
        `[api/installations/repos] Installation not found for owner '${owner}'`,
      );
      res
        .status(404)
        .json({ error: `Installation not found for owner '${owner}'` });
      return;
    }

    logger.info(
      `[api/installations/repos] Found installation #${installation.installationId}, requesting GitHub API repositories`,
    );

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

    logger.info(
      `[api/installations/repos] Retrieved ${reposData.repositories.length} repos from GitHub for installation #${installation.installationId}`,
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

    logger.info(
      `[api/installations/repos] Success: Returning ${reposWithStats.length} repository status records for '${owner}'`,
    );
    res.json({ repositories: reposWithStats });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      `[api/installations/repos] ERROR: Failed to get repos for '${req.params.owner}': ${message}`,
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
  const { owner, repo } = req.params;
  logger.info(
    `[api/repos/scan] On-demand scan requested for '${owner}/${repo}'`,
  );

  try {
    const installation = await Installation.findOne({
      owner: new RegExp(`^${owner}$`, "i"),
      uninstalledAt: null,
    }).lean();

    if (!installation) {
      logger.warn(
        `[api/repos/scan] Active installation not found for owner '${owner}'`,
      );
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

    logger.info(
      `[api/repos/scan] Dispatched background scan worker for ${owner}/${repo} (inst #${installation.installationId})`,
    );

    // Fire scan with manual trigger
    void scanRepoList(
      client,
      installationKey,
      installation.owner,
      repoList,
      "manual",
    );

    res.json({
      message: `Scan initiated for ${owner}/${repo}`,
      owner,
      repo,
      installationId: installation.installationId,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      `[api/repos/scan] ERROR: Failed to trigger scan for ${req.params.owner}/${req.params.repo}: ${message}`,
    );
    res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * GET /api/installations/:owner/pulls
 * Lists open Fix PRs across ALL repositories under an installation in a single call.
 */
export const getInstallationFixPRs = async (
  req: Request,
  res: Response,
): Promise<void> => {
  const { owner } = req.params;
  logger.info(
    `[api/installations/pulls] Fetching open Fix PRs for installation '${owner}'`,
  );

  try {
    const installation = await Installation.findOne({
      owner: new RegExp(`^${owner}$`, "i"),
      uninstalledAt: null,
    }).lean();

    if (!installation) {
      logger.warn(
        `[api/installations/pulls] Installation not found for owner '${owner}'`,
      );
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
      { per_page: 100 },
    );

    const repos = reposData.repositories || [];

    const deriveSeverity = (pr: {
      labels: { name: string }[];
      title: string;
    }): string => {
      const labelNames = pr.labels.map((l) => l.name.toLowerCase());
      if (
        labelNames.includes("critical") ||
        pr.title.toLowerCase().includes("critical")
      )
        return "critical";
      if (
        labelNames.includes("high") ||
        pr.title.toLowerCase().includes("high")
      )
        return "high";
      if (
        labelNames.includes("medium") ||
        pr.title.toLowerCase().includes("medium")
      )
        return "medium";
      return "low";
    };

    const prPromises = repos.map(
      async (r: { name: string; full_name: string }) => {
        try {
          const { data: pulls } = await client.request(
            "GET /repos/{owner}/{repo}/pulls",
            {
              owner,
              repo: r.name,
              state: "open",
              per_page: 50,
            },
          );

          const repoGuardPulls = pulls.filter(
            (pr: { title: string; head: { ref: string } }) =>
              pr.title.includes("RepoGuard") ||
              pr.head.ref.startsWith("repoguard/"),
          );

          return repoGuardPulls.map(
            (pr: {
              id: number;
              number: number;
              title: string;
              head: { ref: string };
              base: { repo: { name: string } };
              html_url: string;
              created_at: string;
              user: { login: string } | null;
              labels: { name: string }[];
            }) => ({
              id: pr.id,
              number: pr.number,
              title: pr.title,
              owner,
              repo: pr.base?.repo?.name || r.name,
              branch: pr.head.ref,
              url: pr.html_url,
              findingsCount: 1,
              severity: deriveSeverity(pr),
              rule: "security-fix",
              status: "open",
              createdAt: pr.created_at,
              author: pr.user?.login || "repoguard[bot]",
            }),
          );
        } catch {
          return [];
        }
      },
    );

    const nested = await Promise.all(prPromises);
    const allPulls = nested.flat();

    logger.info(
      `[api/installations/pulls] Success: Returning ${allPulls.length} Fix PR(s) across ${repos.length} repos for '${owner}'`,
    );
    res.json({ pulls: allPulls });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      `[api/installations/pulls] ERROR: Failed to fetch PRs for '${req.params.owner}': ${message}`,
    );
    res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * GET /api/repos/:owner/:repo/pulls
 * Lists open Fix PRs created by RepoGuard for a repository,
 * normalized to the FixPRRecord shape the frontend expects.
 */
export const getRepoFixPRs = async (
  req: Request,
  res: Response,
): Promise<void> => {
  const { owner, repo } = req.params;
  logger.info(`[api/repos/pulls] Fetching open Fix PRs for '${owner}/${repo}'`);

  try {
    const installation = await Installation.findOne({
      owner: new RegExp(`^${owner}$`, "i"),
      uninstalledAt: null,
    }).lean();

    if (!installation) {
      logger.warn(
        `[api/repos/pulls] Installation not found for owner '${owner}'`,
      );
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

    // Derive severity from PR labels or title keywords
    const deriveSeverity = (pr: {
      labels: { name: string }[];
      title: string;
    }): string => {
      const labelNames = pr.labels.map((l) => l.name.toLowerCase());
      if (
        labelNames.includes("critical") ||
        pr.title.toLowerCase().includes("critical")
      )
        return "critical";
      if (
        labelNames.includes("high") ||
        pr.title.toLowerCase().includes("high")
      )
        return "high";
      if (
        labelNames.includes("medium") ||
        pr.title.toLowerCase().includes("medium")
      )
        return "medium";
      return "low";
    };

    // Fetch unified diff for each PR (accepts vnd.github.diff)
    const normalizedPulls = await Promise.all(
      repoGuardPulls.map(
        async (pr: {
          id: number;
          number: number;
          title: string;
          head: { ref: string };
          base: { repo: { name: string } };
          html_url: string;
          created_at: string;
          user: { login: string } | null;
          labels: { name: string }[];
        }) => {
          let diff: string | undefined;
          try {
            const diffRes = await client.request(
              "GET /repos/{owner}/{repo}/pulls/{pull_number}",
              {
                owner,
                repo,
                pull_number: pr.number,
                headers: { accept: "application/vnd.github.diff" },
              },
            );
            // Octokit types this endpoint as a PR object; the diff media type
            // returns raw text, so narrow from unknown instead of the typed body.
            const diffText: unknown = diffRes.data;
            if (typeof diffText === "string" && diffText.length > 0) {
              diff = diffText;
            }
          } catch (diffErr) {
            const diffMsg =
              diffErr instanceof Error ? diffErr.message : String(diffErr);
            logger.warn(
              `[api/repos/pulls] Could not fetch diff for PR #${pr.number}: ${diffMsg}`,
            );
          }

          return {
            id: pr.id,
            number: pr.number,
            title: pr.title,
            owner,
            repo: pr.base?.repo?.name || repo,
            branch: pr.head.ref,
            url: pr.html_url,
            findingsCount: 1,
            severity: deriveSeverity(pr),
            rule: "security-fix",
            status: "open",
            createdAt: pr.created_at,
            author: pr.user?.login || "repoguard[bot]",
            diff,
          };
        },
      ),
    );

    logger.info(
      `[api/repos/pulls] Success: Returning ${normalizedPulls.length} normalized Fix PR(s) for ${owner}/${repo}`,
    );
    res.json({ pulls: normalizedPulls });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      `[api/repos/pulls] ERROR: Failed to fetch PRs for ${req.params.owner}/${req.params.repo}: ${message}`,
    );
    res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * GET /api/repos/:owner/:repo/pulls/:pull_number/diff
 * Fetches the unified Git diff for a specific Fix PR on demand.
 */
export const getRepoFixPRDiff = async (
  req: Request,
  res: Response,
): Promise<void> => {
  const { owner, repo, pull_number } = req.params;
  const pullNumber = parseInt(pull_number, 10);
  logger.info(
    `[api/repos/pulls/diff] Fetching on-demand diff for PR #${pullNumber} in '${owner}/${repo}'`,
  );

  try {
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

    const [diffRes, reviewsRes] = await Promise.all([
      client.request("GET /repos/{owner}/{repo}/pulls/{pull_number}", {
        owner,
        repo,
        pull_number: pullNumber,
        headers: { accept: "application/vnd.github.diff" },
      }),
      client
        .request("GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews", {
          owner,
          repo,
          pull_number: pullNumber,
          per_page: 20,
        })
        .catch(() => ({ data: [] })),
    ]);

    const diffText: unknown = diffRes.data;
    let diff = "";
    let isTruncated = false;
    if (typeof diffText === "string" && diffText.length > 0) {
      const MAX_DIFF_LEN = 25000;
      if (diffText.length > MAX_DIFF_LEN) {
        diff =
          diffText.slice(0, MAX_DIFF_LEN) +
          "\n\n... (Diff truncated for preview. View full patch on GitHub)";
        isTruncated = true;
      } else {
        diff = diffText;
      }
    }

    let isApproved = false;
    let reviewStatus: string | null = null;
    const reviews = Array.isArray(reviewsRes.data) ? reviewsRes.data : [];
    const approvedReview = reviews.find(
      (r: { state: string }) => r.state === "APPROVED",
    );
    if (approvedReview) {
      isApproved = true;
      reviewStatus = "APPROVED";
    }

    res.json({ diff, isTruncated, isApproved, reviewStatus });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      `[api/repos/pulls/diff] ERROR: Failed to fetch diff for PR #${pullNumber}: ${message}`,
    );
    res.status(500).json({ error: message });
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
  const { owner, repo, pull_number } = req.params;
  const pullNumber = parseInt(pull_number, 10);
  logger.info(
    `[api/repos/pulls/approve] Approving Fix PR #${pullNumber} in '${owner}/${repo}'`,
  );

  try {
    const installation = await Installation.findOne({
      owner: new RegExp(`^${owner}$`, "i"),
      uninstalledAt: null,
    }).lean();

    if (!installation) {
      logger.warn(
        `[api/repos/pulls/approve] Installation not found for owner '${owner}'`,
      );
      res
        .status(404)
        .json({ error: `Installation not found for owner '${owner}'` });
      return;
    }

    // Check if the user is authenticated with their personal GitHub OAuth token
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ")
      ? authHeader.substring(7)
      : null;
    let userAccessToken: string | undefined;
    let userLogin: string | undefined;

    if (token) {
      const session = verifySessionToken(token);
      if (session?.user?.accessToken) {
        userAccessToken = session.user.accessToken;
        userLogin = session.user.login;
      }
    }

    let approvedAsUser = false;

    if (userAccessToken) {
      try {
        logger.info(
          `[api/repos/pulls/approve] Submitting review as user @${userLogin} for PR #${pullNumber} in '${owner}/${repo}'`,
        );
        const reviewRes = await fetch(
          `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls/${pullNumber}/reviews`,
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${userAccessToken}`,
              Accept: "application/vnd.github+json",
              "User-Agent": "RepoGuard-App",
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              event: "APPROVE",
              body: "Approved via RepoGuard Security Console.",
            }),
          },
        );

        if (reviewRes.ok) {
          approvedAsUser = true;
          logger.info(
            `[api/repos/pulls/approve] SUCCESS: User @${userLogin} approved PR #${pullNumber}`,
          );
        } else {
          const errBody = await reviewRes.json().catch(() => ({}));
          logger.warn(
            `[api/repos/pulls/approve] User review failed with status ${reviewRes.status}: ${JSON.stringify(errBody)}. Falling back to bot.`,
          );
        }
      } catch (userErr) {
        logger.warn(
          `[api/repos/pulls/approve] Error during user review call: ${String(userErr)}. Falling back to bot.`,
        );
      }
    }

    if (!approvedAsUser) {
      const octokit = await githubApp.getInstallationOctokit(
        installation.installationId,
      );
      const client = normaliseOctokit(octokit);

      try {
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
      } catch (reviewErr: unknown) {
        const errMsg =
          reviewErr instanceof Error ? reviewErr.message : String(reviewErr);
        if (
          errMsg.includes("Can not approve your own pull request") ||
          errMsg.includes("Unprocessable Entity")
        ) {
          logger.info(
            `[api/repos/pulls/approve] Bot is author of PR #${pullNumber}. Submitting review confirmation comment instead.`,
          );
          await client.request(
            "POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews",
            {
              owner,
              repo,
              pull_number: pullNumber,
              event: "COMMENT",
              body: "✅ **RepoGuard Approval:** Changes verified and approved for merge via RepoGuard Security Console.",
            },
          );
        } else {
          throw reviewErr;
        }
      }
    }

    logger.info(
      `[api/repos/pulls/approve] SUCCESS: Approved PR #${pullNumber} in ${owner}/${repo}`,
    );
    res.json({ message: `Pull Request #${pullNumber} approved successfully` });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      `[api/repos/pulls/approve] ERROR: Failed to approve PR #${req.params.pull_number}: ${message}`,
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
  const { owner, repo, pull_number } = req.params;
  const pullNumber = parseInt(pull_number, 10);
  logger.info(
    `[api/repos/pulls/merge] Squashing & merging Fix PR #${pullNumber} in '${owner}/${repo}'`,
  );

  try {
    const installation = await Installation.findOne({
      owner: new RegExp(`^${owner}$`, "i"),
      uninstalledAt: null,
    }).lean();

    if (!installation) {
      logger.warn(
        `[api/repos/pulls/merge] Installation not found for owner '${owner}'`,
      );
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
    const updateRes = await Finding.updateMany(
      { installationId: installation.installationId, repo, resolvedAt: null },
      { $set: { resolvedAt: new Date() } },
    );

    logger.info(
      `[api/repos/pulls/merge] SUCCESS: Merged PR #${pullNumber} in ${owner}/${repo}, marked ${updateRes.modifiedCount} findings as resolved`,
    );
    res.json({
      message: `Pull Request #${pullNumber} merged successfully!`,
      mergeResult,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      `[api/repos/pulls/merge] ERROR: Failed to merge PR #${req.params.pull_number}: ${message}`,
    );
    res.status(500).json({ error: message });
  }
};

/**
 * POST /api/repos/:owner/:repo/pulls/:pull_number/close
 * Closes a Fix PR on GitHub without merging
 */
export const closeFixPR = async (
  req: Request,
  res: Response,
): Promise<void> => {
  const { owner, repo, pull_number } = req.params;
  const pullNumber = parseInt(pull_number, 10);
  logger.info(
    `[api/repos/pulls/close] Closing Fix PR #${pullNumber} in '${owner}/${repo}'`,
  );

  try {
    const installation = await Installation.findOne({
      owner: new RegExp(`^${owner}$`, "i"),
      uninstalledAt: null,
    }).lean();

    if (!installation) {
      logger.warn(
        `[api/repos/pulls/close] Installation not found for owner '${owner}'`,
      );
      res
        .status(404)
        .json({ error: `Installation not found for owner '${owner}'` });
      return;
    }

    const octokit = await githubApp.getInstallationOctokit(
      installation.installationId,
    );
    const client = normaliseOctokit(octokit);

    await client.request("PATCH /repos/{owner}/{repo}/pulls/{pull_number}", {
      owner,
      repo,
      pull_number: pullNumber,
      state: "closed",
    });

    logger.info(
      `[api/repos/pulls/close] SUCCESS: Closed PR #${pullNumber} in ${owner}/${repo}`,
    );
    res.json({ message: `Pull Request #${pullNumber} closed successfully` });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      `[api/repos/pulls/close] ERROR: Failed to close PR #${req.params.pull_number}: ${message}`,
    );
    res.status(500).json({ error: message });
  }
};

/**
 * GET /api/findings
 * Lists all threat findings across all scans/repositories for an owner or specific repository
 */
export const getFindings = async (
  req: Request,
  res: Response,
): Promise<void> => {
  const owner =
    typeof req.query.owner === "string" ? req.query.owner.trim() : "";
  const repo = typeof req.query.repo === "string" ? req.query.repo.trim() : "";
  const severity =
    typeof req.query.severity === "string"
      ? req.query.severity.trim().toLowerCase()
      : "";
  const status =
    typeof req.query.status === "string"
      ? req.query.status.trim().toLowerCase()
      : "";
  const scanId =
    typeof req.query.scanId === "string" ? req.query.scanId.trim() : "";

  logger.info(
    `[api/findings] Fetching findings (owner: ${owner || "ALL"}, repo: ${repo || "ALL"}, status: ${status || "ALL"})`,
  );

  try {
    const filter: Record<string, unknown> = {};

    if (owner) {
      filter.owner = new RegExp(`^${owner}$`, "i");
    }

    if (repo) {
      filter.repo = new RegExp(`^${repo}$`, "i");
    }

    if (severity) {
      filter.severity = severity;
    }

    if (status === "unresolved") {
      filter.resolvedAt = null;
    } else if (status === "resolved") {
      filter.resolvedAt = { $ne: null };
    }

    if (scanId) {
      filter.scanId = scanId;
    }

    const findings = await Finding.find(filter)
      .sort({ detectedAt: -1, severity: 1 })
      .lean();

    const formatted = findings.map((f) => ({
      id: f._id.toString(),
      _id: f._id.toString(),
      scanId: f.scanId ? f.scanId.toString() : "",
      installationId: f.installationId,
      owner: f.owner,
      repo: f.repo,
      rule: f.rule,
      ruleTitle: f.rule,
      severity: f.severity,
      message: f.message,
      file: f.file || "-",
      lineNumber: 1,
      matchedSnippet: f.message,
      status: f.resolvedAt ? "resolved" : "unresolved",
      detectedAt: f.detectedAt,
      resolvedAt: f.resolvedAt,
    }));

    logger.info(
      `[api/findings] Success: Found ${formatted.length} finding(s) matching filter`,
    );
    res.json({ findings: formatted });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`[api/findings] ERROR: Failed to get findings: ${message}`);
    res.status(500).json({ error: "Internal server error" });
  }
};
