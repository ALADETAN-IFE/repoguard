import express, { raw, type Request, type Response } from "express";
import {
  authRateLimit,
  handleWebhook,
  requireApiKey,
  requireRescanSecret,
  requireWebhookSignature,
  webhookRateLimit,
} from "./middleware";
import { Scan, Finding, Installation, Checkpoint } from "./models";
import { scanRepoList } from "./webhooks/installation";
import { githubApp } from "./config/githubApp";
import { normaliseOctokit } from "./utils/normaliseOctokit";
import logger from "./utils/logger";
import { getHealthReport, getHealthStatusCode } from "./utils/health";
import { handleMarketplaceWebhook } from "./webhooks/marketplace";

const router = express.Router();

router.get("/", (_req: Request, res: Response) => {
  res.json({ message: "Welcome to RepoGuard API" });
});

router.use(
  "/api/webhook",
  raw({ type: "application/json" }), // ← raw buffer, not parsed JSON
  webhookRateLimit,
  requireWebhookSignature,
  handleWebhook,
);

router.get("/health", (_req: Request, res: Response) => {
  void (async (): Promise<void> => {
    try {
      const report = await getHealthReport();
      res.status(getHealthStatusCode(report)).json(report);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`[health] Health check failed: ${message}`);
      res.status(503).json({
        status: "degraded",
        app: "RepoGuard-IfeCodes",
        version: "1.0.0",
        checks: {
          mongodb: { status: "error", message },
          redis: { status: "error", message: "Health check aborted" },
        },
      });
    }
  })();
});

router.get("/auth/callback", (req: Request, res: Response) => {
  const { installation_id, setup_action } = req.query;
  res.json({
    message: "RepoGuard installed successfully!",
    installation_id,
    setup_action,
  });
});

// Marketplace billing webhook — receives purchase/change/cancel events from GitHub
router.post(
  "/api/marketplace-webhook",
  raw({ type: "application/json" }), // raw buffer needed for signature verification
  (req, res) => {
    void handleMarketplaceWebhook(req, res);
  },
);

// Returns recent scans for a given owner/repo (paginated)
const getScans = async (req: Request, res: Response): Promise<void> => {
  try {
    const { owner, repo, limit = "20", page = "1" } = req.query;

    const pageNum = Math.max(1, parseInt(page as string, 10));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit as string, 10)));
    const skip = (pageNum - 1) * limitNum;

    const filter: Record<string, unknown> = {};
    if (owner) filter.owner = owner;
    if (repo) filter.repo = repo;

    const [scans, total] = await Promise.all([
      Scan.find(filter)
        .sort({ startedAt: -1 })
        .skip(skip)
        .limit(limitNum)
        .lean(),
      Scan.countDocuments(filter),
    ]);

    const totalPages = Math.ceil(total / limitNum);

    res.json({
      scans,
      pagination: {
        total,
        totalPages,
        page: pageNum,
        limit: limitNum,
        hasNextPage: pageNum < totalPages,
        hasPrevPage: pageNum > 1,
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`[scans] Failed to fetch scans: ${message}`);
    res.status(500).json({ error: "Internal server error" });
  }
};

router.get("/api/scans", authRateLimit, requireApiKey, (req, res) => {
  void getScans(req, res);
});

// Returns findings for a specific scan
const getScanFindings = async (req: Request, res: Response): Promise<void> => {
  try {
    const findings = await Finding.find({ scanId: req.params.scanId })
      .sort({ severity: 1 })
      .lean();
    res.json({ findings });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`[scans] Failed to fetch scans: ${message}`);
    res.status(500).json({ error: "Internal server error" });
  }
};

router.get(
  "/api/scans/:scanId/findings",
  authRateLimit,
  requireApiKey,
  (req, res) => {
    void getScanFindings(req, res);
  },
);

// Rescan all repos
const rescanAll = async (req: Request, res: Response): Promise<void> => {
  try {
    const installations = await Installation.find({
      uninstalledAt: null,
    }).lean();

    if (installations.length === 0) {
      res.json({ message: "No active installations found" });
      return;
    }

    const secret = req.headers["x-rescan-secret"];
    if (secret !== process.env.RESCAN_SECRET) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    // Fire and forget — don't await, respond immediately
    void (async (): Promise<void> => {
      for (const installation of installations) {
        try {
          const octokit = await githubApp.getInstallationOctokit(
            installation.installationId,
          );
          const client = normaliseOctokit(octokit);

          // Get all repos for this installation
          const { data: repos } = await client.request(
            "GET /installation/repositories",
            { per_page: 100 },
          );

          const repoList = repos.repositories.map(
            (r: { full_name: string; name: string }) => ({
              full_name: r.full_name,
              name: r.name,
            }),
          );

          if (repoList.length === 0) continue;

          const installationKey = `${installation.owner}-${installation.installationId}`;

          // Clear the checkpoint so scanRepoList rescans everything
          await Checkpoint.deleteOne({ installationKey });

          // Re-init checkpoint with all repos
          await Checkpoint.findOneAndUpdate(
            { installationKey },
            {
              $setOnInsert: {
                installationKey,
                installationId: installation.installationId,
                owner: installation.owner,
                totalRepos: repoList.map(
                  (r: { full_name: string }) => r.full_name,
                ),
                scanned: [],
                startedAt: new Date(),
              },
            },
            { upsert: true, new: false },
          );

          logger.info(
            `[rescan] Starting rescan for ${installation.owner} — ${repoList.length} repos`,
          );
          await scanRepoList(
            client,
            installationKey,
            installation.owner,
            repoList,
          );
          logger.info(`[rescan] Completed rescan for ${installation.owner}`);
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          logger.error(
            `[rescan] Failed for installation ${installation.installationId}: ${message}`,
          );
        }
      }
    })();

    res.json({
      message: `Rescan triggered for ${installations.length} installation${installations.length > 1 ? "s" : ""}`,
      installations: installations.map((i) => i.owner),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`[rescan] Failed to trigger rescan: ${message}`);
    res.status(500).json({ error: "Internal server error" });
  }
};

router.post(
  "/api/rescan-all",
  authRateLimit,
  requireRescanSecret,
  (req, res) => {
    void rescanAll(req, res);
  },
);

router.use((_req: Request, res: Response) => {
  res.status(404).json({ error: "Route not found" });
});

export default router;
