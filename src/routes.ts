import express, { type Request, type Response } from "express";
import { handleWebhook, requireWebhookSignature, webhookRateLimit } from "./middleware";
import { Scan, Finding } from "./models";

const router = express.Router();

router.get("/", (_req: Request, res: Response) => {
  res.json({ message: "Welcome to RepoGuard API" });
})

router.use("/api/webhook", webhookRateLimit, requireWebhookSignature, handleWebhook);

router.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", app: "RepoGuard-IfeCodes", version: "1.0.0" });
});

router.get("/auth/callback", (req: Request, res: Response) => {
  const { installation_id, setup_action } = req.query;
  res.json({
    message: "RepoGuard installed successfully!",
    installation_id,
    setup_action,
  });
});

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
    res.status(500).json({ error: message });
  }
};
router.get("/api/scans", (req, res) => { void getScans(req, res); });

// Returns findings for a specific scan
const getScanFindings = async (req: Request, res: Response): Promise<void> => {
  try {
    const findings = await Finding.find({ scanId: req.params.scanId })
      .sort({ severity: 1 })
      .lean();
    res.json({ findings });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: message });
  }
};
router.get("/api/scans/:scanId/findings", (req, res) => { void getScanFindings(req, res); });

export default router;