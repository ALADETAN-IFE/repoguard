import fs from "fs";
import path from "path";
import express, { type Request, type Response } from "express";
import { handleWebhook, requireWebhookSignature, webhookRateLimit } from "./middleware";

const router = express.Router();

router.use("/api/webhook", webhookRateLimit, requireWebhookSignature, handleWebhook);

router.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", app: "RepoGuard", version: "1.0.0" });
});

router.get("/auth/callback", (req: Request, res: Response) => {
  const { installation_id, setup_action } = req.query;
  res.json({
    message: "RepoGuard installed successfully!",
    installation_id,
    setup_action,
  });
});

router.get("/api/scans", (_req: Request, res: Response) => {
  const checkpointFile = path.resolve(".repoguard-checkpoint.json");
  try {
    if (fs.existsSync(checkpointFile)) {
      const data = JSON.parse(fs.readFileSync(checkpointFile, "utf8"));
      res.json({ scans: Object.values(data) });
      return;
    }
  } catch {
    // Ignore error and fall back to empty list
  }
  res.json({ scans: [] });
});

export default router;