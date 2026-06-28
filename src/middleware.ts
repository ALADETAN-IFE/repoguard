import {
  type Request,
  type Response,
  type NextFunction,
  RequestHandler,
} from "express";
import { createNodeMiddleware, type Webhooks } from "@octokit/webhooks";
import { githubApp } from "./config/githubApp";
import logger from "./utils/logger";
import crypto from "crypto";
import rateLimit from "express-rate-limit";
import RedisStore from "rate-limit-redis";
import { redis } from "./config/redis";

// ─── Webhook middleware ───────────────────────────────────────────────────────

const webhookMiddleware = createNodeMiddleware(
  githubApp.webhooks as unknown as Webhooks<unknown>,
  { path: "/" },
);

export function handleWebhook(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  // Convert Buffer to string so @octokit/webhooks can verify the signature
  if (Buffer.isBuffer(req.body)) {
    req.body = req.body.toString("utf8");
  }
  void webhookMiddleware(req, res, next);
}

// ─── Security: reject webhook requests missing the signature header ───────────
// @octokit/webhooks verifies the signature internally, but we add an early
// guard so unsigned requests never reach the webhook parser at all.

export function requireWebhookSignature(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const sig = req.headers["x-hub-signature-256"];
  if (!sig) {
    logger.warn(
      `[security] Rejected unsigned webhook request from ${req.ip ?? "unknown"}`,
    );
    res.status(400).json({ error: "Missing x-hub-signature-256 header" });
    return;
  }
  next();
}

// ─── Security: simple in-memory rate limiter for the webhook endpoint ─────────
// Prevents hammering — max 60 requests per IP per minute.
// For production with multiple instances, replace with Redis-backed rate limit.

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 60;

export const webhookRateLimit: RequestHandler = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS, // 1 minute
  max: RATE_LIMIT_MAX, // Max 60 requests per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  store: redis
    ? new RedisStore({
        // @ts-expect-error - Safely routes commands across different client versions
        sendCommand: (...args: string[]) => redis.sendCommand(args),
      })
    : undefined,

  handler: (req, res, _next, options) => {
    logger.warn(`[security] Rate limit exceeded for IP ${req.ip ?? "unknown"}`);
    res.status(options.statusCode).json(options.message);
  },

  message: { error: "Too many requests" },
});

export function requireApiKey(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || typeof apiKey !== "string" || !process.env.API_SECRET) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const keyBuffer = Buffer.from(apiKey);
  const secretBuffer = Buffer.from(process.env.API_SECRET);

  if (
    keyBuffer.length !== secretBuffer.length ||
    !crypto.timingSafeEqual(keyBuffer, secretBuffer)
  ) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  next();
}

export function requireRescanSecret(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const secret = req.headers["x-rescan-secret"];
  if (!secret || typeof secret !== "string" || !process.env.RESCAN_SECRET) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const keyBuffer = Buffer.from(secret);
  const secretBuffer = Buffer.from(process.env.RESCAN_SECRET);

  if (
    keyBuffer.length !== secretBuffer.length ||
    !crypto.timingSafeEqual(keyBuffer, secretBuffer)
  ) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  next();
}
