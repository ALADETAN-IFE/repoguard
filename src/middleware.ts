import { type Request, type Response, type NextFunction } from "express";
import { createNodeMiddleware, type Webhooks } from "@octokit/webhooks";
import { githubApp } from "./config/githubApp";
import logger from "./utils/logger";

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

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const rateLimitStore = new Map<string, RateLimitEntry>();

// Clean up stale entries every 5 minutes so the map doesn't grow unbounded
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore.entries()) {
    if (entry.resetAt < now) rateLimitStore.delete(key);
  }
}, 5 * 60_000);

export function webhookRateLimit(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const ip = req.ip ?? req.socket.remoteAddress ?? "unknown";
  const now = Date.now();

  const entry = rateLimitStore.get(ip);

  if (!entry || entry.resetAt < now) {
    rateLimitStore.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    next();
    return;
  }

  entry.count++;

  if (entry.count > RATE_LIMIT_MAX) {
    logger.warn(
      `[security] Rate limit exceeded for IP ${ip} — ${entry.count} requests in window`,
    );
    res.status(429).json({ error: "Too many requests" });
    return;
  }

  next();
}