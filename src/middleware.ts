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

// ─── Shared Redis Configuration helper ────────────────────────────────────────

const createRedisStore = (): RedisStore | undefined => {
  return redis
    ? new RedisStore({
        // @ts-expect-error - Safely routes commands across different client versions
        sendCommand: (...args: string[]) => redis.sendCommand(args),
      })
    : undefined;
};

// ─── Security: simple in-memory rate limiter for the webhook endpoint ─────────

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 60;

export const webhookRateLimit: RequestHandler = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS, // 1 minute
  max: RATE_LIMIT_MAX, // Max 60 requests per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  store: createRedisStore(),

  handler: (req, res, _next, options) => {
    logger.warn(`[security] Rate limit exceeded for IP ${req.ip ?? "unknown"}`);
    res.status(options.statusCode).json(options.message);
  },

  message: { error: "Too many requests" },
});

// ─── Security: Auth Endpoint Rate Limiter (Brute-Force Protection) ────────────
// Drastically slows down scanning endpoints to a maximum of 5 requests per minute.

export const authRateLimit: RequestHandler = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS, // 1 minute window
  max: 5, // Max 5 attempts per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  store: createRedisStore(),
  handler: (req, res, _next, options) => {
    logger.warn(
      `[security] Brute-force protection triggered on auth route from IP ${req.ip ?? "unknown"}`,
    );
    res
      .status(options.statusCode)
      .json({ error: "Too many requests. Please try again later." });
  },
});

// ─── Security Helpers for Key Verification ────────────────────────────────────

/**
 * A wrapper around crypto.timingSafeEqual that safely handles inputs of
 * mismatched string lengths without leaking execution timing profile differences.
 */
function safeCompare(input: string, secret: string): boolean {
  const inputBuffer = Buffer.from(input);
  const secretBuffer = Buffer.from(secret);

  if (inputBuffer.length !== secretBuffer.length) {
    // Generate a dummy comparison to mimic computation overhead
    crypto.timingSafeEqual(secretBuffer, secretBuffer);
    return false;
  }

  return crypto.timingSafeEqual(inputBuffer, secretBuffer);
}

// ─── Route Guards ─────────────────────────────────────────────────────────────

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

  if (!safeCompare(apiKey, process.env.API_SECRET)) {
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

  if (!safeCompare(secret, process.env.RESCAN_SECRET)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  next();
}
