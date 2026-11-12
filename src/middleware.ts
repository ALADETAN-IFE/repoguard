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
import { getClientIp } from "./utils/getClientIp";

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
      `[security] Rejected unsigned webhook request from ${getClientIp(req)}`,
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
        // sendCommand: (...args: string[]) => redis.sendCommand(args),
        // For ioredis, use client.call(...) and spread the arguments list
        sendCommand: (command: string, ...args: string[]): Promise<unknown> =>
          redis!.call(command, ...args),
      })
    : undefined;
};

// ─── Security: simple in-memory rate limiter for the webhook endpoint ─────────

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 600; // Raised to 600 req/min to handle webhook delivery bursts

export const webhookRateLimit: RequestHandler = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS, // 1 minute
  max: RATE_LIMIT_MAX, // Max 600 requests per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getClientIp(req),
  store: createRedisStore(),

  handler: (req, res, _next, options) => {
    logger.warn(`[security] Rate limit exceeded for IP ${getClientIp(req)}`);
    res.status(options.statusCode).json(options.message);
  },

  message: { error: "Too many requests" },
});

// ─── Security: Auth Initiation Rate Limiter (Brute-Force Protection) ──────────
// Limits how many times a single IP can START the OAuth flow.
// 20 per minute is plenty for a real user refreshing the login page; bots will
// still be blocked long before they can enumerate anything useful.
export const authInitRateLimit: RequestHandler = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: 20, // 20 login initiations per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  store: createRedisStore(),
  handler: (req, res, _next, options) => {
    logger.warn(
      `[security] Auth initiation rate limit triggered from IP ${getClientIp(req)}`,
    );
    res
      .status(options.statusCode)
      .json({ error: "Too many requests. Please try again later." });
  },
});

// ─── Security: OAuth Callback Rate Limiter ────────────────────────────────────
// The callback is already protected by GitHub's one-time state+code parameters.
// A higher limit prevents legitimate users being blocked if their browser
// follows the redirect multiple times or retries on a slow connection.
export const authCallbackRateLimit: RequestHandler = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: 40, // 40 callbacks per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  store: createRedisStore(),
  handler: (req, res, _next, options) => {
    logger.warn(
      `[security] Auth callback rate limit triggered from IP ${getClientIp(req)}`,
    );
    res
      .status(options.statusCode)
      .json({ error: "Too many requests. Please try again later." });
  },
});

// Backward-compat alias — any other callers that import authRateLimit
// (e.g. /api/scans) continue to work unchanged with the initiation limiter.
export const authRateLimit = authInitRateLimit;

// ─── Security: Dashboard API Rate Limiter ────────────────────────────────────
// Allows smooth navigation and background SWR revalidation across pages (120 req/min)
export const apiRateLimit: RequestHandler = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS, // 1 minute window
  max: 120, // Max 120 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  store: createRedisStore(),
  handler: (req, res, _next, options) => {
    logger.warn(
      `[security] API rate limit exceeded on route from IP ${getClientIp(req)}`,
    );
    res
      .status(options.statusCode)
      .json({ error: "Too many requests. Please slow down." });
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

import {
  verifySessionToken,
  parseCookies,
  type SessionPayload,
} from "./controllers/auth";
import { getServerSession } from "./services/sessionStore";

export interface AuthenticatedRequest extends Request {
  userSession?: SessionPayload;
}

export async function requireAuthOrApiKey(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  // 1. Check for Bearer token, query param token, or repoguard_session cookie
  const authHeader = req.headers.authorization;
  const tokenFromQuery =
    typeof req.query.token === "string" ? req.query.token : undefined;
  const cookies = parseCookies(req);
  const token = authHeader?.startsWith("Bearer ")
    ? authHeader.substring(7)
    : tokenFromQuery || cookies["repoguard_session"];

  if (token) {
    let session = verifySessionToken(token);
    if (!session) {
      const serverSession = await getServerSession(token);
      if (serverSession) {
        session = serverSession;
      }
    }
    if (session) {
      (req as AuthenticatedRequest).userSession = session;
      next();
      return;
    }
  }

  // 2. Check for machine-to-machine x-api-key fallback
  const apiKey = req.headers["x-api-key"];
  if (
    apiKey &&
    typeof apiKey === "string" &&
    process.env.API_SECRET &&
    safeCompare(apiKey, process.env.API_SECRET)
  ) {
    next();
    return;
  }

  res.status(401).json({
    error:
      "Authentication required. Please provide a valid user session token or API key.",
  });
}

export async function requireAdminUserOrSecret(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  // 1. Check for Bearer token, query param token (for EventSource SSE), or cookie with isSystemAdmin privilege
  const authHeader = req.headers.authorization;
  const tokenFromQuery =
    typeof req.query.token === "string" ? req.query.token : undefined;
  const cookies = parseCookies(req);
  const token = authHeader?.startsWith("Bearer ")
    ? authHeader.substring(7)
    : tokenFromQuery || cookies["repoguard_session"];

  if (token) {
    let session = verifySessionToken(token);
    if (!session) {
      const serverSession = await getServerSession(token);
      if (serverSession) {
        session = serverSession;
      }
    }
    if (session && session.user.isSystemAdmin) {
      (req as AuthenticatedRequest).userSession = session;
      next();
      return;
    }
  }

  // 2. Check for machine-to-machine x-rescan-secret fallback
  const secret = req.headers["x-rescan-secret"];
  if (
    secret &&
    typeof secret === "string" &&
    process.env.RESCAN_SECRET &&
    safeCompare(secret, process.env.RESCAN_SECRET)
  ) {
    next();
    return;
  }

  res.status(403).json({
    error: "Access denied. System administrator privileges required.",
  });
}

export function requireApiKey(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  void requireAuthOrApiKey(req, res, next);
}

export function requireRescanSecret(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  void requireAdminUserOrSecret(req, res, next);
}
