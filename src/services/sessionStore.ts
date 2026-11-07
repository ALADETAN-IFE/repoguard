import crypto from "crypto";
import { redis } from "../config/redis";
import logger from "../utils/logger";
import type { AccountContext } from "../controllers/auth";

export interface ServerSessionData {
  sessionId: string;
  user: {
    id: number;
    login: string;
    name: string;
    email: string | null;
    avatarUrl: string;
    isSystemAdmin: boolean;
    role: "system_admin" | "org_admin" | "member";
    accessToken?: string;
    refreshToken?: string;
    accessTokenExpiresAt?: number;
  };
  accounts: AccountContext[];
  exp: number;
}

const SESSION_TTL_SECONDS = 7 * 24 * 3600; // 7 days

// In-memory fallback for local dev / tests when Redis is not configured
const inMemoryStore = new Map<
  string,
  { data: ServerSessionData; expiresAt: number }
>();

function cleanExpiredInMemory(): void {
  const now = Date.now();
  for (const [id, item] of inMemoryStore.entries()) {
    if (item.expiresAt <= now) {
      inMemoryStore.delete(id);
    }
  }
}

export function generateSessionId(): string {
  return crypto.randomBytes(32).toString("hex");
}

export async function saveServerSession(
  sessionId: string,
  data: ServerSessionData,
): Promise<void> {
  if (redis) {
    try {
      await redis.set(
        `repoguard:session:${sessionId}`,
        JSON.stringify(data),
        "EX",
        SESSION_TTL_SECONDS,
      );
      return;
    } catch (err) {
      logger.warn(
        `[sessionStore] Redis set failed for session ${sessionId}, falling back to memory: ${String(err)}`,
      );
    }
  }

  cleanExpiredInMemory();
  inMemoryStore.set(sessionId, {
    data,
    expiresAt: Date.now() + SESSION_TTL_SECONDS * 1000,
  });
}

export async function getServerSession(
  sessionId: string,
): Promise<ServerSessionData | null> {
  if (!sessionId) return null;

  if (redis) {
    try {
      const raw = await redis.get(`repoguard:session:${sessionId}`);
      if (raw) {
        return JSON.parse(raw) as ServerSessionData;
      }
    } catch (err) {
      logger.warn(
        `[sessionStore] Redis get failed for session ${sessionId}, checking memory: ${String(err)}`,
      );
    }
  }

  cleanExpiredInMemory();
  const item = inMemoryStore.get(sessionId);
  if (!item || item.expiresAt <= Date.now()) {
    inMemoryStore.delete(sessionId);
    return null;
  }
  return item.data;
}

export async function updateServerSessionTokens(
  sessionId: string,
  tokens: {
    accessToken: string;
    refreshToken: string;
    accessTokenExpiresAt?: number;
  },
): Promise<boolean> {
  const session = await getServerSession(sessionId);
  if (!session) return false;

  session.user.accessToken = tokens.accessToken;
  session.user.refreshToken = tokens.refreshToken;
  session.user.accessTokenExpiresAt = tokens.accessTokenExpiresAt;

  await saveServerSession(sessionId, session);
  return true;
}

export async function deleteServerSession(sessionId: string): Promise<void> {
  if (redis) {
    try {
      await redis.del(`repoguard:session:${sessionId}`);
    } catch {
      // ignore
    }
  }
  inMemoryStore.delete(sessionId);
}
