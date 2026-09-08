import mongoose from "mongoose";
import { redis } from "../config/redis";
import { Installation, Scan } from "../models";
import { pendingWriteCount } from "./writeQueue";

export type CheckStatus = "ok" | "connected" | "error" | "disconnected" | "skipped";

export interface MongoHealthCheck {
  status: CheckStatus;
  latencyMs?: number;
  message?: string;
}

export interface RedisHealthCheck {
  status: CheckStatus;
  queueLength?: number;
  pendingWrites?: number;
  message?: string;
}

export interface HealthReport {
  status: "ok" | "healthy" | "degraded";
  app: string;
  version: string;
  uptime?: number;
  totalInstallations?: number;
  totalScans?: number;
  activeWorkers?: number;
  checks: {
    mongodb: MongoHealthCheck;
    redis: RedisHealthCheck;
  };
}

async function checkMongoDB(): Promise<MongoHealthCheck> {
  if (Number(mongoose.connection.readyState) !== 1) {
    return {
      status: "disconnected",
      latencyMs: 0,
      message: `MongoDB not connected (readyState=${mongoose.connection.readyState})`,
    };
  }

  try {
    const start = Date.now();
    await mongoose.connection.db?.admin().ping();
    const latencyMs = Math.max(1, Date.now() - start);
    return { status: "connected", latencyMs };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { status: "error", latencyMs: 0, message };
  }
}

async function checkRedis(): Promise<RedisHealthCheck> {
  const pendingCount = await pendingWriteCount().catch(() => 0);

  if (!process.env.REDIS_URL && !redis) {
    return {
      status: "connected",
      queueLength: pendingCount,
      pendingWrites: pendingCount,
    };
  }

  if (!redis) {
    return {
      status: "disconnected",
      queueLength: pendingCount,
      pendingWrites: pendingCount,
      message: "REDIS_URL configured but client unavailable",
    };
  }

  try {
    const pong = await redis.ping();
    if (pong !== "PONG") {
      return {
        status: "error",
        queueLength: pendingCount,
        pendingWrites: pendingCount,
        message: `Unexpected ping response: ${String(pong)}`,
      };
    }
    const qLen = await redis.llen("repoguard:write_queue").catch(() => 0);
    return {
      status: "connected",
      queueLength: qLen + pendingCount,
      pendingWrites: pendingCount,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      status: "error",
      queueLength: pendingCount,
      pendingWrites: pendingCount,
      message,
    };
  }
}

export async function getHealthReport(): Promise<HealthReport> {
  const [mongodb, redisCheck, totalInstallations, totalScans] = await Promise.all([
    checkMongoDB(),
    checkRedis(),
    Installation.countDocuments({ uninstalledAt: null }).catch(() => 0),
    Scan.countDocuments().catch(() => 0),
  ]);

  const isHealthy =
    (mongodb.status === "ok" || mongodb.status === "connected") &&
    (redisCheck.status === "ok" ||
      redisCheck.status === "connected" ||
      redisCheck.status === "skipped");

  return {
    status: isHealthy ? "ok" : "degraded",
    app: "RepoGuard-IfeCodes",
    version: "1.0.0",
    uptime: Math.floor(process.uptime()),
    totalInstallations,
    totalScans,
    activeWorkers: 1,
    checks: {
      mongodb,
      redis: redisCheck,
    },
  };
}

export function getHealthStatusCode(report: HealthReport): number {
  return report.status === "ok" || report.status === "healthy" ? 200 : 503;
}

