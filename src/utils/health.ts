import mongoose from "mongoose";
import { redis } from "../config/redis";

export type CheckStatus = "ok" | "error" | "skipped";

export interface HealthCheck {
  status: CheckStatus;
  message?: string;
}

export interface HealthReport {
  status: "ok" | "degraded";
  app: string;
  version: string;
  checks: {
    mongodb: HealthCheck;
    redis: HealthCheck;
  };
}

async function checkMongoDB(): Promise<HealthCheck> {
  if (Number(mongoose.connection.readyState) !== 1) {
    return {
      status: "error",
      message: `MongoDB not connected (readyState=${mongoose.connection.readyState})`,
    };
  }

  try {
    await mongoose.connection.db?.admin().ping();
    return { status: "ok" };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { status: "error", message };
  }
}

async function checkRedis(): Promise<HealthCheck> {
  if (!process.env.REDIS_URL) {
    return { status: "skipped", message: "REDIS_URL not configured" };
  }

  if (!redis) {
    return {
      status: "error",
      message: "REDIS_URL configured but client unavailable",
    };
  }

  try {
    const pong = await redis.ping();
    if (pong !== "PONG") {
      return {
        status: "error",
        message: `Unexpected ping response: ${String(pong)}`,
      };
    }
    return { status: "ok" };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { status: "error", message };
  }
}

export async function getHealthReport(): Promise<HealthReport> {
  const checks = {
    mongodb: await checkMongoDB(),
    redis: await checkRedis(),
  };

  const isHealthy =
    checks.mongodb.status === "ok" &&
    (checks.redis.status === "ok" || checks.redis.status === "skipped");

  return {
    status: isHealthy ? "ok" : "degraded",
    app: "RepoGuard-IfeCodes",
    version: "1.0.0",
    checks,
  };
}

export function getHealthStatusCode(report: HealthReport): number {
  return report.status === "ok" ? 200 : 503;
}
