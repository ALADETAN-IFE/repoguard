import Redis from "ioredis";
import logger from "../utils/logger";

const REDIS_URL = process.env.REDIS_URL;
let redis: Redis | null = null;

if (REDIS_URL) {
  redis = new Redis(REDIS_URL, {
    maxRetriesPerRequest: null,
    enableReadyCheck: true,
  });
  redis.on("connect", () => logger.info("[redis] Connected to Redis"));
  redis.on("error", (err) =>
    logger.error(`[redis] Connection error: ${err.message}`),
  );
} else {
  logger.info("[redis] REDIS_URL not configured. Using in-memory fallback.");
}

export { redis };
