import mongoose from "mongoose";
import logger from "../utils/logger";

const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  logger.error("Missing required environment variable: MONGODB_URI");
  process.exit(1);
}

export async function connectDatabase(): Promise<void> {
  try {
    await mongoose.connect(MONGODB_URI!, {
      serverSelectionTimeoutMS: 5000,
    });
    logger.info("[db] Connected to MongoDB");
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`[db] Failed to connect to MongoDB: ${message}`);
    process.exit(1);
  }
}

mongoose.connection.on("disconnected", () => {
  logger.warn("[db] MongoDB disconnected — attempting reconnect...");
});

mongoose.connection.on("reconnected", () => {
  logger.info("[db] MongoDB reconnected");
});

export { mongoose };