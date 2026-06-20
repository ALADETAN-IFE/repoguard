import mongoose from "mongoose";
import logger from "./logger";
import { redis } from "../config/redis";
import { Checkpoint, Scan, Finding } from "../models";

export type QueuedWrite =
  | {
      type: "MARK_SCANNED";
      data: {
        installationKey: string;
        repoFullName: string;
      };
    }
  | {
      type: "CREATE_SCAN";
      data: {
        scanId: string;
        installationId: number | undefined;
        owner: string;
        repo: string;
        status: string;
        trigger: string;
        startedAt: string;
      };
    }
  | {
      type: "INSERT_FINDINGS";
      data: {
        findings: Array<{
          scanId: string;
          installationId: number | undefined;
          owner: string;
          repo: string;
          rule: string;
          severity: string;
          message: string;
          file: string | null;
          detectedAt: string;
        }>;
      };
    }
  | {
      type: "COMPLETE_SCAN";
      data: {
        scanId: string;
        findingsCount: number;
        completedAt: string;
      };
    };

export interface SerializedWrite {
  label: string;
  write: QueuedWrite;
  attempts: number;
}

const MAX_ATTEMPTS = 5;
const BASE_DELAY_MS = 500;
const REDIS_QUEUE_KEY = "repoguard:write_queue";

// ─── In-memory fallback queue ──────────────────────────────────────────────────
const queue: SerializedWrite[] = [];
let draining = false;

// ─── Internal helper: execute specific model operations with full Type Safety ───
async function executeWrite(write: QueuedWrite): Promise<void> {
  switch (write.type) {
    case "MARK_SCANNED":
      await Checkpoint.updateOne(
        { installationKey: write.data.installationKey },
        { $addToSet: { scanned: write.data.repoFullName } }
      );
      break;

    case "CREATE_SCAN":
      await Scan.create({
        _id: new mongoose.Types.ObjectId(write.data.scanId),
        installationId: write.data.installationId,
        owner: write.data.owner,
        repo: write.data.repo,
        status: write.data.status,
        trigger: write.data.trigger,
        startedAt: new Date(write.data.startedAt),
      });
      break;

    case "INSERT_FINDINGS":
      await Finding.insertMany(
        write.data.findings.map((f) => ({
          scanId: new mongoose.Types.ObjectId(f.scanId),
          installationId: f.installationId,
          owner: f.owner,
          repo: f.repo,
          rule: f.rule,
          severity: f.severity,
          message: f.message,
          file: f.file,
          detectedAt: new Date(f.detectedAt),
        }))
      );
      break;

    case "COMPLETE_SCAN":
      await Scan.updateOne(
        { _id: new mongoose.Types.ObjectId(write.data.scanId) },
        {
          $set: {
            status: "complete",
            completedAt: new Date(write.data.completedAt),
            findingsCount: write.data.findingsCount,
          },
        }
      );
      break;

    default: {
      const exhaustiveCheck: never = write;
      throw new Error(`Unhandled write type: ${JSON.stringify(exhaustiveCheck)}`);
    }
  }
}

// ─── Public: enqueue a write ──────────────────────────────────────────────────

/**
 * Attempt a MongoDB write immediately. If it fails (network / DB down),
 * push it onto the retry queue (Redis or in-memory) instead of throwing.
 * The caller never sees an exception — progress is never lost, and the server stays up.
 *
 * @param label  Short description used in log messages.
 * @param write  The strongly-typed write operation to run.
 */
export async function safeWrite(
  label: string,
  write: QueuedWrite
): Promise<void> {
  try {
    await executeWrite(write);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.warn(`[writeQueue] "${label}" failed — queuing for retry. Reason: ${message}`);
    
    const entry: SerializedWrite = {
      label,
      write,
      attempts: 1,
    };

    try {
      if (redis) {
        await redis.lpush(REDIS_QUEUE_KEY, JSON.stringify(entry));
        logger.info(`[writeQueue] Enqueued "${label}" to Redis`);
      } else {
        queue.push(entry);
        logger.info(`[writeQueue] Enqueued "${label}" to in-memory queue`);
      }
    } catch (queueErr) {
      const qMsg = queueErr instanceof Error ? queueErr.message : String(queueErr);
      logger.error(`[writeQueue] Failed to write to Redis queue, falling back to memory. Error: ${qMsg}`);
      queue.push(entry);
    }

    // Trigger an asynchronous drain in case the connection is already active/restored
    void drainQueue();
  }
}

// ─── Internal: drain the queue ────────────────────────────────────────────────

async function drainQueue(): Promise<void> {
  if (draining) return;
  draining = true;

  try {
    // Snapshot the current queue contents so we don't infinitely loop on offline database
    const snapshot: SerializedWrite[] = [];

    if (redis) {
      try {
        let raw = await redis.rpop(REDIS_QUEUE_KEY);
        while (raw) {
          snapshot.push(JSON.parse(raw) as SerializedWrite);
          raw = await redis.rpop(REDIS_QUEUE_KEY);
        }
      } catch (redisErr) {
        const rMsg = redisErr instanceof Error ? redisErr.message : String(redisErr);
        logger.error(`[writeQueue] Redis drain snapshot failed: ${rMsg}`);
      }
    } else {
      snapshot.push(...queue.splice(0, queue.length));
    }

    if (snapshot.length === 0) {
      draining = false;
      return;
    }

    logger.info(`[writeQueue] Draining ${snapshot.length} queued write(s)…`);

    for (const entry of snapshot) {
      // Add backoff delay based on attempts
      const delay = Math.min(
        BASE_DELAY_MS * 2 ** (entry.attempts - 1) + Math.random() * 200,
        30_000,
      );
      await new Promise((r) => setTimeout(r, delay));

      try {
        await executeWrite(entry.write);
        logger.info(`[writeQueue] ✓ Replayed "${entry.label}" successfully`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);

        if (entry.attempts >= MAX_ATTEMPTS) {
          logger.error(
            `[writeQueue] ✗ Dropping "${entry.label}" after ${entry.attempts} attempts. Reason: ${message}`,
          );
        } else {
          logger.warn(
            `[writeQueue] Retry ${entry.attempts} failed for "${entry.label}" — re-queueing. Reason: ${message}`,
          );
          entry.attempts++;

          try {
            if (redis) {
              await redis.lpush(REDIS_QUEUE_KEY, JSON.stringify(entry));
            } else {
              queue.push(entry);
            }
          } catch {
            logger.error(`[writeQueue] Failed to re-queue "${entry.label}", falling back to memory.`);
            queue.push(entry);
          }
        }
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`[writeQueue] Unexpected error during drain: ${message}`);
  } finally {
    draining = false;
  }
}

// ─── Trigger drain on reconnect ───────────────────────────────────────────────

mongoose.connection.on("reconnected", () => {
  logger.info(`[writeQueue] MongoDB reconnected — checking for queued writes`);
  void drainQueue();
});

// ─── Expose queue length for health checks / tests ───────────────────────────

export async function pendingWriteCount(): Promise<number> {
  let count = queue.length;
  if (redis) {
    try {
      const len = await redis.llen(REDIS_QUEUE_KEY);
      count += len;
    } catch {
      // ignore
    }
  }
  return count;
}
