import mongoose from "mongoose";
import logger from "./logger";

type WriteOperation = () => Promise<void>;

interface QueueEntry {
  label: string;      // human-readable name for logs
  op: WriteOperation;
  attempts: number;
}

const MAX_ATTEMPTS = 5;
const BASE_DELAY_MS = 500;

// ─── In-memory queue ──────────────────────────────────────────────────────────

const queue: QueueEntry[] = [];
let draining = false;

// ─── Public: enqueue a write ──────────────────────────────────────────────────

/**
 * Attempt a MongoDB write immediately. If it fails (network / DB down),
 * push it onto the retry queue instead of throwing.  The caller never
 * sees an exception — progress is never lost, and the server stays up.
 *
 * @param label  Short description used in log messages.
 * @param op     Async function that performs the Mongoose write.
 */
export async function safeWrite(label: string, op: WriteOperation): Promise<void> {
  try {
    await op();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.warn(`[writeQueue] "${label}" failed — queuing for retry. Reason: ${message}`);
    queue.push({ label, op, attempts: 1 });
  }
}

// ─── Internal: drain the queue ────────────────────────────────────────────────

async function drainQueue(): Promise<void> {
  if (draining || queue.length === 0) return;
  draining = true;

  logger.info(`[writeQueue] Draining ${queue.length} queued write(s)…`);

  // Snapshot current entries — new failures during drain go to the back
  const snapshot = queue.splice(0, queue.length);

  for (const entry of snapshot) {
    const delay = Math.min(
      BASE_DELAY_MS * 2 ** (entry.attempts - 1) + Math.random() * 200,
      30_000,
    );

    await new Promise((r) => setTimeout(r, delay));

    try {
      await entry.op();
      logger.info(`[writeQueue] ✓ Replayed "${entry.label}" (attempt ${entry.attempts})`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);

      if (entry.attempts >= MAX_ATTEMPTS) {
        logger.error(
          `[writeQueue] ✗ Dropping "${entry.label}" after ${entry.attempts} attempts. Reason: ${message}`,
        );
      } else {
        logger.warn(
          `[writeQueue] Retry ${entry.attempts} failed for "${entry.label}" — will retry. Reason: ${message}`,
        );
        queue.push({ ...entry, attempts: entry.attempts + 1 });
      }
    }
  }

  draining = false;

  // If new items were added during the drain, schedule another pass
  if (queue.length > 0) {
    logger.info(`[writeQueue] ${queue.length} item(s) remain — scheduling next drain`);
    void drainQueue();
  }
}

// ─── Trigger drain on reconnect ───────────────────────────────────────────────

mongoose.connection.on("reconnected", () => {
  if (queue.length > 0) {
    logger.info(`[writeQueue] MongoDB reconnected — replaying ${queue.length} queued write(s)`);
    void drainQueue();
  }
});

// ─── Expose queue length for health checks / tests ───────────────────────────

export function pendingWriteCount(): number {
  return queue.length;
}
