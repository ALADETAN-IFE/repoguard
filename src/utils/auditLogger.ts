import crypto from "crypto";

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  event: string;
  source: string;
  owner?: string;
  repo?: string;
  status: "success" | "warning" | "error" | "info";
  detail: string;
  meta?: Record<string, unknown>;
}

const MAX_ENTRIES = 100;
const ringBuffer: AuditLogEntry[] = [];

/**
 * Record an audit or webhook event in the system audit stream
 */
export function logAuditEvent(
  entry: Omit<AuditLogEntry, "id" | "timestamp"> & {
    timestamp?: string;
    id?: string;
  },
): AuditLogEntry {
  const item: AuditLogEntry = {
    id: entry.id || crypto.randomUUID(),
    timestamp: entry.timestamp || new Date().toISOString(),
    event: entry.event,
    source: entry.source,
    owner: entry.owner,
    repo: entry.repo,
    status: entry.status,
    detail: entry.detail,
    meta: entry.meta,
  };

  ringBuffer.unshift(item);
  if (ringBuffer.length > MAX_ENTRIES) {
    ringBuffer.pop();
  }

  return item;
}

/**
 * Retrieve recent audit logs with optional limit and filtering
 */
export function getRecentAuditLogs(
  limit = 50,
  eventFilter?: string,
): AuditLogEntry[] {
  let logs = ringBuffer;
  if (eventFilter) {
    const q = eventFilter.toLowerCase();
    logs = logs.filter(
      (l) =>
        l.event.toLowerCase().includes(q) ||
        l.source.toLowerCase().includes(q) ||
        (l.owner && l.owner.toLowerCase().includes(q)) ||
        (l.repo && l.repo.toLowerCase().includes(q)),
    );
  }
  return logs.slice(0, limit);
}

// Pre-populate with initial system boot event
logAuditEvent({
  event: "system.boot",
  source: "core",
  status: "info",
  detail: "RepoGuard engine initialized and ready to receive GitHub webhooks.",
});
