import type { Request } from "express";

/**
 * Extracts the real client IP from a request.
 *
 * Railway (and most reverse proxies) append IPs to x-forwarded-for as:
 *   client-ip, proxy1-ip, proxy2-ip
 *
 * The leftmost value is always the original client IP.
 * req.ip with trust proxy can return the wrong value when there are
 * multiple hops in the chain.
 */
export function getClientIp(req: Request): string {
  const forwarded = req.headers["x-forwarded-for"];

  if (forwarded) {
    const ips = Array.isArray(forwarded) ? forwarded[0] : forwarded;

    // Take the first (leftmost) IP — that's the real client
    const clientIp = ips.split(",")[0]?.trim();
    if (clientIp) return clientIp;
  }

  // Fallback chain
  return (
    (req.headers["x-real-ip"] as string | undefined) ??
    req.socket.remoteAddress ??
    "unknown"
  );
}
