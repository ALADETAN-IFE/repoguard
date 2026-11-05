import type { Request } from "express";
import net from "net";

/**
 * Extracts the real client IP from a request safely.
 * When Express has "trust proxy" enabled (as in src/index.ts), req.ip
 * returns the trusted client address according to proxy hops.
 */
export function getClientIp(req: Request): string {
  // 1. Prefer Express's trusted req.ip when available
  if (req.ip && net.isIP(req.ip)) {
    return req.ip;
  }

  // 2. Check x-real-ip
  const realIp = req.headers["x-real-ip"];
  if (typeof realIp === "string" && net.isIP(realIp.trim())) {
    return realIp.trim();
  }

  // 3. Fallback: Parse x-forwarded-for and ensure it is a valid IP address
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    const rawIps = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    const ips = rawIps.split(",").map((s) => s.trim());
    for (const ip of ips) {
      if (net.isIP(ip)) {
        return ip;
      }
    }
  }

  // 4. Socket remote address fallback
  if (req.socket?.remoteAddress && net.isIP(req.socket.remoteAddress)) {
    return req.socket.remoteAddress;
  }

  return "unknown";
}
