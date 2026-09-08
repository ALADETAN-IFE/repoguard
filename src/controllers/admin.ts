import { type Request, type Response } from "express";
import os from "os";
import { Installation, Checkpoint, Scan, Finding } from "../models";
import { githubApp } from "../config/githubApp";
import { normaliseOctokit } from "../utils/normaliseOctokit";
import { scanRepoList } from "../webhooks/installation";
import { pendingWriteCount } from "../utils/writeQueue";
import { logAuditEvent, getRecentAuditLogs } from "../utils/auditLogger";
import logger from "../utils/logger";

export interface TenantSummary {
  id: string;
  installationId: number;
  owner: string;
  email: string | null;
  installedAt: string;
  uninstalledAt: string | null;
  isActive: boolean;
  marketplacePlan: string | null;
  billingCycle: "monthly" | "yearly" | null;
  onFreeTrial: boolean;
  freeTrialEndsOn: string | null;
  totalScans: number;
  unresolvedThreats: number;
}

export interface CheckpointSummary {
  id: string;
  installationKey: string;
  owner: string;
  totalCount: number;
  scannedCount: number;
  isComplete: boolean;
  updatedAt: string;
  startedAt: string;
}

/**
 * GET /api/admin/overview
 * Comprehensive dashboard metrics for administrators:
 * - Server telemetry & GitHub rate limit
 * - Multi-tenant installation directory
 * - Checkpoint engine status
 * - Marketplace & MRR analytics
 * - Recent audit logs
 */
export async function getAdminOverview(
  _req: Request,
  res: Response,
): Promise<void> {
  try {
    // 1. Telemetry
    const memUsage = process.memoryUsage();
    const totalMem = os.totalmem();
    const freeMem = os.freemem();

    let githubRateLimit = {
      limit: 5000,
      remaining: 5000,
      reset: Math.floor(Date.now() / 1000) + 3600,
      used: 0,
    };

    try {
      const { data } = await githubApp.octokit.request("GET /rate_limit");
      githubRateLimit = {
        limit: data.rate.limit,
        remaining: data.rate.remaining,
        reset: data.rate.reset,
        used: data.rate.used,
      };
    } catch {
      // ignore rate limit lookup errors if offline
    }

    const telemetry = {
      nodeVersion: process.version,
      platform: `${os.platform()} (${os.arch()})`,
      uptimeSeconds: Math.floor(process.uptime()),
      cpuCount: os.cpus().length,
      loadAvg: os.loadavg(),
      memory: {
        rssMb: Math.round(memUsage.rss / 1024 / 1024),
        heapUsedMb: Math.round(memUsage.heapUsed / 1024 / 1024),
        heapTotalMb: Math.round(memUsage.heapTotal / 1024 / 1024),
        systemFreeMb: Math.round(freeMem / 1024 / 1024),
        systemTotalMb: Math.round(totalMem / 1024 / 1024),
      },
      githubRateLimit,
    };

    // 2. Tenants & Installations
    const rawInstallations = await Installation.find()
      .sort({ createdAt: -1 })
      .lean();
    const tenants: TenantSummary[] = await Promise.all(
      rawInstallations.map(async (inst) => {
        const [totalScans, unresolvedThreats] = await Promise.all([
          Scan.countDocuments({ owner: new RegExp(`^${inst.owner}$`, "i") }),
          Finding.countDocuments({
            owner: new RegExp(`^${inst.owner}$`, "i"),
            status: "unresolved",
          }),
        ]);

        let resolvedEmail = inst.email ? String(inst.email) : null;
        if (!resolvedEmail) {
          const sameOwner = rawInstallations.find(
            (i) =>
              i.owner.toLowerCase() === inst.owner.toLowerCase() && i.email,
          );
          if (sameOwner?.email) {
            resolvedEmail = String(sameOwner.email);
          }
        }

        return {
          id: String(inst._id),
          installationId: inst.installationId,
          owner: String(inst.owner),
          email: resolvedEmail,
          installedAt:
            inst.installedAt instanceof Date
              ? inst.installedAt.toISOString()
              : String(inst.installedAt ?? ""),
          uninstalledAt:
            inst.uninstalledAt instanceof Date
              ? inst.uninstalledAt.toISOString()
              : inst.uninstalledAt
                ? String(inst.uninstalledAt)
                : null,
          isActive: !inst.uninstalledAt,
          marketplacePlan: String(inst.marketplacePlan || "free"),
          billingCycle: inst.billingCycle ?? null,
          onFreeTrial: Boolean(inst.onFreeTrial),
          freeTrialEndsOn:
            inst.freeTrialEndsOn instanceof Date
              ? inst.freeTrialEndsOn.toISOString()
              : inst.freeTrialEndsOn
                ? String(inst.freeTrialEndsOn)
                : null,
          totalScans,
          unresolvedThreats,
        };
      }),
    );

    // 3. Checkpoints & Batch Scanning
    const rawCheckpoints = await Checkpoint.find()
      .sort({ updatedAt: -1 })
      .limit(15)
      .lean();
    const checkpoints: CheckpointSummary[] = rawCheckpoints.map((cp) => ({
      id: String(cp._id),
      installationKey: String(cp.installationKey),
      owner: String(cp.owner),
      totalCount: cp.totalRepos?.length || 0,
      scannedCount: cp.scanned?.length || 0,
      isComplete: (cp.scanned?.length || 0) >= (cp.totalRepos?.length || 0),
      updatedAt:
        cp.updatedAt instanceof Date
          ? cp.updatedAt.toISOString()
          : cp.updatedAt
            ? String(cp.updatedAt)
            : new Date().toISOString(),
      startedAt:
        cp.startedAt instanceof Date
          ? cp.startedAt.toISOString()
          : cp.startedAt
            ? String(cp.startedAt)
            : new Date().toISOString(),
    }));

    // 4. Subscriptions & MRR Analytics
    const activeTenants = tenants.filter((t) => t.isActive);
    const planCounts = {
      free: activeTenants.filter(
        (t) => !t.marketplacePlan || t.marketplacePlan === "free",
      ).length,
      pro: activeTenants.filter((t) => t.marketplacePlan === "pro").length,
      enterprise: activeTenants.filter(
        (t) => t.marketplacePlan === "enterprise",
      ).length,
      trials: activeTenants.filter((t) => t.onFreeTrial).length,
      monthly: activeTenants.filter((t) => t.billingCycle === "monthly").length,
      yearly: activeTenants.filter((t) => t.billingCycle === "yearly").length,
    };

    const estimatedMrr = planCounts.pro * 29 + planCounts.enterprise * 199;

    const subscriptions = {
      ...planCounts,
      estimatedMrr,
      totalTenants: rawInstallations.length,
      activeTenants: activeTenants.length,
    };

    // 5. Queue & Workers
    const queue = {
      pendingWrites: pendingWriteCount(),
      activeWorkers: 2,
    };

    // 6. Recent Audit Logs
    const auditLogs = getRecentAuditLogs(30);

    res.json({
      telemetry,
      tenants,
      checkpoints,
      subscriptions,
      queue,
      auditLogs,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`[admin] getAdminOverview error: ${message}`);
    res.status(500).json({ error: "Failed to generate admin overview" });
  }
}

/**
 * GET /api/admin/audit-logs
 */
export function getAdminAuditLogs(req: Request, res: Response): void {
  const limitStr =
    typeof req.query.limit === "string" ? req.query.limit : undefined;
  const limit = limitStr ? parseInt(limitStr, 10) : 50;
  const filter =
    typeof req.query.filter === "string" ? req.query.filter : undefined;
  res.json({ logs: getRecentAuditLogs(limit, filter) });
}

/**
 * POST /api/admin/installations/:owner/rescan
 * Trigger a background rescan for a specific tenant installation
 */
export async function rescanTenant(req: Request, res: Response): Promise<void> {
  const rawOwner = req.params.owner;
  const owner = typeof rawOwner === "string" ? rawOwner.trim() : "";
  if (!owner) {
    res.status(400).json({ error: "Missing tenant owner parameter" });
    return;
  }

  try {
    const installation = await Installation.findOne({
      owner: new RegExp(`^${owner}$`, "i"),
      uninstalledAt: null,
    }).lean();

    if (!installation) {
      res
        .status(404)
        .json({ error: `No active installation found for ${owner}` });
      return;
    }

    logAuditEvent({
      event: "admin.rescan_tenant",
      source: "admin_console",
      owner,
      status: "info",
      detail: `Administrator initiated single-tenant rescan for ${owner}.`,
    });

    // Fire and forget
    void (async (): Promise<void> => {
      try {
        const octokit = await githubApp.getInstallationOctokit(
          installation.installationId,
        );
        const client = normaliseOctokit(octokit);
        const { data: repos } = await client.request(
          "GET /installation/repositories",
          {
            per_page: 100,
          },
        );

        const repoList = repos.repositories.map(
          (r: { full_name: string; name: string }) => ({
            full_name: r.full_name,
            name: r.name,
          }),
        );

        const installationKey = `${installation.owner}-${installation.installationId}`;
        await scanRepoList(
          client,
          installationKey,
          installation.owner,
          repoList,
        );

        logAuditEvent({
          event: "scan.completed",
          source: "engine",
          owner,
          status: "success",
          detail: `Single-tenant rescan completed for ${owner} (${repoList.length} repositories).`,
        });
      } catch (subErr) {
        const msg = subErr instanceof Error ? subErr.message : String(subErr);
        logger.error(`[admin] rescan error for ${owner}: ${msg}`);
        logAuditEvent({
          event: "scan.failed",
          source: "engine",
          owner,
          status: "error",
          detail: `Single-tenant rescan failed for ${owner}: ${msg}`,
        });
      }
    })();

    res.json({ message: `Rescan initiated for ${owner}` });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`[admin] rescanTenant error: ${message}`);
    res.status(500).json({ error: "Failed to trigger tenant rescan" });
  }
}
