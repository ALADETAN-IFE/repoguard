import type { App } from "@octokit/app";
import { scanFileContent } from "../scanner";
import { openFixPR } from "../pullRequest";
import { Installation, Checkpoint, Scan, Finding as FindingModel } from "../models";
import logger from "../utils/logger";
import { safeWrite } from "../utils/writeQueue";
import type { Finding, WebhookEvent, InstallationEventPayload, OctokitClient } from "../types/index";
import { Types } from "mongoose";
import { sendAlert } from "../alerts";

interface RepoFile {
  path: string;
  content: string;
}

// ─── Checkpoint helpers (MongoDB) ─────────────────────────────────────────────

async function initCheckpoint(
  installationKey: string,
  installationId: number,
  owner: string,
  allRepos: string[],
): Promise<void> {
  await Checkpoint.findOneAndUpdate(
    { installationKey },
    {
      $setOnInsert: {
        installationKey,
        installationId,
        owner,
        totalRepos: allRepos,
        scanned: [],
        startedAt: new Date(),
      },
    },
    { upsert: true, new: false },
  );

  // If it already existed but totalRepos was empty, patch it
  await Checkpoint.updateOne(
    { installationKey, totalRepos: { $size: 0 } },
    { $set: { totalRepos: allRepos, installationId, owner } },
  );

  logger.info(
    `[checkpoint] Initialised for ${installationKey} — ${allRepos.length} repos`,
  );
}

async function markScanned(
  installationKey: string,
  repoFullName: string,
): Promise<void> {
  await safeWrite(`markScanned:${repoFullName}`, () =>
    Checkpoint.updateOne(
      { installationKey },
      { $addToSet: { scanned: repoFullName } },
    ).then(() => undefined),
  );
}

export async function clearCheckpoint(installationKey: string): Promise<void> {
  await Checkpoint.deleteOne({ installationKey });
  logger.info(`[checkpoint] Cleared for ${installationKey}`);
}

export async function patchCheckpointTotalRepos(
  installationKey: string,
  totalRepos: string[],
): Promise<void> {
  await Checkpoint.updateOne(
    { installationKey },
    { $set: { totalRepos } },
    { upsert: true },
  );
}

export async function getIncompleteScans(): Promise<
  Array<{
    key: string;
    installationId: number;
    owner: string;
    totalRepos: string[] | undefined;
    scanned: string[];
  }>
> {
  const checkpoints = await Checkpoint.find({
    $expr: { $lt: [{ $size: "$scanned" }, { $size: "$totalRepos" }] },
  }).lean();

  return checkpoints.map((c) => ({
    key: c.installationKey,
    installationId: c.installationId,
    owner: c.owner,
    totalRepos: c.totalRepos,
    scanned: c.scanned,
  }));
}

// ─── Core scan logic ──────────────────────────────────────────────────────────

export async function scanRepoList(
  client: OctokitClient,
  installationKey: string,
  owner: string,
  repos: Array<{ full_name: string; name: string }>,
): Promise<void> {
  const checkpoint = await Checkpoint.findOne({ installationKey }).lean();
  const alreadyScanned = checkpoint?.scanned ?? [];

  const pending = repos.filter((r) => !alreadyScanned.includes(r.full_name));
  const alreadyDone = repos.length - pending.length;

  if (alreadyDone > 0) {
    logger.info(
      `[installation] Resuming — skipping ${alreadyDone} already-scanned ${alreadyDone > 1 ? "repos" : "repo"}`,
    );
  }

  for (const repo of pending) {
    logger.info(`[installation] Scanning: ${repo.full_name}`);

    // Create a scan record (queued on failure so loop continues)
    let scanId: unknown = null;
    await safeWrite(`Scan.create:${repo.full_name}`, async () => {
      const scan = await Scan.create({
        installationId: checkpoint?.installationId,
        owner,
        repo: repo.name,
        status: "in_progress",
        trigger: "installation",
        startedAt: new Date(),
      });
      scanId = scan._id;
    });

    try {
      const findings = await scanFullRepo(client, owner, repo.name);

      // Persist findings
      if (findings.length > 0) {
        await safeWrite(`FindingModel.insertMany:${repo.full_name}`, () =>
          FindingModel.insertMany(
            findings.map((f) => ({
              scanId,
              installationId: checkpoint?.installationId,
              owner,
              repo: repo.name,
              rule: f.rule,
              severity: f.severity,
              message: f.message,
              file: f.file,
              detectedAt: new Date(),
            })),
          ).then(() => undefined),
        );
      }

      // Update scan record
      await safeWrite(`Scan.complete:${repo.full_name}`, () =>
        Scan.updateOne(
          { _id: scanId as Types.ObjectId },
          {
            $set: {
              status: "complete",
              completedAt: new Date(),
              findingsCount: findings.length,
            },
          },
        ).then(() => undefined),
      );

      if (findings.length === 0) {
        logger.info(`[installation] CLEAN — ${repo.full_name}`);

        const { data: issue } = await client.request(
          "POST /repos/{owner}/{repo}/issues",
          {
            owner,
            repo: repo.name,
            title: "✅ RepoGuard: Initial scan complete — no issues found",
            body: [
              "## RepoGuard Initial Scan",
              "",
              "RepoGuard scanned your entire codebase on installation and found **no security issues**.",
              "",
              "From this point on, every push will be automatically scanned.",
              "",
              "---",
              "_Closed automatically — no action required._",
            ].join("\n"),
          },
        );

        await client.request(
          "PATCH /repos/{owner}/{repo}/issues/{issue_number}",
          {
            owner,
            repo: repo.name,
            issue_number: issue.number,
            state: "closed",
          },
        );
      } else {
        logger.warn(
          `[installation] ${findings.length} finding${findings.length > 1 ? "s" : ""} in ${repo.full_name} — opening fix PR`,
        );
        await openFixPR(client, { owner, repo: repo.name, findings });
      }

      await markScanned(installationKey, repo.full_name);
      logger.info(`[installation] ✓ ${repo.full_name} checkpointed`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`[installation] Error scanning ${repo.full_name}: ${message}`);

      await Scan.updateOne(
        { _id: scanId as Types.ObjectId },
        { $set: { status: "failed", completedAt: new Date() } },
      ).catch((dbErr: unknown) => {
        const msg = dbErr instanceof Error ? dbErr.message : String(dbErr);
        logger.warn(`[installation] Could not update scan status to failed: ${msg}`);
      });
      // Don't mark as scanned — will retry on resume
    }
  }

  // Clear checkpoint if all done
  const updated = await Checkpoint.findOne({ installationKey }).lean();
  if (
    updated &&
    updated.totalRepos.length > 0 &&
    updated.scanned.length >= updated.totalRepos.length
  ) {
    await clearCheckpoint(installationKey);
    logger.info(`[installation] All repos scanned for ${owner} — checkpoint cleared`);
  }
}

// ─── Webhook handler ──────────────────────────────────────────────────────────

export function handleInstallation(
  _app: App,
): (event: WebhookEvent<InstallationEventPayload>) => Promise<void> {
  return async ({ octokit, payload }) => {
    const action = payload.action;

    // App uninstalled — clear checkpoint and mark installation
    if (action === "deleted") {
      const { installation } = payload as {
        installation: { id: number; account: { login?: string; name?: string } };
      };
      const owner = installation.account.login ?? installation.account.name ?? "unknown";
      const installationKey = `${owner}-${installation.id}`;

      await clearCheckpoint(installationKey);
      await Installation.updateOne(
        { installationId: installation.id },
        { $set: { uninstalledAt: new Date() } },
      );

      await sendAlert({
        owner,
        repo: owner,  // links to owner profile
        ref: "N/A",
        pusher: owner,
        headSha: null,
        findings: [{
          rule: "app-uninstalled",
          severity: "high",
          message: `RepoGuard was uninstalled by ${owner} — repositories are no longer protected`,
          file: null,
        }],
        context: "installation",
      });

      logger.info(`[installation] App uninstalled by ${owner} — records updated`);
      return;
    }

    if (action !== "created") return;

    const { installation, repositories } = payload;
    const owner = installation.account.login ?? installation.account.name ?? "unknown";
    const installationKey = `${owner}-${installation.id}`;
    const allRepos = repositories ?? [];

    const email = installation.account?.email ?? null;

    // Persist the installation record
    await Installation.findOneAndUpdate(
      { installationId: installation.id },
      {
        $setOnInsert: {
          installationId: installation.id,
          owner,
          email,
          installedAt: new Date(),
          uninstalledAt: null,
        },
      },
      { upsert: true },
    );

    await sendAlert({
      owner,
      repo: allRepos.length === 1 ? allRepos[0].name : "*",
      ref: "N/A",
      pusher: owner,
      headSha: null,
      findings: [{
        rule: "app-installed",
        severity: "low",
        message: `RepoGuard installed by ${owner} on ${allRepos.length} repo${allRepos.length > 1 ? "s" : ""} — scanning in progress`,
        file: null,
      }],
      context: "installation",
    });

    logger.info(
      `[installation] App installed by ${owner} on ${allRepos.length} ${allRepos.length > 1 ? "repos" : "repo"}`,
    );

    const client = normaliseOctokit(octokit);

    await initCheckpoint(
      installationKey,
      installation.id,
      owner,
      allRepos.map((r) => r.full_name),
    );

    await scanRepoList(client, installationKey, owner, allRepos);
  };
}

export function handleInstallationRepositories(
  _app: App,
): (event: WebhookEvent<any>) => Promise<void> {
  return async ({ octokit, payload }) => {
    const action = payload.action;

    if (action !== "added") return;

    const { installation, repositories_added } = payload as {
      installation: { id: number; account: { login?: string; name?: string } };
      repositories_added: Array<{ full_name: string; name: string }>;
    };

    const owner = installation.account.login ?? installation.account.name ?? "unknown";
    const installationKey = `${owner}-${installation.id}`;

    logger.info(
      `[installation] ${repositories_added.length} repo(s) added by ${owner} — scanning`,
    );

    const client = normaliseOctokit(octokit);

    // Get existing repos already in checkpoint
    const existing = await Checkpoint.findOne({ installationKey }).lean();
    const currentTotal = existing?.totalRepos ?? [];

    const updatedTotal = [
      ...currentTotal,
      ...repositories_added.map((r) => r.full_name),
    ];

    // ✅ Use initCheckpoint so installationId is always set on the checkpoint
    await initCheckpoint(
      installationKey,
      installation.id,
      owner,
      updatedTotal,
    );

    // Update the installation record
    await Installation.findOneAndUpdate(
      { installationId: installation.id },
      {
        $set: { owner },
        $setOnInsert: {
          installationId: installation.id,
          installedAt: new Date(),
          uninstalledAt: null,
        },
      },
      { upsert: true },
    );

    await sendAlert({
      owner,
      repo: owner,
      ref: "N/A",
      pusher: owner,
      headSha: null,
      findings: [{
        rule: "app-repositories-added",
        severity: "low",
        message: `${repositories_added.length} repo${repositories_added.length > 1 ? "s" : ""} added to RepoGuard protection`,
        file: null,
      }],
      context: "installation",
      repoList: repositories_added.map(r => r.name),
    });

    // Scan only the newly added repos
    await scanRepoList(client, installationKey, owner, repositories_added);
  };
}

// ─── Normalise the octokit client ────────────────────────────────────────────

function normaliseOctokit(octokit: unknown): OctokitClient {
  if (octokit && typeof octokit === "object") {
    if ("octokit" in octokit && octokit.octokit) {
      return octokit.octokit as OctokitClient;
    }
  }
  return octokit as OctokitClient;
}

// ─── Scan every file in the repo ─────────────────────────────────────────────

async function scanFullRepo(
  client: OctokitClient,
  owner: string,
  repo: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];

  const { data: tree } = await client.request(
    "GET /repos/{owner}/{repo}/git/trees/{tree_sha}",
    { owner, repo, tree_sha: "HEAD", recursive: "1" },
  );

  const files: RepoFile[] = [];

  for (const item of tree.tree) {
    if (item.type !== "blob" || !item.path) continue;
    if (isBinaryPath(item.path)) continue;

    try {
      const { data } = await client.request(
        "GET /repos/{owner}/{repo}/contents/{path}",
        { owner, repo, path: item.path },
      );

      if (Array.isArray(data) || data.type !== "file" || !("content" in data))
        continue;

      const content = Buffer.from(data.content || "", "base64").toString("utf8");
      files.push({ path: item.path, content });
    } catch {
      // File deleted or inaccessible — skip
    }
  }

  for (const file of files) {
    findings.push(...scanFileContent(file.content, file.path));
  }

  return findings;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
  ".woff", ".woff2", ".ttf", ".eot",
  ".zip", ".tar", ".gz", ".exe", ".dll", ".so",
  ".pdf", ".mp4", ".mp3",
]);

function isBinaryPath(filePath: string): boolean {
  return [...BINARY_EXTENSIONS].some((ext) =>
    filePath.toLowerCase().endsWith(ext),
  );
}