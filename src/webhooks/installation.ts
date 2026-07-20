import type { App } from "@octokit/app";
import { scanFileContent } from "../scanner";
import { openFixPR } from "../pullRequest";
import { Installation, Checkpoint, Scan } from "../models";
import logger from "../utils/logger";
import { safeWrite } from "../utils/writeQueue";
import type {
  Finding,
  WebhookEvent,
  InstallationEventPayload,
  OctokitClient,
} from "../types/index";
import { Types } from "mongoose";
import { sendAlert } from "../alerts";
import { normaliseOctokit } from "../utils/normaliseOctokit";
import { shouldSkipPath } from "../utils/skipPaths";
import { isBinaryPath, looksLikeJavaScript } from "../utils/binaryPath";
import AdmZip from "adm-zip";

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
  await safeWrite(`markScanned:${repoFullName}`, {
    type: "MARK_SCANNED",
    data: { installationKey, repoFullName },
  });
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

// ─── Known non-retryable error messages ──────────────────────────────────────
const SKIP_ERRORS = [
  "Git Repository is empty",
  "Issues has been disabled",
  "Repository access blocked",
  "Repository was archived",
];

function isSkippableError(message: string): boolean {
  return SKIP_ERRORS.some((e) => message.includes(e));
}

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

    // Pre-generate the scan ID using Types.ObjectId to avoid race conditions
    const scanId = new Types.ObjectId();

    // Create a scan record (queued on failure so loop continues)
    await safeWrite(`Scan.create:${repo.full_name}`, {
      type: "CREATE_SCAN",
      data: {
        scanId: scanId.toHexString(),
        installationId: checkpoint?.installationId,
        owner,
        repo: repo.name,
        status: "in_progress",
        trigger: "installation",
        startedAt: new Date().toISOString(),
      },
    });

    try {
      const findings = await scanFullRepoForPush(client, owner, repo.name);

      // Persist findings
      if (findings.length > 0) {
        await safeWrite(`FindingModel.insertMany:${repo.full_name}`, {
          type: "INSERT_FINDINGS",
          data: {
            findings: findings.map((f) => ({
              scanId: scanId.toHexString(),
              installationId: checkpoint?.installationId,
              owner,
              repo: repo.name,
              rule: f.rule,
              severity: f.severity,
              message: f.message,
              file: f.file,
              detectedAt: new Date().toISOString(),
            })),
          },
        });
      }

      // Update scan record
      await safeWrite(`Scan.complete:${repo.full_name}`, {
        type: "COMPLETE_SCAN",
        data: {
          scanId: scanId.toHexString(),
          findingsCount: findings.length,
          completedAt: new Date().toISOString(),
        },
      });

      if (findings.length === 0) {
        logger.info(`[installation] CLEAN — ${repo.full_name}`);

        try {
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
        } catch (issueErr) {
          const msg =
            issueErr instanceof Error ? issueErr.message : String(issueErr);
          logger.warn(
            `[installation] Could not post clean scan issue for ${repo.full_name}: ${msg.split(" - ")[0]}`,
          );
        }
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
      logger.error(
        `[installation] Error scanning ${repo.full_name}: ${message}`,
      );

      await Scan.updateOne(
        { _id: scanId },
        { $set: { status: "failed", completedAt: new Date() } },
      ).catch((dbErr: unknown) => {
        const msg = dbErr instanceof Error ? dbErr.message : String(dbErr);
        logger.warn(
          `[installation] Could not update scan status to failed: ${msg}`,
        );
      });
      if (isSkippableError(message)) {
        // Non-retryable — mark as scanned so it doesn't retry
        await markScanned(installationKey, repo.full_name);
        logger.warn(
          `[installation] Skipping ${repo.full_name} permanently — ${message.split(" - ")[0]}`,
        );
      } else {
        // Retryable error — leave unscanned so it retries on resume
        logger.warn(
          `[installation] Will retry ${repo.full_name} on next resume`,
        );
      }
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
    logger.info(
      `[installation] All repos scanned for ${owner} — checkpoint cleared`,
    );
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
        installation: {
          id: number;
          account: { login?: string; name?: string };
        };
      };
      const owner =
        installation.account.login ?? installation.account.name ?? "unknown";
      const installationKey = `${owner}-${installation.id}`;

      await clearCheckpoint(installationKey);
      await Installation.updateOne(
        { installationId: installation.id },
        { $set: { uninstalledAt: new Date() } },
      );

      await sendAlert({
        owner,
        repo: owner,
        ref: "N/A",
        pusher: owner,
        headSha: null,
        findings: [
          {
            rule: "app-uninstalled",
            severity: "high",
            message: `RepoGuard was uninstalled by ${owner} — repositories are no longer protected`,
            file: null,
          },
        ],
        context: "installation",
      });

      logger.info(
        `[installation] App uninstalled by ${owner} — records updated`,
      );
      return;
    }

    if (action !== "created") return;

    const { installation, repositories } = payload;
    const owner =
      installation.account.login ?? installation.account.name ?? "unknown";
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
      findings: [
        {
          rule: "app-installed",
          severity: "low",
          message: `RepoGuard installed by ${owner} on ${allRepos.length} repo${allRepos.length > 1 ? "s" : ""} — scanning in progress`,
          file: null,
        },
      ],
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

interface InstallationRepositoriesPayload {
  action: string;
  installation: { id: number; account: { login?: string; name?: string } };
  repositories_added: Array<{ full_name: string; name: string }>;
}

export function handleInstallationRepositories(
  _app: App,
): (event: WebhookEvent<InstallationRepositoriesPayload>) => Promise<void> {
  return async ({ octokit, payload }) => {
    const action = payload.action;

    if (action !== "added") return;

    const { installation, repositories_added } = payload;

    const owner =
      installation.account.login ?? installation.account.name ?? "unknown";
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

    await initCheckpoint(installationKey, installation.id, owner, updatedTotal);

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
      findings: [
        {
          rule: "app-repositories-added",
          severity: "low",
          message: `${repositories_added.length} repo${repositories_added.length > 1 ? "s" : ""} added to RepoGuard protection`,
          file: null,
        },
      ],
      context: "installation",
      repoList: repositories_added.map((r) => r.name),
    });

    // Scan only the newly added repos
    await scanRepoList(client, installationKey, owner, repositories_added);
  };
}

// ─── Zipball-based scanning with Tree fallback ───────────────────────────────

async function scanViaZipball(
  client: OctokitClient,
  owner: string,
  repo: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];

  logger.info(`[scan] Downloading zipball for ${owner}/${repo}`);
  const response = await client.request(
    "GET /repos/{owner}/{repo}/zipball/{ref}",
    { owner, repo, ref: "HEAD" },
  );

  const buffer = Buffer.isBuffer(response.data)
    ? response.data
    : Buffer.from(response.data as ArrayBuffer);

  const zip = new AdmZip(buffer);
  const entries = zip.getEntries();

  // ── Fetch .repoguardignore if present in zip ───────────────────────────────
  let ignoredPaths: string[] = [];
  const ignoreEntry = entries.find((entry) => {
    const parts = entry.entryName.split("/");
    return parts.length === 2 && parts[1] === ".repoguardignore";
  });

  if (ignoreEntry) {
    const raw = ignoreEntry.getData().toString("utf8");
    ignoredPaths = raw
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"));
  }

  // ── Iterate and scan entries ───────────────────────────────────────────────
  for (const entry of entries) {
    if (entry.isDirectory) continue;

    // GitHub zipball has root folder: owner-repo-sha/
    const parts = entry.entryName.split("/");
    if (parts.length <= 1) continue;

    const filePath = parts.slice(1).join("/");
    if (!filePath) continue;

    if (shouldSkipPath(filePath)) continue;
    if (ignoredPaths.some((p) => filePath.startsWith(p))) continue;

    const content = entry.getData().toString("utf8");
    const binary = isBinaryPath(filePath);

    // Skip true binaries UNLESS they contain JS malware signatures
    if (binary && !looksLikeJavaScript(content)) continue;

    findings.push(...scanFileContent(content, filePath));
  }

  return findings;
}

async function scanViaTreeAndIndividualFiles(
  client: OctokitClient,
  owner: string,
  repo: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];

  const { data: tree } = await client.request(
    "GET /repos/{owner}/{repo}/git/trees/{tree_sha}",
    { owner, repo, tree_sha: "HEAD", recursive: "1" },
  );

  // ── Fetch .repoguardignore if present ──────────────────────────────────────
  let ignoredPaths: string[] = [];
  try {
    const { data: ignoreFile } = await client.request(
      "GET /repos/{owner}/{repo}/contents/{path}",
      { owner, repo, path: ".repoguardignore" },
    );
    if (!Array.isArray(ignoreFile) && "content" in ignoreFile) {
      const raw = Buffer.from(ignoreFile.content, "base64").toString("utf8");
      ignoredPaths = raw
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith("#"));
    }
  } catch {
    // No .repoguardignore — that's fine
  }

  // ✅ Filter blobs upfront then fetch in batches of 10
  const BATCH_SIZE = 10;
  const blobs = tree.tree.filter(
    (item) =>
      item.type === "blob" &&
      !!item.path &&
      !shouldSkipPath(item.path) &&
      !ignoredPaths.some((p) => item.path!.startsWith(p)),
  );

  for (let i = 0; i < blobs.length; i += BATCH_SIZE) {
    const batch = blobs.slice(i, i + BATCH_SIZE);

    await Promise.all(
      batch.map(async (item) => {
        const binary = isBinaryPath(item.path!);
        try {
          const { data } = await client.request(
            "GET /repos/{owner}/{repo}/contents/{path}",
            { owner, repo, path: item.path! },
          );

          if (
            Array.isArray(data) ||
            data.type !== "file" ||
            !("content" in data)
          )
            return;

          const content = Buffer.from(data.content || "", "base64").toString(
            "utf8",
          );

          if (binary && !looksLikeJavaScript(content)) return;

          // ✅ Scan immediately — no files array accumulation
          findings.push(...scanFileContent(content, item.path));
        } catch {
          // File deleted or inaccessible — skip
        }
      }),
    );
  }

  return findings;
}

export async function scanFullRepoForPush(
  client: OctokitClient,
  owner: string,
  repo: string,
): Promise<Finding[]> {
  try {
    logger.info(`[scan] Attempting zipball-based scan for ${owner}/${repo}`);
    return await scanViaZipball(client, owner, repo);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.warn(
      `[scan] Zipball scan failed for ${owner}/${repo}: ${msg}. Falling back to file-by-file scan...`,
    );
    return await scanViaTreeAndIndividualFiles(client, owner, repo);
  }
}
