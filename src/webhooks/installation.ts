import fs from "fs";
import path from "path";
import type { App } from "@octokit/app";
import { scanFileContent } from "../scanner";
import { openFixPR } from "../pullRequest";
import logger from "../utils/logger";
import type { Finding, WebhookEvent, InstallationEventPayload, OctokitClient } from "../types/index";

interface RepoFile {
  path: string;
  content: string;
}

// ─── Checkpoint helpers ───────────────────────────────────────────────────────

const CHECKPOINT_FILE = path.resolve(".repoguard-checkpoint.json");

interface CheckpointEntry {
  scanned: string[];
  startedAt: string;
  installationId: number;
  owner: string;
  totalRepos: string[]; // all repo full_names from the original event
}

interface Checkpoint {
  [installationKey: string]: CheckpointEntry;
}

function loadCheckpoint(): Checkpoint {
  try {
    if (fs.existsSync(CHECKPOINT_FILE)) {
      logger.info(
        `[checkpoint] Loading checkpoint from file: ${CHECKPOINT_FILE}`,
      );
      return JSON.parse(fs.readFileSync(CHECKPOINT_FILE, "utf8")) as Checkpoint;
    }
  } catch {
    logger.warn("[checkpoint] Could not read checkpoint file — starting fresh");
  }
  return {};
}

function saveCheckpoint(checkpoint: Checkpoint): void {
  try {
    fs.writeFileSync(CHECKPOINT_FILE, JSON.stringify(checkpoint, null, 2));
  } catch {
    logger.warn("[checkpoint] Could not write checkpoint file");
  }
}

function initCheckpoint(
  installationKey: string,
  installationId: number,
  owner: string,
  allRepos: string[],
): void {
  const checkpoint = loadCheckpoint();
  logger.info(
    `[checkpoint] Initialising checkpoint for installation: ${installationKey}`,
  );
  if (!checkpoint[installationKey]) {
    checkpoint[installationKey] = {
      scanned: [],
      startedAt: new Date().toISOString(),
      installationId,
      owner,
      totalRepos: allRepos,
    };
    logger.info(`[checkpoint] Total repos to scan: ${allRepos.length}`);
    saveCheckpoint(checkpoint);
  } else {
    logger.info(
      `[checkpoint] Checkpoint already exists for installation: ${installationKey} — resuming scan`,
    );
    // Backfill missing fields from the key if they were never saved
    let dirty = false;
    if (!checkpoint[installationKey].totalRepos) {
      logger.info(
        `[checkpoint] Updating totalRepos for installation: ${installationKey}`,
      );
      checkpoint[installationKey].totalRepos = allRepos;
      dirty = true;
    }
    if (!checkpoint[installationKey].installationId) {
      checkpoint[installationKey].installationId = installationId;
      dirty = true;
    }
    if (!checkpoint[installationKey].owner) {
      checkpoint[installationKey].owner = owner;
      dirty = true;
    }
    if (dirty) saveCheckpoint(checkpoint);
  }
}

function markScanned(installationKey: string, repoFullName: string): void {
  const checkpoint = loadCheckpoint();
  if (!checkpoint[installationKey]) return;
  if (!checkpoint[installationKey].scanned.includes(repoFullName)) {
    checkpoint[installationKey].scanned.push(repoFullName);
  }
  saveCheckpoint(checkpoint);
}

export function patchCheckpointTotalRepos(
  installationKey: string,
  totalRepos: string[],
): void {
  const checkpoint = loadCheckpoint();
  if (!checkpoint[installationKey]) return;
  checkpoint[installationKey].totalRepos = totalRepos;
  saveCheckpoint(checkpoint);
  logger.info(
    `[checkpoint] Patched totalRepos for ${installationKey}: ${totalRepos.length} repos`,
  );
}

export function clearCheckpoint(installationKey: string): void {
  const checkpoint = loadCheckpoint();
  delete checkpoint[installationKey];
  saveCheckpoint(checkpoint);
}

// Returns ALL incomplete entries alongside their key.
// For legacy entries where installationId/owner were never persisted,
// we parse them out of the key (format: "<owner>-<installationId>").
export function getIncompleteScans(): Array<CheckpointEntry & { key: string }> {
  const checkpoint = loadCheckpoint();
  const totalEntries = Object.keys(checkpoint).length;

  logger.info(
    `[checkpoint] Loaded checkpoint with ${totalEntries} installation${totalEntries > 1 ? "s" : ""}`,
  );

  return Object.entries(checkpoint)
    .filter(([, entry]) => {
      // Legacy entry: totalRepos not yet known — treat as incomplete so the
      // startup resume logic can fetch the list from GitHub and continue.
      if (!entry.totalRepos) return true;
      return entry.scanned.length < entry.totalRepos.length;
    })
    .map(([key, entry]) => {
      // Parse owner and installationId out of the key when missing from the
      // entry itself. Key format: "<owner>-<installationId>" where
      // installationId is the numeric suffix after the last hyphen.
      let { owner, installationId } = entry;

      if (!owner || !installationId) {
        const lastDash = key.lastIndexOf("-");
        if (lastDash !== -1) {
          owner = owner || key.slice(0, lastDash);
          installationId =
            installationId || parseInt(key.slice(lastDash + 1), 10);
          logger.info(
            `[checkpoint] Recovered owner="${owner}" installationId=${installationId} from key "${key}"`,
          );
        }
      }

      return { ...entry, owner, installationId, key };
    });
}

// ─── Core scan logic (shared by webhook handler and startup resume) ───────────

export async function scanRepoList(
  client: OctokitClient,
  installationKey: string,
  owner: string,
  repos: Array<{ full_name: string; name: string }>,
): Promise<void> {
  const pending = repos.filter(
    (r) => !loadCheckpoint()[installationKey]?.scanned.includes(r.full_name),
  );

  const alreadyDone = repos.length - pending.length;
  if (alreadyDone > 0) {
    logger.info(
      `[installation] Resuming — skipping ${alreadyDone} already-scanned ${alreadyDone > 1 ? "repos" : "repo"}`,
    );
  }

  for (const repo of pending) {
    logger.info(`[installation] Scanning: ${repo.full_name}`);

    try {
      const findings = await scanFullRepo(client, owner, repo.name);

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

      markScanned(installationKey, repo.full_name);
      logger.info(`[installation] ✓ ${repo.full_name} checkpointed`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(
        `[installation] Error scanning ${repo.full_name}: ${message}`,
      );
      // Don't checkpoint on error — will retry on resume
    }
  }

  // Check if all repos are now done
  const checkpoint = loadCheckpoint();
  const entry = checkpoint[installationKey];
  if (
    entry &&
    entry.totalRepos &&
    entry.scanned.length >= entry.totalRepos.length
  ) {
    clearCheckpoint(installationKey);
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
    const action = (payload as { action: string }).action;

    // When app is uninstalled — clear stale checkpoint so startup resume skips it
    if (action === "deleted") {
      const { installation } = payload as { installation: { id: number; account: { login?: string; name?: string } } };
      const owner = installation.account.login ?? installation.account.name ?? "unknown";
      const installationKey = `${owner}-${installation.id}`;
      clearCheckpoint(installationKey);
      logger.info(`[installation] App uninstalled by ${owner} — checkpoint cleared`);
      return;
    }

    if (action !== "created") return;

    const { installation, repositories } = payload;

    const owner =
      installation.account.login ?? installation.account.name ?? "unknown";
    const installationKey = `${owner}-${installation.id}`;
    const allRepos = repositories ?? [];

    logger.info(
      `[installation] App installed by ${owner} on ${allRepos.length} ${allRepos.length > 1 ? "repos" : "repo"}`,
    );

    const client = normaliseOctokit(octokit);

    initCheckpoint(
      installationKey,
      installation.id,
      owner,
      allRepos.map((r) => r.full_name),
    );

    await scanRepoList(client, installationKey, owner, allRepos);
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

      if (
        Array.isArray(data) ||
        data.type !== "file" ||
        !("content" in data)
      )
        continue;

      const content = Buffer.from(data.content || "", "base64").toString(
        "utf8",
      );
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
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".ico",
  ".svg",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
  ".zip",
  ".tar",
  ".gz",
  ".exe",
  ".dll",
  ".so",
  ".pdf",
  ".mp4",
  ".mp3",
]);

function isBinaryPath(filePath: string): boolean {
  return [...BINARY_EXTENSIONS].some((ext) =>
    filePath.toLowerCase().endsWith(ext),
  );
}