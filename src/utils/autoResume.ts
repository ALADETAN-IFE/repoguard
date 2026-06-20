import { githubApp } from "../config/githubApp";
import {
  getIncompleteScans,
  patchCheckpointTotalRepos,
  clearCheckpoint,
  scanRepoList,
} from "../webhooks/installation";
import type { OctokitClient } from "../types/index";
import logger from "./logger";

export async function resumeIncompleteScans(): Promise<void> {
  const incomplete = await getIncompleteScans();
  const totalIncomplete = incomplete.length;

  if (totalIncomplete === 0) {
    logger.info("[startup] No incomplete scans to resume");
    return;
  }

  logger.info(
    `[startup] Found ${totalIncomplete} incomplete scan${totalIncomplete > 1 ? "s" : ""} — resuming...`,
  );

  for (const entry of incomplete) {
    const { key: installationKey, owner, installationId } = entry;

    if (!installationId || !owner) {
      logger.error(
        `[startup] Could not determine owner/installationId for key "${installationKey}" — skipping`,
      );
      continue;
    }

    try {
      let octokit: Awaited<ReturnType<typeof githubApp.getInstallationOctokit>>;

      try {
        octokit = await githubApp.getInstallationOctokit(installationId);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes("Not Found") || message.includes("404")) {
          logger.warn(
            `[startup] Installation ${installationId} (${owner}) no longer exists — clearing stale checkpoint`,
          );
          await clearCheckpoint(installationKey);
        } else {
          logger.error(
            `[startup] Could not authenticate for ${owner} (${installationId}): ${message}`,
          );
        }
        continue;
      }

      // Legacy entries: totalRepos missing — fetch from GitHub
      if (!entry.totalRepos || entry.totalRepos.length === 0) {
        logger.info(
          `[startup] ${installationKey} has no totalRepos — fetching from GitHub`,
        );

        const allRepos: Array<{ full_name: string; name: string }> = [];
        let page = 1;
        let hasMore = true;

        while (hasMore) {
          const { data } = await octokit.request(
            "GET /installation/repositories",
            { per_page: 100, page },
          );
          allRepos.push(...data.repositories);
          hasMore =
            allRepos.length < data.total_count &&
            data.repositories.length === 100;
          page++;
        }

        await patchCheckpointTotalRepos(
          installationKey,
          allRepos.map((r) => r.full_name),
        );

        const remaining = allRepos.filter(
          (r) => !entry.scanned.includes(r.full_name),
        );

        logger.info(
          `[startup] Resuming ${owner}: ${entry.scanned.length}/${allRepos.length} done, ${remaining.length} remaining`,
        );

        await scanRepoList(
          octokit as OctokitClient,
          installationKey,
          owner,
          remaining,
        );
        continue;
      }

      const remaining = entry.totalRepos.filter(
        (r) => !entry.scanned.includes(r),
      );

      logger.info(
        `[startup] Resuming ${owner}: ${entry.scanned.length}/${entry.totalRepos.length} done, ${remaining.length} remaining`,
      );

      const repos = remaining.map((fullName) => ({
        full_name: fullName,
        name: fullName.split("/")[1] ?? fullName,
      }));

      await scanRepoList(
        octokit as OctokitClient,
        installationKey,
        owner,
        repos,
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`[startup] Failed to resume scan for ${owner}: ${message}`);
    }
  }
}
