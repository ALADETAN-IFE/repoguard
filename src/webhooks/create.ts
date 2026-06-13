import type { App } from "@octokit/app";
import { sendAlert } from "../alerts";
import logger from "../utils/logger";
import type { WebhookEvent, CreateEventPayload } from "../types/index";

const SUSPICIOUS_BRANCH_PATTERNS: RegExp[] = [
  /^update[-_]deps?/i,
  /^auto[-_]fix/i,
  /^patch[-_]\d+/i,
  /^hotfix[-_]security/i,
];

const BOT_LOGINS = new Set(["repoguard-ifecodes[bot]"]);

export function handleCreate(_app: App): (event: WebhookEvent<CreateEventPayload>) => Promise<void> {
  return async ({ octokit, payload }) => {
    const { ref_type, ref, sender, repository } = payload;
    const owner = repository.owner.login ?? repository.owner.name ?? "unknown";
    const repo = repository.name;

    logger.info(
      `[create] ${owner}/${repo} — new ${ref_type}: "${ref}" by ${sender.login}`,
    );

    if (BOT_LOGINS.has(sender.login) || sender.login.endsWith("[bot]")) return;

    try {
      let isMember = true;
      try {
        await octokit.request("GET /orgs/{org}/members/{username}", {
          org: owner,
          username: sender.login,
        });
      } catch {
        isMember = false;
      }

      const isSuspiciousName = SUSPICIOUS_BRANCH_PATTERNS.some((p) =>
        p.test(ref),
      );

      if (!isMember || isSuspiciousName) {
        await sendAlert({
          owner,
          repo,
          ref,
          pusher: sender.login,
          headSha: null,
          findings: [
            {
              rule: "suspicious-branch-create",
              severity: "high",
              message: !isMember
                ? `Non-org member "${sender.login}" created ${ref_type} "${ref}"`
                : `${ref_type} name "${ref}" matches known malware naming patterns`,
              file: null,
            },
          ],
          context: "branch_create",
        });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(
        `[create] Error processing event in ${owner}/${repo}: ${message}`,
      );
    }
  };
}
