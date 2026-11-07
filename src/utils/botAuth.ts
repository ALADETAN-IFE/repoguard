import type { OctokitClient } from "../types";

/**
 * Known bot logins and patterns for RepoGuard automated services.
 */
const WRITE_PERMISSIONS = new Set(["admin", "maintain"]);

/**
 * Checks whether a push or PR synchronize event on a `repoguard/fixes-*` branch
 * originated from the authorized RepoGuard GitHub App bot.
 */
export function isAuthorizedFixBranchPusher(
  pusherName?: string,
  senderLogin?: string,
  _senderType?: string,
): boolean {
  const configuredBot = (process.env.BOT_NAME || "repoguard").toLowerCase();
  const knownBotLogins = new Set([
    `${configuredBot}[bot]`,
    "repoguard[bot]",
    "repoguard-ifecodes[bot]",
  ]);
  const name = (pusherName || "").toLowerCase().trim();
  const login = (senderLogin || "").toLowerCase().trim();

  return knownBotLogins.has(login) || knownBotLogins.has(name);
}

/**
 * Allows repository users who can legitimately update a remediation branch.
 * GitHub's collaborator permission endpoint includes organization members with
 * repository access, while rejecting ordinary write and read-only access.
 */
export async function hasFixBranchWritePermission(
  client: OctokitClient,
  owner: string,
  repo: string,
  actorLogin: string,
): Promise<boolean> {
  const login = actorLogin.trim();
  if (!login) return false;
  if (login.toLowerCase() === owner.toLowerCase()) return true;

  try {
    const { data } = await client.request(
      "GET /repos/{owner}/{repo}/collaborators/{username}/permission",
      { owner, repo, username: login },
    );
    return WRITE_PERMISSIONS.has((data?.permission || "").toLowerCase());
  } catch {
    return false;
  }
}
