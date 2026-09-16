/**
 * Known bot logins and patterns for RepoGuard automated services.
 */
const KNOWN_BOT_LOGINS = new Set(["repoguard-ifecodes[bot]", "repoguard[bot]"]);

/**
 * Checks whether a push or PR synchronize event on a `repoguard/fixes-*` branch
 * originated from the authorized RepoGuard GitHub App bot.
 */
export function isAuthorizedFixBranchPusher(
  pusherName?: string,
  senderLogin?: string,
  senderType?: string,
): boolean {
  const name = (pusherName || "").toLowerCase().trim();
  const login = (senderLogin || "").toLowerCase().trim();
  const type = (senderType || "").toLowerCase().trim();

  // Explicit GitHub Bot sender type with repoguard in name/login
  if (
    type === "bot" &&
    (login.includes("repoguard") || name.includes("repoguard"))
  ) {
    return true;
  }

  // Exact known bot logins
  if (KNOWN_BOT_LOGINS.has(login) || KNOWN_BOT_LOGINS.has(name)) {
    return true;
  }

  // Ends with [bot] and contains repoguard
  if (login.endsWith("[bot]") && login.includes("repoguard")) {
    return true;
  }

  if (name.endsWith("[bot]") && name.includes("repoguard")) {
    return true;
  }

  // GitHub App API commit pusher slugs
  if (
    name === "repoguard" ||
    name === "repoguard-ifecodes" ||
    login === "repoguard" ||
    login === "repoguard-ifecodes"
  ) {
    return true;
  }

  return false;
}
