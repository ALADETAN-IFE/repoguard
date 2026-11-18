import type { OctokitClient } from "../types/index";
import logger from "../utils/logger";

// ─── Typed interfaces for lockfile JSON shapes ───────────────────────────────

interface PackageLockEntry {
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

interface PackageLockJson {
  packages?: Record<string, PackageLockEntry>;
  dependencies?: Record<string, { version?: string }>;
}

interface BunLockEntry {
  version?: string;
}

interface BunLockJson {
  packages?: Record<string, string | BunLockEntry>;
}

interface PipfilePackageEntry {
  version?: string;
}

interface PipfileLockJson {
  default?: Record<string, PipfilePackageEntry>;
  develop?: Record<string, PipfilePackageEntry>;
  packages?: Record<string, PipfilePackageEntry>;
}

interface PackageJson {
  packageManager?: string;
}

// ─── npm package-lock.json parser ───────────────────────────────────────────
// Supports lockfileVersion: 1, 2, and 3
export function parsePackageLock(
  content: string,
  packageName: string,
): string | null {
  try {
    const parsed = JSON.parse(content) as PackageLockJson;

    // Lockfile v2 & v3: check packages["node_modules/<pkg>"]
    if (parsed.packages && typeof parsed.packages === "object") {
      const pkgKey = `node_modules/${packageName}`;
      if (parsed.packages[pkgKey]?.version) {
        return String(parsed.packages[pkgKey].version);
      }

      // Check root packages entry
      const rootDeps: Record<string, string> = {
        ...(parsed.packages[""]?.dependencies ?? {}),
        ...(parsed.packages[""]?.devDependencies ?? {}),
      };
      if (
        rootDeps[packageName] &&
        rootDeps[packageName] !== "latest" &&
        rootDeps[packageName] !== "*"
      ) {
        return String(rootDeps[packageName]).replace(/^[\^~>=<\s]+/, "");
      }
    }

    // Lockfile v1 / v2 fallback: check dependencies[<pkg>]
    if (parsed.dependencies && typeof parsed.dependencies === "object") {
      if (parsed.dependencies[packageName]?.version) {
        return String(parsed.dependencies[packageName].version);
      }
    }

    return null;
  } catch (err) {
    logger.debug(
      `[lockfile] Failed to parse package-lock.json: ${String(err)}`,
    );
    return null;
  }
}

// ─── Yarn yarn.lock parser ──────────────────────────────────────────────────
// Supports Yarn Classic (v1) and Yarn Berry (v2/v3/v4)
export function parseYarnLock(
  content: string,
  packageName: string,
): string | null {
  try {
    const escapedPkg = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    const yarnRegex = new RegExp(
      `(?:^|\\n)[^\\n]*?(?:["'/\\s,]|^)${escapedPkg}@[^\\n]*?:\\s*\\n\\s+version(?::|\\s)\\s*["']?([^"\\s'\\n]+)["']?`,
      "m",
    );
    const match = content.match(yarnRegex);
    if (match?.[1]) {
      return match[1];
    }

    return null;
  } catch (err) {
    logger.debug(`[lockfile] Failed to parse yarn.lock: ${String(err)}`);
    return null;
  }
}

// ─── pnpm pnpm-lock.yaml parser ─────────────────────────────────────────────
export function parsePnpmLock(
  content: string,
  packageName: string,
): string | null {
  try {
    const escapedPkg = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const pnpmRegex = new RegExp(
      `(?:^|\\n)\\s*['"]?/?${escapedPkg}@([0-9]+\\.[0-9]+[^:'"()\\s]+)`,
      "m",
    );
    const match = content.match(pnpmRegex);
    if (match?.[1]) {
      return match[1];
    }
    return null;
  } catch (err) {
    logger.debug(`[lockfile] Failed to parse pnpm-lock.yaml: ${String(err)}`);
    return null;
  }
}

// ─── Bun bun.lock parser ────────────────────────────────────────────────────
export function parseBunLock(
  content: string,
  packageName: string,
): string | null {
  try {
    const parsed = JSON.parse(content) as BunLockJson;
    if (parsed.packages && typeof parsed.packages === "object") {
      const match = parsed.packages[packageName];
      if (typeof match === "string") return match.replace(/^[\^~>=<\s]+/, "");
      if (match?.version) return String(match.version);
    }
  } catch {
    const escapedPkg = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const match = content.match(
      new RegExp(`["']?${escapedPkg}["']?\\s*:\\s*["']([^"']+)["']`),
    );
    if (match?.[1]) return match[1].replace(/^[\^~>=<\s]+/, "");
  }
  return null;
}

// ─── Python poetry.lock parser ──────────────────────────────────────────────
export function parsePoetryLock(
  content: string,
  packageName: string,
): string | null {
  try {
    const escapedPkg = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const poetryRegex = new RegExp(
      `\\[\\[package\\]\\][\\s\\S]*?name\\s*=\\s*["']${escapedPkg}["'][\\s\\S]*?version\\s*=\\s*["']([^"']+)["']`,
      "i",
    );
    const match = content.match(poetryRegex);
    if (match?.[1]) {
      return match[1];
    }
    return null;
  } catch (err) {
    logger.debug(`[lockfile] Failed to parse poetry.lock: ${String(err)}`);
    return null;
  }
}

// ─── Python Pipfile.lock parser ─────────────────────────────────────────────
export function parsePipfileLock(
  content: string,
  packageName: string,
): string | null {
  try {
    const parsed = JSON.parse(content) as PipfileLockJson;
    const pkg =
      parsed.default?.[packageName] ??
      parsed.develop?.[packageName] ??
      parsed.packages?.[packageName];
    if (pkg?.version) {
      return String(pkg.version).replace(/^==/, "");
    }
    return null;
  } catch {
    return null;
  }
}

// ─── Rust Cargo.lock parser ─────────────────────────────────────────────────
export function parseCargoLock(
  content: string,
  packageName: string,
): string | null {
  try {
    const escapedPkg = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const cargoRegex = new RegExp(
      `\\[\\[package\\]\\][\\s\\S]*?name\\s*=\\s*["']${escapedPkg}["'][\\s\\S]*?version\\s*=\\s*["']([^"']+)["']`,
      "i",
    );
    const match = content.match(cargoRegex);
    if (match?.[1]) {
      return match[1];
    }
    return null;
  } catch (err) {
    logger.debug(`[lockfile] Failed to parse Cargo.lock: ${String(err)}`);
    return null;
  }
}

// ─── Fetch file content from GitHub repository safely ────────────────────────
async function fetchRepoFile(
  octokit: OctokitClient,
  owner: string,
  repo: string,
  path: string,
  ref?: string,
): Promise<string | null> {
  try {
    const res = await octokit.request(
      "GET /repos/{owner}/{repo}/contents/{path}",
      {
        owner,
        repo,
        path,
        ...(ref ? { ref } : {}),
      },
    );
    const data = res.data as { type?: string; content?: string };
    if (data?.type === "file" && data?.content) {
      return Buffer.from(data.content, "base64").toString("utf8");
    }
    return null;
  } catch {
    return null;
  }
}

export interface LockfileResolutionResult {
  resolvedVersion: string | null;
  sourceLockfile?: string;
  conflictWarning?: string;
}

interface DiscoveredLockfile {
  filename: string;
  type: "npm" | "yarn" | "pnpm" | "bun" | "poetry" | "pipenv" | "cargo";
  version: string;
}

// ─── Find resolved version across ALL lockfiles with multi-tool comparison ───
export async function findLockfileVersion(
  octokit: OctokitClient,
  owner: string,
  repo: string,
  ref: string,
  manifestPath: string,
  packageName: string,
): Promise<LockfileResolutionResult> {
  const parts = manifestPath.split("/");
  parts.pop(); // remove manifest filename
  const dir = parts.join("/"); // directory of manifest, e.g. "azapal-mobile" or ""

  const isNode = manifestPath.endsWith("package.json");
  const isPython =
    manifestPath.endsWith("requirements.txt") ||
    manifestPath.endsWith("pyproject.toml") ||
    manifestPath.endsWith("Pipfile");
  const isRust = manifestPath.endsWith("Cargo.toml");

  // Helper to fetch file from manifest dir or root
  const fetchFile = async (filename: string): Promise<string | null> => {
    let content = await fetchRepoFile(
      octokit,
      owner,
      repo,
      dir ? `${dir}/${filename}` : filename,
      ref,
    );
    if (!content && dir) {
      content = await fetchRepoFile(octokit, owner, repo, filename, ref);
    }
    return content;
  };

  const discovered: DiscoveredLockfile[] = [];

  if (isNode) {
    // 1. Fetch ALL possible Node lockfiles concurrently
    const [packageLockRaw, yarnLockRaw, pnpmLockRaw, bunLockRaw] =
      await Promise.all([
        fetchFile("package-lock.json"),
        fetchFile("yarn.lock"),
        fetchFile("pnpm-lock.yaml"),
        fetchFile("bun.lock"),
      ]);

    if (packageLockRaw) {
      const v = parsePackageLock(packageLockRaw, packageName);
      if (v)
        discovered.push({
          filename: "package-lock.json",
          type: "npm",
          version: v,
        });
    }
    if (yarnLockRaw) {
      const v = parseYarnLock(yarnLockRaw, packageName);
      if (v)
        discovered.push({ filename: "yarn.lock", type: "yarn", version: v });
    }
    if (pnpmLockRaw) {
      const v = parsePnpmLock(pnpmLockRaw, packageName);
      if (v)
        discovered.push({
          filename: "pnpm-lock.yaml",
          type: "pnpm",
          version: v,
        });
    }
    if (bunLockRaw) {
      const v = parseBunLock(bunLockRaw, packageName);
      if (v) discovered.push({ filename: "bun.lock", type: "bun", version: v });
    }
  }

  if (isPython) {
    const [poetryRaw, pipfileRaw] = await Promise.all([
      fetchFile("poetry.lock"),
      fetchFile("Pipfile.lock"),
    ]);

    if (poetryRaw) {
      const v = parsePoetryLock(poetryRaw, packageName);
      if (v)
        discovered.push({
          filename: "poetry.lock",
          type: "poetry",
          version: v,
        });
    }
    if (pipfileRaw) {
      const v = parsePipfileLock(pipfileRaw, packageName);
      if (v)
        discovered.push({
          filename: "Pipfile.lock",
          type: "pipenv",
          version: v,
        });
    }
  }

  if (isRust) {
    const cargoRaw = await fetchFile("Cargo.lock");
    if (cargoRaw) {
      const v = parseCargoLock(cargoRaw, packageName);
      if (v)
        discovered.push({ filename: "Cargo.lock", type: "cargo", version: v });
    }
  }

  // ── No lockfiles found with this package ──────────────────────────────────
  if (discovered.length === 0) {
    return { resolvedVersion: null };
  }

  // ── Exactly 1 lockfile found ──────────────────────────────────────────────
  if (discovered.length === 1) {
    return {
      resolvedVersion: discovered[0].version,
      sourceLockfile: discovered[0].filename,
    };
  }

  // ── Multiple lockfiles found: compare ALL of them! ────────────────────────
  const distinctVersions = [...new Set(discovered.map((d) => d.version))];

  // All lockfiles agree on the exact same version!
  if (distinctVersions.length === 1) {
    const allNames = discovered.map((d) => d.filename).join(", ");
    return {
      resolvedVersion: distinctVersions[0],
      sourceLockfile: `All lockfiles (${allNames})`,
    };
  }

  // ── Conflict Detected: Lockfiles disagree on version! ─────────────────────
  // Determine preferred lockfile based on package.json "packageManager" or priority
  let chosen = discovered[0];

  if (isNode) {
    try {
      const manifestRaw = await fetchFile("package.json");
      if (manifestRaw) {
        const pkgJson = JSON.parse(manifestRaw) as PackageJson;
        const pm: string = pkgJson.packageManager ?? "";
        if (pm.startsWith("yarn")) {
          const match = discovered.find((d) => d.type === "yarn");
          if (match) chosen = match;
        } else if (pm.startsWith("pnpm")) {
          const match = discovered.find((d) => d.type === "pnpm");
          if (match) chosen = match;
        } else if (pm.startsWith("bun")) {
          const match = discovered.find((d) => d.type === "bun");
          if (match) chosen = match;
        } else if (pm.startsWith("npm")) {
          const match = discovered.find((d) => d.type === "npm");
          if (match) chosen = match;
        }
      }
    } catch {
      // fallback to chosen
    }
  }

  // Generate a complete comparative conflict warning showing EVERY lockfile
  const conflictLines = [
    `⚠️ **Lockfile Conflict Detected Across Multiple Tools:**`,
    ...discovered.map(
      (d) =>
        `- \`${d.filename}\` (${d.type}): **\`${d.version}\`**${
          d === chosen ? " *(selected — active package manager)*" : ""
        }`,
    ),
    ``,
    `Recommend deleting or resyncing unused lockfiles to avoid phantom dependency issues.`,
  ];

  return {
    resolvedVersion: chosen.version,
    sourceLockfile: chosen.filename,
    conflictWarning: conflictLines.join("\n"),
  };
}
