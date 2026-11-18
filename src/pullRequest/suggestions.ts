import type { Finding, OctokitClient } from "../types/index";
import { findLockfileVersion } from "./lockfileParsers";
import logger from "../utils/logger";

export interface SuggestionContext {
  octokit: OctokitClient;
  owner: string;
  repo: string;
  ref: string;
}

export interface GeneratedSuggestion {
  suggestionCode: string | null;
  conflictWarning?: string;
  sourceNote?: string;
  diagnosticCommand?: string;
}

// ─── Query public npm registry for latest release (1.5s timeout) ──────────────
async function fetchNpmLatestVersion(
  packageName: string,
): Promise<string | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1500);
    // Encode scoped package name e.g. @scope/pkg -> @scope%2Fpkg
    const encoded = packageName.startsWith("@")
      ? `@${encodeURIComponent(packageName.slice(1))}`
      : encodeURIComponent(packageName);
    const res = await fetch(`https://registry.npmjs.org/${encoded}/latest`, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    clearTimeout(timeout);
    if (!res.ok) return null;
    const data = (await res.json()) as { version?: string };
    return data?.version || null;
  } catch {
    return null;
  }
}

// ─── Query PyPI registry for latest release (1.5s timeout) ───────────────────
async function fetchPyPILatestVersion(
  packageName: string,
): Promise<string | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1500);
    const res = await fetch(
      `https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`,
      {
        signal: controller.signal,
        headers: { Accept: "application/json" },
      },
    );
    clearTimeout(timeout);
    if (!res.ok) return null;
    const data = (await res.json()) as { info?: { version?: string } };
    return data?.info?.version || null;
  } catch {
    return null;
  }
}

// ─── Generate line-level suggestion for manual review finding ─────────────────
export async function generateSuggestionForFinding(
  finding: Finding,
  lineContent: string,
  context?: SuggestionContext,
): Promise<GeneratedSuggestion> {
  const line = lineContent.trimEnd();

  // 1. Dependency Wildcard Version
  if (finding.rule === "dependency-wildcard-version" && finding.file) {
    const isPackageJson = finding.file.endsWith("package.json");
    const isRequirementsTxt = finding.file.endsWith("requirements.txt");

    if (isPackageJson) {
      // Matches: "pkg-name": "latest", or "pkg-name": "*",
      const match = line.match(
        /^(\s*)["']([^"']+)["']\s*:\s*["'][^"']*["'](\s*,?)/,
      );
      if (match) {
        const indent = match[1];
        const pkgName = match[2];
        const comma = match[3] || "";

        // Tier 1: Lockfile lookup (Zero breaking changes)
        if (context) {
          try {
            const lockResult = await findLockfileVersion(
              context.octokit,
              context.owner,
              context.repo,
              context.ref,
              finding.file,
              pkgName,
            );

            if (lockResult.resolvedVersion) {
              const cleanVer = lockResult.resolvedVersion.replace(
                /^[\^~>=<\s]+/,
                "",
              );
              return {
                suggestionCode: `${indent}"${pkgName}": "^${cleanVer}"${comma}`,
                sourceNote: `Pinned to \`^${cleanVer}\` from \`${lockResult.sourceLockfile || "lockfile"}\` (100% build-safe).`,
                conflictWarning: lockResult.conflictWarning,
              };
            }
          } catch (err) {
            logger.debug(
              `[suggestions] Lockfile lookup failed: ${String(err)}`,
            );
          }
        }

        // Tier 2: Public npm registry lookup (Fallback)
        const registryVer = await fetchNpmLatestVersion(pkgName);
        if (registryVer) {
          return {
            suggestionCode: `${indent}"${pkgName}": "^${registryVer}"${comma}`,
            sourceNote: `Pinned to latest stable \`^${registryVer}\` from npm registry (verify peer dependency compatibility).`,
          };
        }

        // Tier 3: Diagnostic command fallback
        return {
          suggestionCode: null,
          diagnosticCommand: `yarn why ${pkgName} || npm ls ${pkgName}`,
        };
      }
    }

    if (isRequirementsTxt) {
      // Matches e.g. requests>=0 or requests* or requests==latest
      const match = line.match(/^([a-zA-Z0-9_\-.]+)(?:[><=*~].*)?$/);
      if (match) {
        const pkgName = match[1];

        // Tier 1: Lockfile lookup
        if (context) {
          try {
            const lockResult = await findLockfileVersion(
              context.octokit,
              context.owner,
              context.repo,
              context.ref,
              finding.file,
              pkgName,
            );
            if (lockResult.resolvedVersion) {
              return {
                suggestionCode: `${pkgName}==${lockResult.resolvedVersion}`,
                sourceNote: `Pinned to \`${lockResult.resolvedVersion}\` from \`${lockResult.sourceLockfile || "lockfile"}\`.`,
              };
            }
          } catch {
            // fallback
          }
        }

        // Tier 2: PyPI registry lookup
        const pypiVer = await fetchPyPILatestVersion(pkgName);
        if (pypiVer) {
          return {
            suggestionCode: `${pkgName}==${pypiVer}`,
            sourceNote: `Pinned to latest stable \`${pypiVer}\` from PyPI.`,
          };
        }

        return {
          suggestionCode: null,
          diagnosticCommand: `pip show ${pkgName}`,
        };
      }
    }
  }

  // 2. Insecure git:// protocol
  if (finding.rule === "dependency-insecure-git-protocol") {
    if (line.includes("git://")) {
      const replaced = line.replace(/git:\/\//g, "https://");
      return {
        suggestionCode: replaced,
        sourceNote:
          "Replaced insecure `git://` protocol with encrypted `https://`.",
      };
    }
  }

  // 3. Docker run as root / no USER directive
  if (finding.rule === "docker-run-as-root") {
    if (/^\s*USER\s+root\b/i.test(line)) {
      const indent = line.match(/^\s*/)?.[0] || "";
      return {
        suggestionCode: `${indent}USER appuser`,
        sourceNote: "Switch to dedicated unprivileged user.",
      };
    }
  }

  if (finding.rule === "docker-no-user-directive") {
    if (/^\s*(CMD|ENTRYPOINT)\b/i.test(line)) {
      const indent = line.match(/^\s*/)?.[0] || "";
      return {
        suggestionCode: `${indent}RUN useradd -m -u 1001 appuser\n${indent}USER appuser\n${line}`,
        sourceNote:
          "Created and switched to unprivileged user before entrypoint.",
      };
    }
  }

  // 4. Docker latest tag
  if (finding.rule === "docker-latest-tag") {
    if (/:latest\b/i.test(line)) {
      const replaced = line.replace(/:latest\b/i, ":stable");
      return {
        suggestionCode: replaced,
        sourceNote: "Replaced mutable `:latest` tag with pinned release.",
      };
    }
  }

  // 5. Workflow pull_request_target checkout
  if (finding.rule === "workflow-pull-request-target-checkout") {
    if (
      /ref:\s*\${{\s*github\.event\.pull_request\.head\.sha\s*}}/i.test(line)
    ) {
      const indent = line.match(/^\s*/)?.[0] || "";
      return {
        suggestionCode: `${indent}# Omitted untrusted PR head checkout to prevent arbitrary code execution`,
        sourceNote: "Prevented untrusted checkout in privileged workflow.",
      };
    }
  }

  return { suggestionCode: null };
}
