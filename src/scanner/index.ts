import type { Finding, ScanRule, ScanCommitOptions } from "../types";
import logger from "../utils/logger";
import { KNOWN_NPM_TYPOSQUATS, KNOWN_PYPI_TYPOSQUATS } from "./typosquat";

const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
  ".woff", ".woff2", ".ttf", ".eot",
  ".zip", ".tar", ".gz", ".exe", ".dll", ".so",
  ".pdf", ".mp4", ".mp3",
]);

function isBinaryPath(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return [...BINARY_EXTENSIONS].some((ext) => lower.endsWith(ext));
}

function isWorkflowPath(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return (
    lower.startsWith(".github/workflows/") &&
    (lower.endsWith(".yml") || lower.endsWith(".yaml"))
  );
}

// ─── File scan rules ─────────────────────────────────────────────────────────

const FILE_RULES: ScanRule[] = [
  // ── Critical ──────────────────────────────────────────────────────────────
  {
    id: "curl-pipe-bash",
    severity: "critical",
    description: "curl output piped directly to bash/sh (remote code execution)",
    test: (content) => /curl\s.+\|\s*(ba)?sh/.test(content),
  },
  {
    id: "wget-pipe-shell",
    severity: "critical",
    description: "wget output piped to shell",
    test: (content) => /wget\s.+\|\s*(ba)?sh/.test(content),
  },
  {
    id: "reverse-shell",
    severity: "critical",
    description: "Reverse shell pattern detected",
    test: (content) =>
      /bash\s+-i\s+>&\s+\/dev\/tcp|nc\s+-e\s+\/bin\/(ba)?sh/.test(content),
  },
  {
    id: "obfuscated-base64",
    severity: "critical",
    description: "Large base64 blob combined with eval (common payload delivery)",
    test: (content) =>
      /(?:[A-Za-z0-9+/]{50,}={0,2})/.test(content) &&
      /eval|exec|Function\(|fromCharCode/.test(content),
  },
  {
    id: "obfuscated-malware-pattern",
    severity: "critical",
    description: "Suspicious obfuscated string array pattern or global require assignment",
    test: (content) =>
      /var\s+_\$_\w+\s*=\s*\(?function/.test(content) ||
      /global\[['"]!['"]\]/.test(content) ||
      /global\[_\$_\w+\[\d+\]\]\s*=\s*require/.test(content),
  },
  {
    id: "python-exec-compile",
    severity: "critical",
    description: "Python exec(compile()) obfuscation — common in PyPI malware",
    test: (content) =>
      /exec\s*\(\s*compile\s*\(/.test(content) ||
      /exec\s*\(\s*__import__\s*\(/.test(content),
  },
  {
    id: "python-subprocess-network",
    severity: "critical",
    description: "Python subprocess spawning curl/wget — remote code execution via Python",
    test: (content) =>
      /subprocess\.(run|call|Popen|check_output)/.test(content) &&
      /curl|wget|http/.test(content),
  },
  {
    id: "powershell-encoded-command",
    severity: "critical",
    description: "Encoded PowerShell command — common Windows malware vector",
    test: (content) =>
      /powershell.*-[Ee]nc(odedCommand)?|\bpowershell\b.*-[Ee]\s+[A-Za-z0-9+/]{20,}/.test(content),
  },

  // ── High ──────────────────────────────────────────────────────────────────
  {
    id: "crypto-miner-keywords",
    severity: "high",
    description: "Cryptocurrency miner indicators",
    test: (content) =>
      /xmrig|stratum\+tcp|monero|cryptonight|--mining-threads/.test(content),
  },
  {
  id: "env-exfiltration",
  severity: "high",
  description: "Environment variable exfiltration — secrets being sent externally",
  test: (content): boolean => {
    const directExfil = /fetch\s*\(\s*[`'"]https?:\/\/[^'"]+\$\{process\.env\.[^}]+\}/.test(content);
    const bodyExfil = /body\s*:.*process\.env\.(PASSWORD|SECRET|TOKEN|KEY|API)/i.test(content);
    const urlConcat = /['"`]\s*\+\s*process\.env\.(PASSWORD|SECRET|TOKEN|KEY|API)/i.test(content);
    return directExfil || bodyExfil || urlConcat;
    },
  },
  {
    id: "suspicious-npm-postinstall",
    severity: "high",
    description: "postinstall script with network call in package.json",
    test: (content, filePath) =>
      filePath?.endsWith("package.json") === true &&
      /"postinstall"\s*:\s*"[^"]*(?:curl|wget|exec|eval|node -e)[^"]*"/.test(content),
  },
  {
    id: "suspicious-registry-url",
    severity: "high",
    description: "Lock file references a non-standard npm registry — possible supply chain attack",
    test: (content, filePath): boolean => {
      const isLockFile =
        filePath?.endsWith("package-lock.json") === true ||
        filePath?.endsWith("yarn.lock") === true ||
        filePath?.endsWith("pnpm-lock.yaml") === true;
      if (!isLockFile) return false;
      return /resolved\s+"https?:\/\/(?!registry\.npmjs\.org|registry\.yarnpkg\.com)/.test(content);
    },
  },
  {
    id: "dotenv-file-committed",
    severity: "high",
    description: ".env file committed to repository — likely contains secrets",
    test: (_content, filePath): boolean => {
      const name = filePath?.split("/").pop()?.toLowerCase() ?? "";
      return (
        name === ".env" ||
        name === ".env.local" ||
        name === ".env.production" ||
        name === ".env.staging" ||
        name === ".env.development"
      );
    },
  },
  {
    id: "python-dynamic-import",
    severity: "high",
    description: "Dynamic __import__() hiding malicious module load",
    test: (content) =>
      /__import__\s*\(\s*['"][^'"]{3,}['"]/.test(content) &&
      /os|sys|subprocess|socket|urllib|http/.test(content),
  },

  // ── Medium ────────────────────────────────────────────────────────────────
  {
    id: "hardcoded-secret",
    severity: "medium",
    description: "Possible hardcoded credential or API key",
    test: (content) =>
      /(?:password|passwd|secret|api_key|apikey|token)\s*=\s*["'][^"']{8,}["']/i.test(content),
  },
  {
    id: "npm-typosquatted-package",
    severity: "high",
    description: "Possible typosquatted npm package name detected",
    test: (content, filePath): boolean => {
      if (!filePath?.endsWith("package.json")) return false;
      try {
        const pkg = JSON.parse(content) as {
          dependencies?: Record<string, string>;
          devDependencies?: Record<string, string>;
        };
        const allDeps = {
          ...pkg.dependencies,
          ...pkg.devDependencies,
        };
        return Object.keys(allDeps).some((name) => name in KNOWN_NPM_TYPOSQUATS);
      } catch {
        return false;
      }
    },
  },
  {
    id: "pypi-typosquatted-package",
    severity: "high",
    description: "Possible typosquatted PyPI package name detected",
    test: (content, filePath): boolean => {
      const name = filePath?.split("/").pop()?.toLowerCase() ?? "";
      if (name !== "requirements.txt" && name !== "requirements-dev.txt" && name !== "requirements-test.txt") {
        return false;
      }
      const lines = content.split("\n").map((l) => l.trim().toLowerCase().split(/[=><!@[]/)[0].trim());
      return lines.some((pkg) => pkg in KNOWN_PYPI_TYPOSQUATS);
    },
  },
];

// ─── Workflow scan rules ──────────────────────────────────────────────────────

const WORKFLOW_RULES: ScanRule[] = [
  {
    id: "workflow-curl-pipe-bash",
    severity: "critical",
    description: "Workflow runs curl|bash (remote code execution)",
    test: (content) => /curl\s.+\|\s*(ba)?sh/.test(content),
  },
  {
    id: "workflow-exfiltrate-secrets",
    severity: "critical",
    description: "Workflow may be exfiltrating GitHub secrets externally",
    test: (content) =>
      /\$\{\{\s*secrets\.\w+\s*\}\}/.test(content) &&
      /curl|wget|http/.test(content),
  },
  {
    id: "workflow-pull-request-target-checkout",
    severity: "critical",
    description: "pull_request_target with PR head checkout — allows arbitrary code execution from forks",
    test: (content) =>
      /on:\s*(pull_request_target|\[.*pull_request_target.*\])/.test(content) &&
      /github\.event\.pull_request\.head\.sha|github\.head_ref/.test(content),
  },
  {
    id: "workflow-suspicious-trigger",
    severity: "high",
    description: "Workflow triggered on all events — overly broad trigger",
    test: (content) => /on:\s*\[.*\*.*\]|on:\s*"\*"/.test(content),
  },
  {
    id: "workflow-unpinned-action",
    severity: "medium",
    description: "Third-party action not pinned to a full commit SHA",
    test: (content) =>
      /uses:\s+(?!actions\/)[^@\n]+@(?![\da-f]{40})/.test(content),
  },
];

// ─── Public API ───────────────────────────────────────────────────────────────

export async function scanCommit({
  octokit,
  owner,
  repo,
  sha,
  addedFiles,
  modifiedFiles,
  renamedFiles = [],
  removedFiles = [],
}: ScanCommitOptions): Promise<Finding[]> {
  const findings: Finding[] = [];
  const filesToScan = [...addedFiles, ...modifiedFiles, ...renamedFiles];

  for (const filePath of filesToScan) {
    if (isBinaryPath(filePath)) continue;

    try {
      const { data } = await octokit.rest.repos.getContent({
        owner,
        repo,
        path: filePath,
        ref: sha,
      });

      if (Array.isArray(data) || data.type !== "file" || !("content" in data)) {
        continue;
      }

      const content = Buffer.from(data.content, "base64").toString("utf8");
      if (isWorkflowPath(filePath)) {
        findings.push(...scanFileContent(content, filePath));
        findings.push(...scanWorkflowContent(content, filePath));
      } else {
        findings.push(...scanFileContent(content, filePath));
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.warn(`Could not fetch ${filePath}@${sha}: ${message}`);
    }
  }

  // Flag deleted .env files — surface for review even on removal
  for (const filePath of removedFiles) {
    const name = filePath.split("/").pop()?.toLowerCase() ?? "";
    if (name === ".env" || name.startsWith(".env.")) {
      findings.push({
        rule: "dotenv-file-removed",
        severity: "medium",
        message: `.env file deleted in this commit — verify it was not containing leaked secrets: ${filePath}`,
        file: filePath,
      });
    }
  }

  return findings;
}

export function scanFileContent(content: string, filePath?: string): Finding[] {
  return applyRules(FILE_RULES, content, filePath);
}

export function scanWorkflowContent(content: string, filePath?: string): Finding[] {
  return applyRules(WORKFLOW_RULES, content, filePath);
}

function applyRules(rules: ScanRule[], content: string, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  for (const rule of rules) {
    try {
      if (rule.test(content, filePath)) {
        findings.push({
          rule: rule.id,
          severity: rule.severity,
          message: rule.description,
          file: filePath ?? null,
        });
      }
    } catch {
      // Silently skip regex errors
    }
  }
  return findings;
}

// ─── Typosquat detail helper ──────────────────────────────────────────────────
// Returns the specific offending packages so PR bodies can name them explicitly.

export function findTyposquattedNpmPackages(content: string): Array<{ found: string; intended: string }> {
  try {
    const pkg = JSON.parse(content) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
    return Object.keys(allDeps)
      .filter((name) => name in KNOWN_NPM_TYPOSQUATS)
      .map((name) => ({ found: name, intended: KNOWN_NPM_TYPOSQUATS[name] }));
  } catch {
    return [];
  }
}

export function findTyposquattedPypiPackages(content: string): Array<{ found: string; intended: string }> {
  const lines = content.split("\n").map((l) => l.trim().toLowerCase().split(/[=><!@[]/)[0].trim());
  return lines
    .filter((pkg) => pkg in KNOWN_PYPI_TYPOSQUATS)
    .map((pkg) => ({ found: pkg, intended: KNOWN_PYPI_TYPOSQUATS[pkg] }));
}