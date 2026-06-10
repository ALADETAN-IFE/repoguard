import type { Finding, ScanRule, ScanCommitOptions } from "../types";
import logger from "../utils/logger";

// ─── Binary file extensions to skip ──────────────────────────────────────────

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
    test: (content) =>
      /process\.env|os\.environ/.test(content) &&
      /fetch|axios|http\.get|requests\.get/.test(content) &&
      /password|secret|token|key|api/i.test(content),
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
    id: "hardcoded-secret",
    severity: "medium",
    description: "Possible hardcoded credential or API key",
    test: (content) =>
      /(?:password|passwd|secret|api_key|apikey|token)\s*=\s*["'][^"']{8,}["']/i.test(content),
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
}: ScanCommitOptions): Promise<Finding[]> {
  const findings: Finding[] = [];
  const filesToScan = [...addedFiles, ...modifiedFiles];

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
        // Workflow files get both the general file rules AND the workflow-specific rules
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

  return findings;
}

export function scanFileContent(content: string, filePath?: string): Finding[] {
  return applyRules(FILE_RULES, content, filePath);
}

export function scanWorkflowContent(content: string, filePath?: string): Finding[] {
  return applyRules(WORKFLOW_RULES, content, filePath);
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

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
      // Silently skip regex errors on edge-case content
    }
  }

  return findings;
}
