# ============================================================
# REPOGUARD — MANUAL REVIEW REQUIRED: tests/scanner.test.ts
# Scanned: 2026-06-14T19:49:20.547Z
# The following findings could NOT be automatically patched:
#   [CRITICAL] wget-pipe-shell: wget output piped to shell
#   [HIGH] crypto-miner-keywords: Cryptocurrency miner indicators
#   [HIGH] env-exfiltration: Environment variable exfiltration — secrets being sent externally
#   [MEDIUM] hardcoded-secret: Possible hardcoded credential or API key
# ============================================================

import { scanFileContent, scanWorkflowContent, scanCommit } from "../src/scanner";
import logger from "../src/utils/logger";
import type { Finding } from "../src/types";

const findRule = (findings: Finding[], ruleId: string): boolean =>
  findings.some((f) => f.rule === ruleId);

// ─── File scanner tests ───────────────────────────────────────────────────────

describe("scanFileContent", () => {
  it("detects curl|bash (remote code execution)", () => {
    const findings = scanFileContent("# REMOVED BY REPOGUARD: curl|bash remote execution", "setup.sh");
    expect(findRule(findings, "curl-pipe-bash")).toBe(true);
  });

  it("detects wget|sh", () => {
    const findings = scanFileContent("# REMOVED BY REPOGUARD: wget|shell remote execution", "install.sh");
    expect(findRule(findings, "wget-pipe-shell")).toBe(true);
  });

  it("detects reverse shell", () => {
    const findings = scanFileContent("# REMOVED BY REPOGUARD: reverse shell
    expect(findRule(findings, "reverse-shell")).toBe(true);
  });

  it("detects base64 + eval obfuscation", () => {
    const encoded = Buffer.from("require('child_process').exec('rm -rf /')").toString("base64");
    const findings = scanFileContent(`eval(Buffer.from("${encoded}","base64").toString())`, "index.js");
    expect(findRule(findings, "obfuscated-base64")).toBe(true);
  });

  it("detects obfuscated string array malware", () => {
    const malware = `// REMOVED BY REPOGUARD: createRequire import for malware\n// REMOVED BY REPOGUARD: require definition for malware\n
// REMOVED BY REPOGUARD: obfuscated malware payload
