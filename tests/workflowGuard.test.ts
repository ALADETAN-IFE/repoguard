import yaml from "js-yaml";
import {
  injectRepoGuardIntoWorkflow,
  buildSuggestPRBody,
  suggestActionForRepo,
  suggestActionForTenant,
  STANDALONE_WORKFLOW_PATH,
  FALLBACK_ACTION_SHA,
} from "../src/services/workflowGuardService";
import { Installation } from "../src/models";

jest.mock("../src/models", () => ({
  Installation: {
    findOneAndUpdate: jest.fn().mockResolvedValue({}),
    find: jest.fn(),
  },
}));

jest.mock("../src/utils/logger", () => ({
  __esModule: true,
  default: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}));

describe("workflowGuardService", () => {
  describe("injectRepoGuardIntoWorkflow", () => {
    it("should detect when RepoGuard action is already configured with pinned SHA and skip modification", () => {
      const existingWorkflow = `
name: CI
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: ALADETAN-IFE/repoguard-action@${FALLBACK_ACTION_SHA} # v1
        with:
          fail-on: high
`;
      const result = injectRepoGuardIntoWorkflow(existingWorkflow);
      expect(result.alreadyConfigured).toBe(true);
      expect(result.modified).toBe(false);
    });

    it("should pin unpinned @v1 action in existing workflow", () => {
      const existingWorkflow = `
name: CI
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: ALADETAN-IFE/repoguard-action@v1
        with:
          fail-on: high
`;
      const result = injectRepoGuardIntoWorkflow(existingWorkflow);
      expect(result.alreadyConfigured).toBe(false);
      expect(result.modified).toBe(true);
      expect(result.newContent).toContain(
        `uses: ALADETAN-IFE/repoguard-action@${FALLBACK_ACTION_SHA} # v1`,
      );
    });

    it("should upgrade an outdated commit SHA to the latest pinned SHA", () => {
      const oldShaWorkflow = `
name: CI
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: ALADETAN-IFE/repoguard-action@4436f1e184cbbb7eca932269f8cc8fc5e31ddb2a # v1
        with:
          fail-on: high
`;
      const result = injectRepoGuardIntoWorkflow(oldShaWorkflow);
      expect(result.alreadyConfigured).toBe(false);
      expect(result.modified).toBe(true);
      expect(result.newContent).toContain(
        `uses: ALADETAN-IFE/repoguard-action@${FALLBACK_ACTION_SHA} # v1`,
      );
    });

    it("should inject repoguard-security-scan job and attach needs to all root jobs", () => {
      const standardCi = `
name: Build & Test
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run lint

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  deploy:
    needs: [test]
    runs-on: ubuntu-latest
    steps:
      - run: echo deploy
`;

      const result = injectRepoGuardIntoWorkflow(standardCi);
      expect(result.modified).toBe(true);
      expect(result.alreadyConfigured).toBe(false);
      expect(result.newContent).toBeDefined();

      const parsed = yaml.load(result.newContent!) as any;
      expect(parsed.jobs["repoguard-security-scan"]).toBeDefined();
      expect(parsed.jobs["repoguard-security-scan"].steps[0].uses).toBe(
        "actions/checkout@v6",
      );
      expect(parsed.jobs["repoguard-security-scan"].steps[1].uses).toContain(
        `ALADETAN-IFE/repoguard-action@${FALLBACK_ACTION_SHA}`,
      );

      // Root jobs (lint, test) should now have needs: [repoguard-security-scan]
      expect(parsed.jobs.lint.needs).toEqual(["repoguard-security-scan"]);
      expect(parsed.jobs.test.needs).toEqual(["repoguard-security-scan"]);

      // Downstream job (deploy) should retain its original needs
      expect(parsed.jobs.deploy.needs).toEqual(["test"]);
    });

    it("should surgically preserve comments, workflow_dispatch without null, and custom triggers", () => {
      const complexCi = `# -----------------------------
# FRONTEND CI/CD PIPELINE
# -----------------------------
name: Frontend CI/CD Pipeline

on:
  workflow_dispatch:
  push:
    branches:
      - main
      - staging

jobs:

  # BUILD & CHECK JOB
  compile-app:
    name: Build Frontend
    runs-on: ubuntu-latest
    steps:
      - run: pnpm build

  deploy-app:
    needs: [compile-app]
    runs-on: ubuntu-latest
    steps:
      - run: echo deploy
`;

      const result = injectRepoGuardIntoWorkflow(complexCi);
      expect(result.modified).toBe(true);
      expect(result.newContent).toBeDefined();

      // Comments must be preserved
      expect(result.newContent).toContain("# FRONTEND CI/CD PIPELINE");
      expect(result.newContent).toContain("# BUILD & CHECK JOB");

      // workflow_dispatch must NOT have ': null'
      expect(result.newContent).toContain("workflow_dispatch:");
      expect(result.newContent).not.toContain("workflow_dispatch: null");

      // 'on:' must not be quoted
      expect(result.newContent).toContain("\non:\n");
      expect(result.newContent).not.toContain("'on':");

      // checkout should use v6
      expect(result.newContent).toContain("uses: actions/checkout@v6");

      // compile-app (the root job) should have needs: [repoguard-security-scan]
      const parsed = yaml.load(result.newContent!) as any;
      expect(parsed.jobs["compile-app"].needs).toEqual([
        "repoguard-security-scan",
      ]);
      expect(parsed.jobs["deploy-app"].needs).toEqual(["compile-app"]);
    });

    it("should handle single job workflows gracefully", () => {
      const singleJob = `
name: Quick Check
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm run build
`;
      const result = injectRepoGuardIntoWorkflow(singleJob);
      expect(result.modified).toBe(true);
      const parsed = yaml.load(result.newContent!) as any;
      expect(parsed.jobs.build.needs).toEqual(["repoguard-security-scan"]);
    });

    it("should reject invalid YAML or empty job definitions", () => {
      expect(injectRepoGuardIntoWorkflow("foo: [bar").modified).toBe(false);
      expect(injectRepoGuardIntoWorkflow("name: CI\njobs: []").modified).toBe(
        false,
      );
      expect(injectRepoGuardIntoWorkflow("name: CI").modified).toBe(false);
    });
  });

  describe("buildSuggestPRBody", () => {
    it("should generate descriptive markdown documentation explaining CI supply chain defense", () => {
      const body = buildSuggestPRBody(
        "my-repo",
        ".github/workflows/ci.yml",
        false,
      );
      expect(body).toContain("RepoGuard Pre-Execution Security Gate");
      expect(body).toContain("ALADETAN-IFE/repoguard-action");
      expect(body).toContain("my-repo");
      expect(body).toContain("supply chain attacks");
      expect(body).toContain('fail-on: "high"');
      expect(body).toContain(
        "https://github.com/marketplace/actions/repoguard-security-scan",
      );
    });
  });

  describe("suggestActionForRepo", () => {
    let mockOctokit: { request: jest.Mock };

    beforeEach(() => {
      jest.clearAllMocks();
      mockOctokit = {
        request: jest.fn(),
      };
    });

    it("should return pr_already_open if a suggestion PR is already open and pinned", async () => {
      mockOctokit.request.mockImplementation((route: string) => {
        if (route === "GET /repos/{owner}/{repo}/pulls") {
          return Promise.resolve({
            data: [
              {
                number: 99,
                html_url: "https://github.com/org/repo/pull/99",
                head: { ref: "repoguard/ci-protection-12345" },
                title:
                  "🛡️ Security: Protect CI/CD pipelines with RepoGuard Pre-Execution Security Gate",
              },
            ],
          });
        }
        if (route === "GET /repos/{owner}/{repo}/pulls/{pull_number}/files") {
          return Promise.resolve({
            data: [
              { filename: ".github/workflows/ci_cd.yml", status: "modified" },
            ],
          });
        }
        if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
          return Promise.resolve({
            data: {
              content: Buffer.from(
                `uses: ALADETAN-IFE/repoguard-action@${FALLBACK_ACTION_SHA} # v1\n`,
              ).toString("base64"),
              sha: "file-sha",
            },
          });
        }
        return Promise.resolve({ data: [] });
      });

      const res = await suggestActionForRepo(mockOctokit as any, "org", "repo");
      expect(res.status).toBe("pr_already_open");
      expect(res.prNumber).toBe(99);
    });

    it("should update existing open PR if it contains unpinned @v1", async () => {
      mockOctokit.request.mockImplementation((route: string) => {
        if (route === "GET /repos/{owner}/{repo}/pulls") {
          return Promise.resolve({
            data: [
              {
                number: 99,
                html_url: "https://github.com/org/repo/pull/99",
                head: { ref: "repoguard/ci-protection-12345" },
                title:
                  "🛡️ Security: Protect CI/CD pipelines with RepoGuard Pre-Execution Security Gate",
              },
            ],
          });
        }
        if (route === "GET /repos/{owner}/{repo}/pulls/{pull_number}/files") {
          return Promise.resolve({
            data: [
              { filename: ".github/workflows/ci_cd.yml", status: "modified" },
            ],
          });
        }
        if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
          return Promise.resolve({
            data: {
              content: Buffer.from(
                "uses: ALADETAN-IFE/repoguard-action@v1\n",
              ).toString("base64"),
              sha: "file-sha",
            },
          });
        }
        if (route === "PUT /repos/{owner}/{repo}/contents/{path}") {
          return Promise.resolve({ data: {} });
        }
        return Promise.resolve({ data: [] });
      });

      const res = await suggestActionForRepo(mockOctokit as any, "org", "repo");
      expect(res.status).toBe("updated");
      expect(res.prNumber).toBe(99);
      expect(mockOctokit.request).toHaveBeenCalledWith(
        "PUT /repos/{owner}/{repo}/contents/{path}",
        expect.objectContaining({
          branch: "repoguard/ci-protection-12345",
          message: expect.stringContaining(
            "pin RepoGuard action to commit SHA",
          ),
        }),
      );
    });

    it("should return already_configured if any workflow already includes repoguard action pinned to SHA", async () => {
      mockOctokit.request.mockImplementation((route: string, params?: any) => {
        if (route === "GET /repos/{owner}/{repo}/pulls") {
          return Promise.resolve({ data: [] });
        }
        if (route === "GET /repos/{owner}/{repo}") {
          return Promise.resolve({ data: { default_branch: "main" } });
        }
        if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
          if (params?.path === ".github/workflows") {
            return Promise.resolve({
              data: [
                {
                  name: "ci.yml",
                  path: ".github/workflows/ci.yml",
                  sha: "sha-ci",
                },
              ],
            });
          }
          return Promise.resolve({
            data: {
              content: Buffer.from(
                `uses: ALADETAN-IFE/repoguard-action@${FALLBACK_ACTION_SHA} # v1\n`,
              ).toString("base64"),
              sha: "sha-ci",
            },
          });
        }
        return Promise.resolve({ data: [] });
      });

      const res = await suggestActionForRepo(mockOctokit as any, "org", "repo");
      expect(res.status).toBe("already_configured");
      expect(res.message).toContain("already configured and pinned");
    });

    it("should open PR to pin action if default branch has unpinned @v1", async () => {
      mockOctokit.request.mockImplementation((route: string, params?: any) => {
        if (route === "GET /repos/{owner}/{repo}/pulls") {
          return Promise.resolve({ data: [] });
        }
        if (route === "GET /repos/{owner}/{repo}") {
          return Promise.resolve({ data: { default_branch: "main" } });
        }
        if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
          if (params?.path === ".github/workflows") {
            return Promise.resolve({
              data: [
                {
                  name: "ci.yml",
                  path: ".github/workflows/ci.yml",
                  sha: "sha-unpinned",
                },
              ],
            });
          }
          return Promise.resolve({
            data: {
              content: Buffer.from(
                "uses: ALADETAN-IFE/repoguard-action@v1\n",
              ).toString("base64"),
              sha: "sha-unpinned",
            },
          });
        }
        if (route === "GET /repos/{owner}/{repo}/git/ref/{ref}") {
          return Promise.resolve({ data: { object: { sha: "base-sha" } } });
        }
        if (route === "POST /repos/{owner}/{repo}/git/refs") {
          return Promise.resolve({ data: {} });
        }
        if (route === "PUT /repos/{owner}/{repo}/contents/{path}") {
          return Promise.resolve({ data: {} });
        }
        if (route === "POST /repos/{owner}/{repo}/pulls") {
          return Promise.resolve({
            data: {
              number: 102,
              html_url: "https://github.com/org/repo/pull/102",
            },
          });
        }
        return Promise.resolve({ data: [] });
      });

      const res = await suggestActionForRepo(mockOctokit as any, "org", "repo");
      expect(res.status).toBe("created");
      expect(res.prNumber).toBe(102);
      expect(res.message).toContain("to pin RepoGuard Action commit SHA");
    });

    it("should create branch, commit standalone workflow, and open PR when no workflows exist", async () => {
      mockOctokit.request.mockImplementation((route: string) => {
        if (route === "GET /repos/{owner}/{repo}/pulls") {
          return Promise.resolve({ data: [] });
        }
        if (route === "GET /repos/{owner}/{repo}") {
          return Promise.resolve({ data: { default_branch: "main" } });
        }
        if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
          const err404 = new Error("Not Found") as any;
          err404.status = 404;
          return Promise.reject(err404);
        }
        if (route === "GET /repos/{owner}/{repo}/git/ref/{ref}") {
          return Promise.resolve({ data: { object: { sha: "base-sha-123" } } });
        }
        if (route === "POST /repos/{owner}/{repo}/git/refs") {
          return Promise.resolve({
            data: { ref: "refs/heads/repoguard/ci-protection" },
          });
        }
        if (route === "PUT /repos/{owner}/{repo}/contents/{path}") {
          return Promise.resolve({ data: {} });
        }
        if (route === "POST /repos/{owner}/{repo}/pulls") {
          return Promise.resolve({
            data: {
              number: 101,
              html_url: "https://github.com/org/repo/pull/101",
            },
          });
        }
        return Promise.resolve({ data: [] });
      });

      const res = await suggestActionForRepo(mockOctokit as any, "org", "repo");
      expect(res.status).toBe("created");
      expect(res.prNumber).toBe(101);
      expect(res.prUrl).toBe("https://github.com/org/repo/pull/101");

      // Verify file path committed was STANDALONE_WORKFLOW_PATH
      expect(mockOctokit.request).toHaveBeenCalledWith(
        "PUT /repos/{owner}/{repo}/contents/{path}",
        expect.objectContaining({
          path: STANDALONE_WORKFLOW_PATH,
        }),
      );
    });

    it("should rollback and delete created branch if committing workflow fails", async () => {
      mockOctokit.request.mockImplementation((route: string) => {
        if (route === "GET /repos/{owner}/{repo}/pulls") {
          return Promise.resolve({ data: [] });
        }
        if (route === "GET /repos/{owner}/{repo}") {
          return Promise.resolve({ data: { default_branch: "main" } });
        }
        if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
          const err = new Error("404") as any;
          err.status = 404;
          return Promise.reject(err);
        }
        if (route === "GET /repos/{owner}/{repo}/git/ref/{ref}") {
          return Promise.resolve({ data: { object: { sha: "base-sha" } } });
        }
        if (route === "POST /repos/{owner}/{repo}/git/refs") {
          return Promise.resolve({ data: {} });
        }
        if (route === "PUT /repos/{owner}/{repo}/contents/{path}") {
          return Promise.reject(
            new Error(
              "Resource not accessible by integration - https://docs.github.com/rest/repos/contents#create-or-update-file-contents",
            ),
          );
        }
        if (route === "DELETE /repos/{owner}/{repo}/git/refs/{ref}") {
          return Promise.resolve({ data: {} });
        }
        return Promise.resolve({ data: [] });
      });

      const res = await suggestActionForRepo(mockOctokit as any, "org", "repo");
      expect(res.status).toBe("error");
      expect(res.message).toContain("Workflows: Read and write");
      expect(mockOctokit.request).toHaveBeenCalledWith(
        "DELETE /repos/{owner}/{repo}/git/refs/{ref}",
        expect.objectContaining({
          owner: "org",
          repo: "repo",
          ref: expect.stringMatching(/^heads\/repoguard\/ci-protection-/),
        }),
      );
    });
  });

  describe("suggestActionForTenant", () => {
    it("should process targetRepo and update Installation record in MongoDB", async () => {
      const mockOctokit = {
        request: jest.fn().mockImplementation((route: string) => {
          if (route === "GET /repos/{owner}/{repo}/pulls") {
            return Promise.resolve({ data: [] });
          }
          if (route === "GET /repos/{owner}/{repo}") {
            return Promise.resolve({ data: { default_branch: "main" } });
          }
          if (route === "GET /repos/{owner}/{repo}/contents/{path}") {
            const err = new Error("404") as any;
            err.status = 404;
            return Promise.reject(err);
          }
          if (route === "GET /repos/{owner}/{repo}/git/ref/{ref}") {
            return Promise.resolve({ data: { object: { sha: "base-sha" } } });
          }
          if (route === "POST /repos/{owner}/{repo}/git/refs") {
            return Promise.resolve({ data: {} });
          }
          if (route === "PUT /repos/{owner}/{repo}/contents/{path}") {
            return Promise.resolve({ data: {} });
          }
          if (route === "POST /repos/{owner}/{repo}/pulls") {
            return Promise.resolve({
              data: {
                number: 42,
                html_url: "https://github.com/org/repo/pull/42",
              },
            });
          }
          return Promise.resolve({ data: {} });
        }),
      };

      const results = await suggestActionForTenant(
        mockOctokit as any,
        "test-org",
        "test-repo",
      );
      expect(results).toHaveLength(1);
      expect(results[0].status).toBe("created");
      expect(results[0].prNumber).toBe(42);

      expect(Installation.findOneAndUpdate).toHaveBeenCalledWith(
        { owner: "test-org" },
        expect.objectContaining({
          actionPRNumber: 42,
        }),
      );
    });
  });
});
