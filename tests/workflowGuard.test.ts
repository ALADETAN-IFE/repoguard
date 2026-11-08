import yaml from "js-yaml";
import {
  injectRepoGuardIntoWorkflow,
  buildSuggestPRBody,
  suggestActionForRepo,
  suggestActionForTenant,
  STANDALONE_WORKFLOW_PATH,
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
    it("should detect when RepoGuard action is already configured and skip modification", () => {
      const existingWorkflow = `
name: CI
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ALADETAN-IFE/repoguard-action@v1
        with:
          fail-on: high
`;
      const result = injectRepoGuardIntoWorkflow(existingWorkflow);
      expect(result.alreadyConfigured).toBe(true);
      expect(result.modified).toBe(false);
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
      expect(parsed.jobs["repoguard-security-scan"].steps[1].uses).toBe(
        "ALADETAN-IFE/repoguard-action@v1",
      );

      // Root jobs (lint, test) should now have needs: [repoguard-security-scan]
      expect(parsed.jobs.lint.needs).toEqual(["repoguard-security-scan"]);
      expect(parsed.jobs.test.needs).toEqual(["repoguard-security-scan"]);

      // Downstream job (deploy) should retain its original needs
      expect(parsed.jobs.deploy.needs).toEqual(["test"]);
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
      expect(body).toContain("ALADETAN-IFE/repoguard-action@v1");
      expect(body).toContain("my-repo");
      expect(body).toContain("supply chain attacks");
      expect(body).toContain('fail-on: "high"');
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

    it("should return pr_already_open if a suggestion PR is already open", async () => {
      mockOctokit.request.mockResolvedValueOnce({
        data: [
          {
            number: 99,
            html_url: "https://github.com/org/repo/pull/99",
            head: { ref: "repoguard/ci-protection-12345" },
            title: "🛡️ Security: Protect CI/CD pipelines with RepoGuard",
          },
        ],
      });

      const res = await suggestActionForRepo(mockOctokit as any, "org", "repo");
      expect(res.status).toBe("pr_already_open");
      expect(res.prNumber).toBe(99);
    });

    it("should return already_configured if any workflow already includes repoguard action", async () => {
      // 1. Open PRs
      mockOctokit.request.mockResolvedValueOnce({ data: [] });
      // 2. Repo info
      mockOctokit.request.mockResolvedValueOnce({
        data: { default_branch: "main" },
      });
      // 3. Workflow list
      mockOctokit.request.mockResolvedValueOnce({
        data: [
          { name: "ci.yml", path: ".github/workflows/ci.yml", sha: "sha-ci" },
        ],
      });
      // 4. File content
      const content = Buffer.from(
        "uses: ALADETAN-IFE/repoguard-action@v1",
      ).toString("base64");
      mockOctokit.request.mockResolvedValueOnce({ data: { content } });

      const res = await suggestActionForRepo(mockOctokit as any, "org", "repo");
      expect(res.status).toBe("already_configured");
      expect(res.message).toContain("already configured");
    });

    it("should create branch, commit standalone workflow, and open PR when no workflows exist", async () => {
      // 1. Open PRs: none
      mockOctokit.request.mockResolvedValueOnce({ data: [] });
      // 2. Repo info
      mockOctokit.request.mockResolvedValueOnce({
        data: { default_branch: "main" },
      });
      // 3. Workflow list: 404 (no directory)
      const err404 = new Error("Not Found") as any;
      err404.status = 404;
      mockOctokit.request.mockRejectedValueOnce(err404);
      // 4. Git ref for base branch
      mockOctokit.request.mockResolvedValueOnce({
        data: { object: { sha: "base-sha-123" } },
      });
      // 5. Create ref
      mockOctokit.request.mockResolvedValueOnce({
        data: { ref: "refs/heads/repoguard/ci-protection" },
      });
      // 6. Commit file
      mockOctokit.request.mockResolvedValueOnce({ data: {} });
      // 7. Open PR
      mockOctokit.request.mockResolvedValueOnce({
        data: {
          number: 101,
          html_url: "https://github.com/org/repo/pull/101",
        },
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
