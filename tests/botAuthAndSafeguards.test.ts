import { isAuthorizedFixBranchPusher } from "../src/utils/botAuth";
import { handlePullRequestOpened } from "../src/webhooks/pullRequest";
import { updateCheckRun } from "../src/checks";

jest.mock("prettier", () => ({
  getFileInfo: jest.fn().mockResolvedValue({ inferredParser: null }),
  format: jest.fn().mockImplementation((content: string) => Promise.resolve(content)),
}));

jest.mock("../src/utils/writeQueue", () => ({
  safeWrite: jest.fn().mockResolvedValue(undefined),
}));

jest.mock("../src/checks", () => ({
  createCheckRun: jest.fn().mockResolvedValue(777),
  updateCheckRun: jest.fn().mockResolvedValue(undefined),
}));

jest.mock("../src/alerts", () => ({
  sendAlert: jest.fn().mockResolvedValue(undefined),
}));

jest.mock("../src/models", () => ({
  Scan: {
    create: jest.fn().mockResolvedValue({ _id: { toHexString: () => "mockScanId" } }),
    findByIdAndUpdate: jest.fn().mockResolvedValue(undefined),
  },
  Installation: {
    findOne: jest.fn().mockResolvedValue(null),
  },
}));

jest.mock("../src/pullRequest", () => ({
  closeRepoGuardPRsAndIssues: jest.fn().mockResolvedValue(undefined),
  getOpenRepoGuardIssue: jest.fn().mockResolvedValue(null),
  hasOpenRepoGuardFixPR: jest.fn().mockResolvedValue(false),
  openFixPR: jest.fn().mockResolvedValue(undefined),
  postReviewComments: jest.fn().mockResolvedValue(undefined),
}));

jest.mock("../src/webhooks/installation", () => ({
  scanFullRepoForPush: jest.fn().mockResolvedValue([]),
  scanFullRepoWithDetails: jest.fn().mockResolvedValue({ findings: [], filesScanned: 0 }),
}));

describe("botAuth utility & Fix PR Safeguards", () => {
  describe("isAuthorizedFixBranchPusher", () => {
    it("recognizes exact known bot logins", () => {
      expect(isAuthorizedFixBranchPusher("repoguard-ifecodes[bot]")).toBe(true);
      expect(isAuthorizedFixBranchPusher("repoguard[bot]")).toBe(true);
      expect(isAuthorizedFixBranchPusher(undefined, "repoguard-ifecodes[bot]")).toBe(true);
      expect(isAuthorizedFixBranchPusher(undefined, "repoguard[bot]")).toBe(true);
    });

    it("recognizes bot logins ending with [bot] containing repoguard", () => {
      expect(isAuthorizedFixBranchPusher("my-repoguard-app[bot]")).toBe(true);
      expect(isAuthorizedFixBranchPusher(undefined, "repoguard-staging[bot]")).toBe(true);
    });

    it("recognizes sender with bot type containing repoguard", () => {
      expect(
        isAuthorizedFixBranchPusher("repoguard-action", "repoguard-action", "Bot"),
      ).toBe(true);
    });

    it("recognizes GitHub App slug names", () => {
      expect(isAuthorizedFixBranchPusher("repoguard")).toBe(true);
      expect(isAuthorizedFixBranchPusher("repoguard-ifecodes")).toBe(true);
      expect(isAuthorizedFixBranchPusher(undefined, "repoguard")).toBe(true);
    });

    it("rejects unauthorized human users and attackers", () => {
      expect(isAuthorizedFixBranchPusher("malicious-actor")).toBe(false);
      expect(isAuthorizedFixBranchPusher("octocat")).toBe(false);
      expect(isAuthorizedFixBranchPusher(undefined, "random-contributor")).toBe(false);
      expect(isAuthorizedFixBranchPusher("dependabot[bot]")).toBe(false);
      expect(isAuthorizedFixBranchPusher("renovate[bot]")).toBe(false);
    });

    it("handles undefined, null, or empty values safely", () => {
      expect(isAuthorizedFixBranchPusher()).toBe(false);
      expect(isAuthorizedFixBranchPusher("", "", "")).toBe(false);
    });
  });

  describe("handlePullRequestOpened Safeguards", () => {
    it("detects tampering on fix branch during synchronize and closes PR", async () => {
      const requestMock = jest.fn().mockImplementation((endpoint: string) => {
        if (endpoint.startsWith("POST /repos/{owner}/{repo}/issues/{issue_number}/comments")) {
          return Promise.resolve({ data: {} });
        }
        if (endpoint.startsWith("PATCH /repos/{owner}/{repo}/pulls/{pull_number}")) {
          return Promise.resolve({ data: {} });
        }
        if (endpoint.startsWith("DELETE /repos/{owner}/{repo}/git/refs/{ref}")) {
          return Promise.resolve({ data: {} });
        }
        return Promise.resolve({ data: {} });
      });

      const octokit = { request: requestMock } as any;
      const handler = handlePullRequestOpened({} as any);

      await handler({
        octokit,
        payload: {
          action: "synchronize",
          pull_request: {
            number: 42,
            head: { sha: "attacker123", ref: "repoguard/fixes-12345" },
            changed_files: 1,
          },
          repository: {
            name: "test-repo",
            owner: { login: "test-owner" },
          },
          sender: { login: "malicious-user", type: "User" },
        },
      });

      // Verify PR was closed and branch deleted
      expect(requestMock).toHaveBeenCalledWith(
        "PATCH /repos/{owner}/{repo}/pulls/{pull_number}",
        expect.objectContaining({ pull_number: 42, state: "closed" }),
      );
      expect(requestMock).toHaveBeenCalledWith(
        "DELETE /repos/{owner}/{repo}/git/refs/{ref}",
        expect.objectContaining({ ref: "heads/repoguard/fixes-12345" }),
      );
    });

    it("detects obsolete Fix PR with 0 diff and auto-closes it", async () => {
      const requestMock = jest.fn().mockImplementation((endpoint: string) => {
        if (endpoint.startsWith("GET /repos/{owner}/{repo}/pulls/{pull_number}/files")) {
          return Promise.resolve({ data: [] }); // 0 changed files!
        }
        if (endpoint.startsWith("POST /repos/{owner}/{repo}/issues/{issue_number}/comments")) {
          return Promise.resolve({ data: {} });
        }
        if (endpoint.startsWith("PATCH /repos/{owner}/{repo}/pulls/{pull_number}")) {
          return Promise.resolve({ data: {} });
        }
        if (endpoint.startsWith("DELETE /repos/{owner}/{repo}/git/refs/{ref}")) {
          return Promise.resolve({ data: {} });
        }
        return Promise.resolve({ data: {} });
      });

      const octokit = { request: requestMock } as any;
      const handler = handlePullRequestOpened({} as any);

      await handler({
        octokit,
        payload: {
          action: "synchronize",
          pull_request: {
            number: 88,
            head: { sha: "reverted123", ref: "repoguard/fixes-99999" },
            changed_files: 0,
          },
          repository: {
            name: "test-repo",
            owner: { login: "test-owner" },
          },
          sender: { login: "repoguard[bot]", type: "Bot" },
        },
      });

      // Verify PR was closed and branch deleted
      expect(requestMock).toHaveBeenCalledWith(
        "PATCH /repos/{owner}/{repo}/pulls/{pull_number}",
        expect.objectContaining({ pull_number: 88, state: "closed" }),
      );
      expect(requestMock).toHaveBeenCalledWith(
        "DELETE /repos/{owner}/{repo}/git/refs/{ref}",
        expect.objectContaining({ ref: "heads/repoguard/fixes-99999" }),
      );
    });
  });

  describe("handlePush Safeguards", () => {
    it("detects unauthorized push to fix branch, fails check run, closes PR, and deletes branch", async () => {
      const { handlePush } = await import("../src/webhooks/push");

      const requestMock = jest.fn().mockImplementation((endpoint: string) => {
        if (endpoint === "POST /repos/{owner}/{repo}/check-runs") {
          return Promise.resolve({ data: { id: 777 } });
        }
        if (endpoint.startsWith("PATCH /repos/{owner}/{repo}/check-runs/")) {
          return Promise.resolve({ data: {} });
        }
        if (endpoint.startsWith("GET /repos/{owner}/{repo}/pulls")) {
          return Promise.resolve({
            data: [{ number: 55, head: { ref: "repoguard/fixes-5555" } }],
          });
        }
        if (endpoint.startsWith("POST /repos/{owner}/{repo}/issues/{issue_number}/comments")) {
          return Promise.resolve({ data: {} });
        }
        if (endpoint.startsWith("PATCH /repos/{owner}/{repo}/pulls/{pull_number}")) {
          return Promise.resolve({ data: {} });
        }
        if (endpoint.startsWith("DELETE /repos/{owner}/{repo}/git/refs/{ref}")) {
          return Promise.resolve({ data: {} });
        }
        return Promise.resolve({ data: {} });
      });

      const octokit = { request: requestMock } as any;
      const handler = handlePush({} as any);

      await handler({
        octokit,
        payload: {
          ref: "refs/heads/repoguard/fixes-5555",
          before: "old123",
          after: "new456",
          forced: true,
          commits: [],
          pusher: { name: "attacker-user" },
          repository: {
            name: "test-repo",
            owner: { login: "test-owner" },
            default_branch: "main",
          },
        },
      });

      // Verify check run was failed via the mocked updateCheckRun
      expect(updateCheckRun).toHaveBeenCalledWith(
        expect.objectContaining({ conclusion: "failure" }),
      );
      // Verify PR was closed
      expect(requestMock).toHaveBeenCalledWith(
        "PATCH /repos/{owner}/{repo}/pulls/{pull_number}",
        expect.objectContaining({ pull_number: 55, state: "closed" }),
      );
      // Verify branch was deleted
      expect(requestMock).toHaveBeenCalledWith(
        "DELETE /repos/{owner}/{repo}/git/refs/{ref}",
        expect.objectContaining({ ref: "heads/repoguard/fixes-5555" }),
      );
    });
  });
});
