import { handleIssueComment, IssueCommentPayload } from "../src/webhooks/issueComment";

jest.mock("../src/webhooks/installation", () => ({
  scanFullRepoForPush: jest.fn(),
}));

jest.mock("../src/pullRequest", () => ({
  openFixPR: jest.fn(),
}));

jest.mock("../src/utils/logger", () => ({
  __esModule: true,
  default: { info: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

import { scanFullRepoForPush } from "../src/webhooks/installation";
import { openFixPR } from "../src/pullRequest";

describe("handleIssueComment", () => {
  let mockOctokit: { request: jest.Mock };

  beforeEach(() => {
    jest.clearAllMocks();
    mockOctokit = {
      request: jest.fn().mockResolvedValue({ data: {} }),
    };
  });

  it("returns false if payload action is not created", async () => {
    const payload: IssueCommentPayload = {
      action: "edited",
      issue: { number: 1, title: "RepoGuard Security Alert" },
      comment: { id: 10, body: "/fix", user: { login: "user1" } },
      repository: { owner: { login: "test-owner" }, name: "test-repo" },
    };

    const result = await handleIssueComment(mockOctokit as any, payload);
    expect(result).toBe(false);
  });

  it("returns false if comment body does not contain /fix command", async () => {
    const payload: IssueCommentPayload = {
      action: "created",
      issue: { number: 1, title: "RepoGuard Security Alert" },
      comment: { id: 10, body: "Hello, looking into this", user: { login: "user1" } },
      repository: { owner: { login: "test-owner" }, name: "test-repo" },
    };

    const result = await handleIssueComment(mockOctokit as any, payload);
    expect(result).toBe(false);
  });

  it("returns false if issue is not a RepoGuard security issue", async () => {
    const payload: IssueCommentPayload = {
      action: "created",
      issue: { number: 1, title: "Unrelated Bug Report" },
      comment: { id: 10, body: "/fix", user: { login: "user1" } },
      repository: { owner: { login: "test-owner" }, name: "test-repo" },
    };

    const result = await handleIssueComment(mockOctokit as any, payload);
    expect(result).toBe(false);
  });

  it("reacts with rocket emoji, rescans repo, calls openFixPR, and comments success message", async () => {
    const findings = [
      { rule: "curl-pipe-bash", severity: "critical" as const, message: "curl pipe bash", file: "test.sh" },
    ];
    (scanFullRepoForPush as jest.Mock).mockResolvedValue(findings);
    (openFixPR as jest.Mock).mockResolvedValue(undefined);

    const payload: IssueCommentPayload = {
      action: "created",
      issue: { number: 42, title: "⚠️ RepoGuard: Security findings" },
      comment: { id: 100, body: "/fix", user: { login: "admin" } },
      repository: { owner: { login: "test-owner" }, name: "test-repo" },
    };

    const result = await handleIssueComment(mockOctokit as any, payload);

    expect(result).toBe(true);
    expect(mockOctokit.request).toHaveBeenCalledWith(
      "POST /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions",
      { owner: "test-owner", repo: "test-repo", comment_id: 100, content: "rocket" },
    );
    expect(scanFullRepoForPush).toHaveBeenCalledWith(mockOctokit, "test-owner", "test-repo");
    expect(openFixPR).toHaveBeenCalledWith(mockOctokit, { owner: "test-owner", repo: "test-repo", findings });
    expect(mockOctokit.request).toHaveBeenCalledWith(
      "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
      expect.objectContaining({
        owner: "test-owner",
        repo: "test-repo",
        issue_number: 42,
        body: expect.stringContaining("Fix Triggered"),
      }),
    );
  });

  it("handles zero remaining findings gracefully", async () => {
    (scanFullRepoForPush as jest.Mock).mockResolvedValue([]);

    const payload: IssueCommentPayload = {
      action: "created",
      issue: { number: 42, title: "⚠️ RepoGuard: Security findings" },
      comment: { id: 101, body: "@repoguard fix", user: { login: "admin" } },
      repository: { owner: { login: "test-owner" }, name: "test-repo" },
    };

    const result = await handleIssueComment(mockOctokit as any, payload);

    expect(result).toBe(true);
    expect(openFixPR).not.toHaveBeenCalled();
    expect(mockOctokit.request).toHaveBeenCalledWith(
      "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
      expect.anything(),
    );
  });
});
