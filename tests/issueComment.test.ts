/**
 * Tests for src/webhooks/issueComment.ts
 *
 * handleIssueComment is an App factory. We test it by calling the returned
 * inner handler directly, mocking normaliseOctokit to return our mock client.
 */

jest.mock("../src/utils/normaliseOctokit", () => ({
  normaliseOctokit: jest.fn((x: unknown) => x),
}));

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

import { handleIssueComment, IssueCommentPayload } from "../src/webhooks/issueComment";
import { scanFullRepoForPush } from "../src/webhooks/installation";
import { openFixPR } from "../src/pullRequest";

describe("handleIssueComment", () => {
  let mockOctokit: { request: jest.Mock };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let innerHandler: (event: { octokit: unknown; payload: IssueCommentPayload }) => Promise<void>;

  beforeEach(() => {
    jest.clearAllMocks();
    mockOctokit = {
      request: jest.fn().mockResolvedValue({ data: {} }),
    };
    // Instantiate the factory with a null app (unused in tests)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    innerHandler = handleIssueComment(null as any) as any;
  });

  function makeEvent(
    payload: Partial<IssueCommentPayload> & {
      action: string;
      issue: IssueCommentPayload["issue"];
      comment: IssueCommentPayload["comment"];
      repository: IssueCommentPayload["repository"];
    },
  ) {
    return { octokit: mockOctokit, payload: payload as IssueCommentPayload };
  }

  it("returns early if payload action is not created", async () => {
    await innerHandler(
      makeEvent({
        action: "edited",
        issue: { number: 1, title: "RepoGuard Security Alert" },
        comment: { id: 10, body: "/fix", user: { login: "user1" } },
        repository: { owner: { login: "test-owner" }, name: "test-repo" },
      }),
    );
    expect(scanFullRepoForPush).not.toHaveBeenCalled();
  });

  it("returns early if comment body does not contain /fix command", async () => {
    await innerHandler(
      makeEvent({
        action: "created",
        issue: { number: 1, title: "RepoGuard Security Alert" },
        comment: { id: 10, body: "Hello, looking into this", user: { login: "user1" } },
        repository: { owner: { login: "test-owner" }, name: "test-repo" },
      }),
    );
    expect(scanFullRepoForPush).not.toHaveBeenCalled();
  });

  it("returns early if issue is not a RepoGuard security issue", async () => {
    await innerHandler(
      makeEvent({
        action: "created",
        issue: { number: 1, title: "Unrelated Bug Report" },
        comment: { id: 10, body: "/fix", user: { login: "user1" } },
        repository: { owner: { login: "test-owner" }, name: "test-repo" },
      }),
    );
    expect(scanFullRepoForPush).not.toHaveBeenCalled();
  });

  it("reacts with rocket emoji, rescans, calls openFixPR, and comments success message", async () => {
    const findings = [
      { rule: "curl-pipe-bash", severity: "critical" as const, message: "curl pipe bash", file: "test.sh" },
    ];
    (scanFullRepoForPush as jest.Mock).mockResolvedValue(findings);
    (openFixPR as jest.Mock).mockResolvedValue(undefined);

    await innerHandler(
      makeEvent({
        action: "created",
        issue: { number: 42, title: "⚠️ RepoGuard: Security findings" },
        comment: { id: 100, body: "/fix", user: { login: "admin" } },
        repository: { owner: { login: "test-owner" }, name: "test-repo" },
      }),
    );

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

  it("posts clean-up message and skips openFixPR when no findings remain", async () => {
    (scanFullRepoForPush as jest.Mock).mockResolvedValue([]);

    await innerHandler(
      makeEvent({
        action: "created",
        issue: { number: 42, title: "⚠️ RepoGuard: Security findings" },
        comment: { id: 101, body: "@repoguard fix", user: { login: "admin" } },
        repository: { owner: { login: "test-owner" }, name: "test-repo" },
      }),
    );

    expect(openFixPR).not.toHaveBeenCalled();
    expect(mockOctokit.request).toHaveBeenCalledWith(
      "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
      expect.objectContaining({ body: expect.stringContaining("No security issues remain") }),
    );
  });

  it("posts error comment and logs when openFixPR throws", async () => {
    (scanFullRepoForPush as jest.Mock).mockResolvedValue([
      { rule: "curl-pipe-bash", severity: "critical" as const, message: "test", file: "a.sh" },
    ]);
    (openFixPR as jest.Mock).mockRejectedValue(new Error("GitHub 403"));

    const logger = (await import("../src/utils/logger")).default;

    await innerHandler(
      makeEvent({
        action: "created",
        issue: { number: 7, title: "RepoGuard alert" },
        comment: { id: 200, body: "/fix", user: { login: "dev" } },
        repository: { owner: { login: "test-owner" }, name: "test-repo" },
      }),
    );

    expect(logger.error).toHaveBeenCalledWith(
      expect.stringContaining("Failed to generate fix"),
    );
    expect(mockOctokit.request).toHaveBeenCalledWith(
      "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
      expect.objectContaining({ body: expect.stringContaining("RepoGuard Error") }),
    );
  });
});
