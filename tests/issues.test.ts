/**
 * Tests for src/webhooks/issues.ts
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

import { handleIssuesOpened, IssuesOpenedPayload } from "../src/webhooks/issues";
import { scanFullRepoForPush } from "../src/webhooks/installation";
import { openFixPR } from "../src/pullRequest";

describe("handleIssuesOpened", () => {
  let mockOctokit: { request: jest.Mock };
  let innerHandler: (event: { octokit: unknown; payload: IssuesOpenedPayload }) => Promise<void>;

  beforeEach(() => {
    jest.clearAllMocks();
    mockOctokit = {
      request: jest.fn().mockResolvedValue({ data: {} }),
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    innerHandler = handleIssuesOpened(null as any) as any;
  });

  function makeEvent(
    payload: Partial<IssuesOpenedPayload> & {
      action: string;
      issue: IssuesOpenedPayload["issue"];
      repository: IssuesOpenedPayload["repository"];
    },
  ) {
    return { octokit: mockOctokit, payload: payload as IssuesOpenedPayload };
  }

  it("returns early if action is not opened", async () => {
    await innerHandler(
      makeEvent({
        action: "edited",
        issue: { number: 1, title: "Repoguard", body: "/repoguard scan" },
        repository: { owner: { login: "owner" }, name: "repo" },
      }),
    );
    expect(scanFullRepoForPush).not.toHaveBeenCalled();
  });

  it("returns early if title does not match Repoguard", async () => {
    await innerHandler(
      makeEvent({
        action: "opened",
        issue: { number: 1, title: "Random Title", body: "/repoguard scan" },
        repository: { owner: { login: "owner" }, name: "repo" },
      }),
    );
    expect(scanFullRepoForPush).not.toHaveBeenCalled();
  });

  it("returns early if body does not match /repoguard scan", async () => {
    await innerHandler(
      makeEvent({
        action: "opened",
        issue: { number: 1, title: "Repoguard", body: "Please check this bug" },
        repository: { owner: { login: "owner" }, name: "repo" },
      }),
    );
    expect(scanFullRepoForPush).not.toHaveBeenCalled();
  });

  it("triggers scan and comments PR markdown link when openFixPR creates a PR", async () => {
    const findings = [
      { rule: "curl-pipe-bash", severity: "critical" as const, message: "curl pipe bash", file: "script.sh" },
    ];
    (scanFullRepoForPush as jest.Mock).mockResolvedValue(findings);
    (openFixPR as jest.Mock).mockResolvedValue({
      pr: { number: 4, html_url: "https://github.com/owner/repo/pull/4" },
    });

    await innerHandler(
      makeEvent({
        action: "opened",
        issue: { number: 12, title: "Repoguard", body: "/repoguard scan" },
        repository: { owner: { login: "owner" }, name: "repo" },
      }),
    );

    // Initial comment
    expect(mockOctokit.request).toHaveBeenCalledWith(
      "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
      expect.objectContaining({
        owner: "owner",
        repo: "repo",
        issue_number: 12,
        body: expect.stringContaining("RepoGuard scanning triggered!"),
      }),
    );

    expect(scanFullRepoForPush).toHaveBeenCalledWith(mockOctokit, "owner", "repo");
    expect(openFixPR).toHaveBeenCalledWith(mockOctokit, { owner: "owner", repo: "repo", findings });

    // Result comment with PR markdown link
    expect(mockOctokit.request).toHaveBeenCalledWith(
      "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
      expect.objectContaining({
        owner: "owner",
        repo: "repo",
        issue_number: 12,
        body: "A pr was created [PR4](https://github.com/owner/repo/pull/4)",
      }),
    );
  });

  it("triggers scan and comments issue markdown link when openFixPR creates an issue", async () => {
    const findings = [
      { rule: "hardcoded-secret", severity: "high" as const, message: "secret leaked", file: "config.js" },
    ];
    (scanFullRepoForPush as jest.Mock).mockResolvedValue(findings);
    (openFixPR as jest.Mock).mockResolvedValue({
      issue: { number: 4, html_url: "https://github.com/owner/repo/issues/4" },
    });

    await innerHandler(
      makeEvent({
        action: "opened",
        issue: { number: 15, title: "Repoguard", body: "/repoguard scan" },
        repository: { owner: { login: "owner" }, name: "repo" },
      }),
    );

    expect(mockOctokit.request).toHaveBeenCalledWith(
      "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
      expect.objectContaining({
        owner: "owner",
        repo: "repo",
        issue_number: 15,
        body: "An issue was created [PR4](https://github.com/owner/repo/issues/4)",
      }),
    );
  });

  it("posts clean comment when no findings are detected", async () => {
    (scanFullRepoForPush as jest.Mock).mockResolvedValue([]);

    await innerHandler(
      makeEvent({
        action: "opened",
        issue: { number: 20, title: "Repoguard", body: "/repoguard scan" },
        repository: { owner: { login: "owner" }, name: "repo" },
      }),
    );

    expect(openFixPR).not.toHaveBeenCalled();
    expect(mockOctokit.request).toHaveBeenCalledWith(
      "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
      expect.objectContaining({
        owner: "owner",
        repo: "repo",
        issue_number: 20,
        body: expect.stringContaining("No security issues found"),
      }),
    );
  });
});
