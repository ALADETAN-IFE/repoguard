import { handlePullRequestClosed } from "../src/webhooks/pullRequest";
import { getOpenRepoGuardIssue, openFixPR } from "../src/pullRequest";
import { scanFullRepoForPush } from "../src/webhooks/installation";

jest.mock("../src/webhooks/installation", () => ({
  scanFullRepoForPush: jest.fn(),
}));

jest.mock("../src/pullRequest", () => ({
  getOpenRepoGuardIssue: jest.fn(),
  openFixPR: jest.fn(),
  postReviewComments: jest.fn(),
}));

const mockedScan = scanFullRepoForPush as jest.MockedFunction<
  typeof scanFullRepoForPush
>;
const mockedGetIssue = getOpenRepoGuardIssue as jest.MockedFunction<
  typeof getOpenRepoGuardIssue
>;
const mockedOpenFixPR = openFixPR as jest.MockedFunction<typeof openFixPR>;

describe("handlePullRequestClosed", () => {
  const findings = [
    {
      rule: "obfuscated-malware-pattern",
      severity: "critical" as const,
      message: "malware",
      file: "eslint.config.js",
    },
  ];

  beforeEach(() => {
    jest.clearAllMocks();
    mockedScan.mockResolvedValue(findings);
    mockedGetIssue.mockResolvedValue(undefined);
    mockedOpenFixPR.mockResolvedValue({
      pr: { number: 99, html_url: "https://github.com/o/r/pull/99" },
    });
  });

  it("does not auto-open a replacement Fix PR when RepoGuard closed the previous one", async () => {
    const requestMock = jest.fn().mockResolvedValue({ data: [] });
    const handler = handlePullRequestClosed({} as never);

    await handler({
      octokit: { request: requestMock } as never,
      payload: {
        action: "closed",
        pull_request: {
          number: 15,
          merged: false,
          head: { sha: "abc", ref: "repoguard/fixes-123" },
        },
        repository: {
          name: "ACAC-SONGS-APP",
          owner: { login: "ALADETAN-IFE" },
          default_branch: "main",
        },
        sender: { login: "repoguard-ifecodes[bot]", type: "Bot" },
      },
    } as never);

    expect(mockedOpenFixPR).not.toHaveBeenCalled();
  });

  it("opens a replacement Fix PR when a human closes an unmerged fix PR and findings remain", async () => {
    const requestMock = jest.fn().mockResolvedValue({ data: [] });
    const handler = handlePullRequestClosed({} as never);

    await handler({
      octokit: { request: requestMock } as never,
      payload: {
        action: "closed",
        pull_request: {
          number: 15,
          merged: false,
          head: { sha: "abc", ref: "repoguard/fixes-123" },
        },
        repository: {
          name: "ACAC-SONGS-APP",
          owner: { login: "ALADETAN-IFE" },
          default_branch: "main",
        },
        sender: { login: "ALADETAN-IFE", type: "User" },
      },
    } as never);

    expect(mockedOpenFixPR).toHaveBeenCalled();
  });
});
