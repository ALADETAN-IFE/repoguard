import { getPushChangedFiles } from "../src/utils/pushChangedFiles";
import type { OctokitClient } from "../src/types";

describe("getPushChangedFiles", () => {
  it("uses compare API results when available", async () => {
    const requestMock = jest.fn().mockResolvedValue({
      data: {
        files: [
          { filename: ".gitignore", status: "modified" },
          { filename: "README.md", status: "modified" },
        ],
      },
    });

    const octokit = { request: requestMock } as unknown as OctokitClient;
    const before = "abc123";
    const after = "def456";

    const result = await getPushChangedFiles(
      octokit,
      "owner",
      "repo",
      before,
      after,
      [{ id: "def456", modified: [] }],
    );

    expect(requestMock).toHaveBeenCalledWith(
      "GET /repos/{owner}/{repo}/compare/{basehead}",
      { owner: "owner", repo: "repo", basehead: `${before}...${after}` },
    );
    expect(result.modified).toEqual([".gitignore", "README.md"]);
    expect(result.added).toEqual([]);
    expect(result.removed).toEqual([]);
  });

  it("falls back to webhook commit file lists when compare fails", async () => {
    const requestMock = jest
      .fn()
      .mockRejectedValue(new Error("Compare API unavailable"));

    const octokit = { request: requestMock } as unknown as OctokitClient;

    const result = await getPushChangedFiles(
      octokit,
      "owner",
      "repo",
      "abc123",
      "def456",
      [
        {
          id: "def456",
          modified: [".gitignore"],
          added: ["new-file.ts"],
          removed: ["old-file.ts"],
        },
      ],
    );

    expect(result.modified).toEqual([".gitignore"]);
    expect(result.added).toEqual(["new-file.ts"]);
    expect(result.removed).toEqual(["old-file.ts"]);
  });

  it("uses webhook file lists for new branches without a before SHA", async () => {
    const requestMock = jest.fn();
    const octokit = { request: requestMock } as unknown as OctokitClient;

    const result = await getPushChangedFiles(
      octokit,
      "owner",
      "repo",
      "0000000000000000000000000000000000000000",
      "def456",
      [{ id: "def456", modified: [".gitignore"] }],
    );

    expect(requestMock).not.toHaveBeenCalled();
    expect(result.modified).toEqual([".gitignore"]);
  });
});
