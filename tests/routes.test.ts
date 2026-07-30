import type { Request, Response } from "express";

// ─── Mocks (must be declared before importing routes) ─────────────────────────

// Mock prettier and pullRequest to prevent dynamic import issues
jest.mock("prettier", () => ({
  getFileInfo: jest.fn().mockResolvedValue({ inferredParser: null }),
  format: jest.fn().mockImplementation((content: string) => Promise.resolve(content)),
}));

jest.mock("../src/pullRequest", () => ({
  openFixPR: jest.fn().mockResolvedValue(undefined),
  closeRepoGuardPRsAndIssues: jest.fn().mockResolvedValue(undefined),
  postReviewComments: jest.fn().mockResolvedValue(undefined),
}));

jest.mock("../src/config/redis", () => ({ redis: null }));

jest.mock("../src/config/db", () => ({
  connectDatabase: jest.fn(),
}));

// Mock githubApp before middleware loads
jest.mock("../src/config/githubApp", () => ({
  githubApp: {
    webhooks: { on: jest.fn(), onAny: jest.fn(), verify: jest.fn() },
    getInstallationOctokit: jest.fn().mockResolvedValue({
      request: jest.fn().mockResolvedValue({
        data: { repositories: [{ full_name: "test-user/repo1", name: "repo1" }] },
      }),
    }),
  },
}));

// Mock @octokit/webhooks createNodeMiddleware (used at middleware top-level)
jest.mock("@octokit/webhooks", () => ({
  createNodeMiddleware: jest.fn().mockReturnValue(
    (_req: unknown, _res: unknown, next: () => void) => next(),
  ),
}));

// Silence logger
jest.mock("../src/utils/logger", () => ({
  __esModule: true,
  default: { info: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

// Mock models
const mockInstallationFind = jest.fn();
const mockCheckpointDeleteOne = jest.fn().mockResolvedValue({ deletedCount: 1 });
const mockCheckpointFindOneAndUpdate = jest.fn().mockResolvedValue(null);

jest.mock("../src/models", () => ({
  Scan: { find: jest.fn(), countDocuments: jest.fn() },
  Finding: { find: jest.fn() },
  Installation: {
    find: (...args: unknown[]) => mockInstallationFind(...args),
  },
  Checkpoint: {
    deleteOne: (...args: unknown[]) => mockCheckpointDeleteOne(...args),
    findOneAndUpdate: (...args: unknown[]) => mockCheckpointFindOneAndUpdate(...args),
  },
}));

jest.mock("../src/webhooks/installation", () => ({
  scanRepoList: jest.fn().mockResolvedValue(undefined),
}));

jest.mock("../src/utils/normaliseOctokit", () => ({
  normaliseOctokit: jest.fn((x: unknown) => x),
}));

jest.mock("../src/webhooks/marketplace", () => ({
  handleMarketplaceWebhook: jest.fn(),
}));

jest.mock("../src/alerts/marketplace", () => ({
  sendMarketplaceAlert: jest.fn(),
}));

jest.mock("../src/utils/health", () => ({
  getHealthReport: jest.fn().mockResolvedValue({ status: "ok" }),
  getHealthStatusCode: jest.fn().mockReturnValue(200),
}));

jest.mock("../src/alerts", () => ({
  sendAlert: jest.fn().mockResolvedValue(undefined),
}));

jest.mock("../src/utils/writeQueue", () => ({
  safeWrite: jest.fn().mockResolvedValue(undefined),
}));

// ─── Import under test (after all mocks) ─────────────────────────────────────

import { rescanAll } from "../src/routes";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function mockReq(overrides: Partial<Request> = {}): Request {
  return {
    body: {},
    query: {},
    headers: {},
    ...overrides,
  } as unknown as Request;
}

function mockRes(): Response & { _status: number; _json: unknown } {
  const res = {
    _status: 200,
    _json: null as unknown,
    status(code: number) {
      res._status = code;
      return res;
    },
    json(body: unknown) {
      res._json = body;
      return res;
    },
  };
  return res as unknown as Response & { _status: number; _json: unknown };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("rescanAll", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("scans all installations when no username parameter is supplied", async () => {
    mockInstallationFind.mockReturnValue({
      lean: jest.fn().mockResolvedValue([
        { installationId: 1, owner: "user1" },
        { installationId: 2, owner: "user2" },
      ]),
    });

    const req = mockReq();
    const res = mockRes();

    await rescanAll(req, res);

    expect(res._status).toBe(200);
    expect((res._json as { targetOwner: string }).targetOwner).toBe("ALL");
    expect((res._json as { installations: string[] }).installations).toEqual(["user1", "user2"]);
    expect(mockInstallationFind).toHaveBeenCalledWith({ uninstalledAt: null });
  });

  it("filters by username when passed in request body", async () => {
    mockInstallationFind.mockReturnValue({
      lean: jest.fn().mockResolvedValue([
        { installationId: 1, owner: "sample-user" },
      ]),
    });

    const req = mockReq({ body: { username: "sample-user" } });
    const res = mockRes();

    await rescanAll(req, res);

    expect(res._status).toBe(200);
    expect((res._json as { targetOwner: string }).targetOwner).toBe("sample-user");
    expect((res._json as { installations: string[] }).installations).toEqual(["sample-user"]);
    expect(mockInstallationFind).toHaveBeenCalledWith({
      uninstalledAt: null,
      owner: expect.any(RegExp),
    });
  });

  it("filters by owner when passed in request body", async () => {
    mockInstallationFind.mockReturnValue({
      lean: jest.fn().mockResolvedValue([
        { installationId: 1, owner: "some-org" },
      ]),
    });

    const req = mockReq({ body: { owner: "some-org" } });
    const res = mockRes();

    await rescanAll(req, res);

    expect(res._status).toBe(200);
    expect((res._json as { targetOwner: string }).targetOwner).toBe("some-org");
  });

  it("returns 404 if a specific username has no active installation", async () => {
    mockInstallationFind.mockReturnValue({
      lean: jest.fn().mockResolvedValue([]),
    });

    const req = mockReq({ body: { username: "non-existent-user" } });
    const res = mockRes();

    await rescanAll(req, res);

    expect(res._status).toBe(404);
    expect((res._json as { message: string }).message).toContain("non-existent-user");
  });

  it("returns 200 with generic message when no installations exist and no username filter", async () => {
    mockInstallationFind.mockReturnValue({
      lean: jest.fn().mockResolvedValue([]),
    });

    const req = mockReq();
    const res = mockRes();

    await rescanAll(req, res);

    expect(res._status).toBe(200);
    expect((res._json as { message: string }).message).toBe("No active installations found");
  });

  it("returns 500 when an unexpected error occurs", async () => {
    mockInstallationFind.mockImplementation(() => {
      throw new Error("DB connection lost");
    });

    const req = mockReq();
    const res = mockRes();

    await rescanAll(req, res);

    expect(res._status).toBe(500);
    expect((res._json as { error: string }).error).toBe("Internal server error");
  });

  it("performs case-insensitive owner matching", async () => {
    mockInstallationFind.mockReturnValue({
      lean: jest.fn().mockResolvedValue([
        { installationId: 1, owner: "MyUser" },
      ]),
    });

    const req = mockReq({ body: { username: "myuser" } });
    const res = mockRes();

    await rescanAll(req, res);

    // Verify the regex is case-insensitive
    const filterArg = mockInstallationFind.mock.calls[0][0] as { owner: RegExp };
    expect(filterArg.owner).toBeInstanceOf(RegExp);
    expect(filterArg.owner.flags).toContain("i");
    expect(filterArg.owner.test("MyUser")).toBe(true);
    expect(filterArg.owner.test("MYUSER")).toBe(true);
  });

  it("trims whitespace from username input", async () => {
    mockInstallationFind.mockReturnValue({
      lean: jest.fn().mockResolvedValue([
        { installationId: 1, owner: "trimmed" },
      ]),
    });

    const req = mockReq({ body: { username: "  trimmed  " } });
    const res = mockRes();

    await rescanAll(req, res);

    expect(res._status).toBe(200);
    expect((res._json as { targetOwner: string }).targetOwner).toBe("trimmed");
  });
});
