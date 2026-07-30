import request from "supertest";
import express from "express";
import router from "../src/routes";
import { Installation } from "../src/models";

jest.mock("../src/config/db", () => ({
  connectDatabase: jest.fn(),
}));

jest.mock("../src/config/redis", () => ({
  redis: null,
}));

jest.mock("../src/models", () => ({
  Scan: { find: jest.fn(), countDocuments: jest.fn() },
  Finding: { find: jest.fn() },
  Installation: { find: jest.fn() },
  Checkpoint: { deleteOne: jest.fn(), findOneAndUpdate: jest.fn() },
}));

jest.mock("../src/webhooks/installation", () => ({
  scanRepoList: jest.fn().mockResolvedValue(undefined),
}));

jest.mock("../src/config/githubApp", () => ({
  githubApp: {
    getInstallationOctokit: jest.fn().mockResolvedValue({
      request: jest.fn().mockResolvedValue({
        data: { repositories: [{ full_name: "test-user/repo1", name: "repo1" }] },
      }),
    }),
  },
}));

jest.mock("../src/utils/logger", () => ({
  default: { info: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

const app = express();
app.use(express.json());
app.use("/", router);

describe("POST /api/rescan-all", () => {
  const ORIGINAL_ENV = process.env;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env = { ...ORIGINAL_ENV, RESCAN_SECRET: "test-secret" };
  });

  afterEach(() => {
    process.env = ORIGINAL_ENV;
  });

  it("returns 401 if x-rescan-secret header is missing or invalid", async () => {
    const res = await request(app).post("/api/rescan-all");
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: "Unauthorized" });
  });

  it("scans all installations when no username parameter is supplied in request body", async () => {
    (Installation.find as jest.Mock).mockReturnValue({
      lean: jest.fn().mockResolvedValue([
        { installationId: 1, owner: "user1" },
        { installationId: 2, owner: "user2" },
      ]),
    });

    const res = await request(app)
      .post("/api/rescan-all")
      .set("x-rescan-secret", "test-secret");

    expect(res.status).toBe(200);
    expect(res.body.targetOwner).toBe("ALL");
    expect(res.body.installations).toEqual(["user1", "user2"]);
    expect(Installation.find).toHaveBeenCalledWith({ uninstalledAt: null });
  });

  it("filters strictly by username in JSON request body for maximum security", async () => {
    (Installation.find as jest.Mock).mockReturnValue({
      lean: jest.fn().mockResolvedValue([
        { installationId: 1, owner: "ALADETAN-IFE" },
      ]),
    });

    const res = await request(app)
      .post("/api/rescan-all")
      .set("x-rescan-secret", "test-secret")
      .send({ username: "ALADETAN-IFE" });

    expect(res.status).toBe(200);
    expect(res.body.targetOwner).toBe("ALADETAN-IFE");
    expect(res.body.installations).toEqual(["ALADETAN-IFE"]);
    expect(Installation.find).toHaveBeenCalledWith({
      uninstalledAt: null,
      owner: expect.any(RegExp),
    });
  });

  it("returns 404 if a specific username is requested but no active installation exists", async () => {
    (Installation.find as jest.Mock).mockReturnValue({
      lean: jest.fn().mockResolvedValue([]),
    });

    const res = await request(app)
      .post("/api/rescan-all")
      .set("x-rescan-secret", "test-secret")
      .send({ username: "non-existent-user" });

    expect(res.status).toBe(404);
    expect(res.body.message).toContain("non-existent-user");
  });
});
