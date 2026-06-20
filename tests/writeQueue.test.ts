import mongoose from "mongoose";
import type { QueuedWrite } from "../src/utils/writeQueue";

const mockLpush = jest.fn();
const mockRpop = jest.fn();
const mockLlen = jest.fn();

let mockRedis: { lpush: jest.Mock; rpop: jest.Mock; llen: jest.Mock } | null = null;
let setTimeoutSpy: jest.SpyInstance;

const flushPromises = () => new Promise((resolve) => setImmediate(resolve));

let safeWrite: typeof import("../src/utils/writeQueue").safeWrite;
let pendingWriteCount: typeof import("../src/utils/writeQueue").pendingWriteCount;
let Checkpoint: typeof import("../src/models").Checkpoint;
let Scan: typeof import("../src/models").Scan;
let Finding: typeof import("../src/models").Finding;

beforeEach(() => {
  jest.resetModules();

  const models = require("../src/models");
  Checkpoint = models.Checkpoint;
  Scan = models.Scan;
  Finding = models.Finding;

  const writeQueue = require("../src/utils/writeQueue");
  safeWrite = writeQueue.safeWrite;
  pendingWriteCount = writeQueue.pendingWriteCount;
});

jest.mock("../src/config/redis", () => ({
  get redis() {
    return mockRedis;
  },
}));

jest.mock("../src/models", () => ({
  Checkpoint: {
    updateOne: jest.fn(),
  },
  Scan: {
    create: jest.fn(),
    updateOne: jest.fn(),
  },
  Finding: {
    insertMany: jest.fn(),
  },
}));

describe("writeQueue (In-Memory Fallback)", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockRedis = null; // No Redis connection
    (Checkpoint.updateOne as jest.Mock).mockResolvedValue({});
    (Scan.create as jest.Mock).mockResolvedValue({});
    (Finding.insertMany as jest.Mock).mockResolvedValue([]);
    (Scan.updateOne as jest.Mock).mockResolvedValue({});

    // Mock setTimeout to fire immediately
    setTimeoutSpy = jest.spyOn(global, "setTimeout").mockImplementation((cb: () => void) => {
      cb();
      return {} as unknown as NodeJS.Timeout;
    });
  });

  afterEach(() => {
    setTimeoutSpy.mockRestore();
  });

  it("should execute the database write immediately when database is online", async () => {
    const write: QueuedWrite = {
      type: "MARK_SCANNED",
      data: {
        installationKey: "test-owner-123",
        repoFullName: "test-owner/test-repo",
      },
    };

    await safeWrite("test-label", write);

    expect(Checkpoint.updateOne).toHaveBeenCalledWith(
      { installationKey: "test-owner-123" },
      { $addToSet: { scanned: "test-owner/test-repo" } }
    );
    expect(await pendingWriteCount()).toBe(0);
  });

  it("should queue the write to the fallback in-memory queue if execution fails", async () => {
    (Checkpoint.updateOne as jest.Mock).mockRejectedValue(new Error("Database disconnected"));

    const write: QueuedWrite = {
      type: "MARK_SCANNED",
      data: {
        installationKey: "test-owner-123",
        repoFullName: "test-owner/test-repo",
      },
    };

    await safeWrite("test-label-fail", write);
    await flushPromises(); // Flush all async operations

    expect(Checkpoint.updateOne).toHaveBeenCalled();
    expect(await pendingWriteCount()).toBe(1);
  });
});

describe("writeQueue with Redis", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (Checkpoint.updateOne as jest.Mock).mockRejectedValue(new Error("DB Down"));
    mockRedis = {
      lpush: mockLpush,
      rpop: mockRpop,
      llen: mockLlen,
    };

    setTimeoutSpy = jest.spyOn(global, "setTimeout").mockImplementation((cb: () => void) => {
      cb();
      return {} as unknown as NodeJS.Timeout;
    });
  });

  afterEach(() => {
    setTimeoutSpy.mockRestore();
    mockRedis = null;
  });

  it("should enqueue to Redis when write fails and Redis is active", async () => {
    mockLpush.mockResolvedValue(1);

    const write: QueuedWrite = {
      type: "MARK_SCANNED",
      data: {
        installationKey: "test-owner-123",
        repoFullName: "test-owner/test-repo",
      },
    };

    await safeWrite("test-label-redis", write);
    await flushPromises();

    expect(mockLpush).toHaveBeenCalled();
    const pushedData = JSON.parse(mockLpush.mock.calls[0][1]);
    expect(pushedData.write.type).toBe("MARK_SCANNED");
  });
});

describe("pendingWriteCount with Redis", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockRedis = {
      lpush: mockLpush,
      rpop: mockRpop,
      llen: mockLlen,
    };

    (Checkpoint.updateOne as jest.Mock).mockResolvedValue({});
    (Scan.create as jest.Mock).mockResolvedValue({});
    (Finding.insertMany as jest.Mock).mockResolvedValue([]);
    (Scan.updateOne as jest.Mock).mockResolvedValue({});

    setTimeoutSpy = jest.spyOn(global, "setTimeout").mockImplementation((cb: () => void) => {
      cb();
      return {} as unknown as NodeJS.Timeout;
    });
  });

  afterEach(() => {
    setTimeoutSpy.mockRestore();
    mockRedis = null;
  });

  it("should return the sum of in-memory queue length and redis.llen result", async () => {
    // First, push an entry into the in-memory queue by failing both db and redis lpush
    (Checkpoint.updateOne as jest.Mock).mockRejectedValue(new Error("DB Down"));
    mockLpush.mockRejectedValue(new Error("Redis lpush failed"));

    const write: QueuedWrite = {
      type: "MARK_SCANNED",
      data: {
        installationKey: "test-owner-123",
        repoFullName: "test-owner/test-repo",
      },
    };

    await safeWrite("test-pending-count", write);
    await flushPromises();

    // Now redis.llen reports 3 items in the Redis queue
    mockLlen.mockResolvedValue(3);

    const count = await pendingWriteCount();
    // Should be in-memory count (1) + Redis llen (3) = 4
    expect(mockLlen).toHaveBeenCalled();
    expect(count).toBe(4);
  });

  it("should fall back gracefully and return only the in-memory count if redis.llen throws", async () => {
    // Push an entry into the in-memory queue
    (Checkpoint.updateOne as jest.Mock).mockRejectedValue(new Error("DB Down"));
    mockLpush.mockRejectedValue(new Error("Redis lpush failed"));

    const write: QueuedWrite = {
      type: "MARK_SCANNED",
      data: {
        installationKey: "test-owner-456",
        repoFullName: "test-owner/test-repo-2",
      },
    };

    await safeWrite("test-pending-fallback", write);
    await flushPromises();

    // redis.llen throws an error
    mockLlen.mockRejectedValue(new Error("Redis connection lost"));

    const count = await pendingWriteCount();
    // Should only return the in-memory count, ignoring Redis error
    expect(mockLlen).toHaveBeenCalled();
    expect(count).toBe(1);
  });
});

describe("writeQueue executeWrite routing", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockRedis = null; // No Redis, keep it simple for routing tests
    (Checkpoint.updateOne as jest.Mock).mockResolvedValue({});
    (Scan.create as jest.Mock).mockResolvedValue({});
    (Finding.insertMany as jest.Mock).mockResolvedValue([]);
    (Scan.updateOne as jest.Mock).mockResolvedValue({});

    setTimeoutSpy = jest.spyOn(global, "setTimeout").mockImplementation((cb: () => void) => {
      cb();
      return {} as unknown as NodeJS.Timeout;
    });
  });

  afterEach(() => {
    setTimeoutSpy.mockRestore();
  });

  it("should call Scan.create with correct parameters including ObjectId for CREATE_SCAN", async () => {
    const scanId = new mongoose.Types.ObjectId().toHexString();
    const startedAt = new Date().toISOString();

    const write: QueuedWrite = {
      type: "CREATE_SCAN",
      data: {
        scanId,
        installationId: 12345,
        owner: "test-owner",
        repo: "test-repo",
        status: "in_progress",
        trigger: "push",
        startedAt,
      },
    };

    await safeWrite("create-scan-test", write);

    expect(Scan.create).toHaveBeenCalledTimes(1);
    const callArgs = (Scan.create as jest.Mock).mock.calls[0][0];
    expect(callArgs._id).toEqual(new mongoose.Types.ObjectId(scanId));
    expect(callArgs.installationId).toBe(12345);
    expect(callArgs.owner).toBe("test-owner");
    expect(callArgs.repo).toBe("test-repo");
    expect(callArgs.status).toBe("in_progress");
    expect(callArgs.trigger).toBe("push");
    expect(callArgs.startedAt).toEqual(new Date(startedAt));
  });

  it("should call Finding.insertMany for INSERT_FINDINGS", async () => {
    const scanId = new mongoose.Types.ObjectId().toHexString();
    const detectedAt = new Date().toISOString();

    const write: QueuedWrite = {
      type: "INSERT_FINDINGS",
      data: {
        findings: [
          {
            scanId,
            installationId: 999,
            owner: "test-owner",
            repo: "test-repo",
            rule: "no-secrets",
            severity: "high",
            message: "Hardcoded secret detected",
            file: "src/config.ts",
            detectedAt,
          },
        ],
      },
    };

    await safeWrite("insert-findings-test", write);

    expect(Finding.insertMany).toHaveBeenCalledTimes(1);
    const insertedFindings = (Finding.insertMany as jest.Mock).mock.calls[0][0];
    expect(insertedFindings).toHaveLength(1);
    expect(insertedFindings[0].scanId).toEqual(new mongoose.Types.ObjectId(scanId));
    expect(insertedFindings[0].rule).toBe("no-secrets");
    expect(insertedFindings[0].severity).toBe("high");
    expect(insertedFindings[0].message).toBe("Hardcoded secret detected");
    expect(insertedFindings[0].file).toBe("src/config.ts");
    expect(insertedFindings[0].detectedAt).toEqual(new Date(detectedAt));
  });

  it("should call Scan.updateOne for COMPLETE_SCAN", async () => {
    const scanId = new mongoose.Types.ObjectId().toHexString();
    const completedAt = new Date().toISOString();

    const write: QueuedWrite = {
      type: "COMPLETE_SCAN",
      data: {
        scanId,
        findingsCount: 5,
        completedAt,
      },
    };

    await safeWrite("complete-scan-test", write);

    expect(Scan.updateOne).toHaveBeenCalledTimes(1);
    expect(Scan.updateOne).toHaveBeenCalledWith(
      { _id: new mongoose.Types.ObjectId(scanId) },
      {
        $set: {
          status: "complete",
          completedAt: new Date(completedAt),
          findingsCount: 5,
        },
      }
    );
  });
});

describe("writeQueue Redis lpush failure fallback", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (Checkpoint.updateOne as jest.Mock).mockRejectedValue(new Error("DB Down"));
    mockRedis = {
      lpush: mockLpush,
      rpop: mockRpop,
      llen: mockLlen,
    };

    setTimeoutSpy = jest.spyOn(global, "setTimeout").mockImplementation((cb: () => void) => {
      cb();
      return {} as unknown as NodeJS.Timeout;
    });
  });

  afterEach(() => {
    setTimeoutSpy.mockRestore();
    mockRedis = null;
  });

  it("should fall back to in-memory queue when Redis lpush throws", async () => {
    mockLpush.mockRejectedValue(new Error("Redis connection refused"));
    // rpop returns null so drain doesn't replay anything from Redis
    mockRpop.mockResolvedValue(null);
    // llen throws too since Redis is fully down
    mockLlen.mockRejectedValue(new Error("Redis connection refused"));

    const write: QueuedWrite = {
      type: "MARK_SCANNED",
      data: {
        installationKey: "test-owner-789",
        repoFullName: "test-owner/test-repo-3",
      },
    };

    await safeWrite("test-lpush-fallback", write);
    await flushPromises();

    // lpush was attempted but failed
    expect(mockLpush).toHaveBeenCalled();

    // The entry should have fallen back to the in-memory queue.
    // With Redis llen failing, pendingWriteCount returns only the in-memory count.
    const count = await pendingWriteCount();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

