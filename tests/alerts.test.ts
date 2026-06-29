import { sendAlert } from "../src/alerts";
import logger from "../src/utils/logger";
import type { Finding, AlertContext } from "../src/types";

jest.mock("../src/utils/logger", () => ({
  __esModule: true,
  default: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

// ─── Helpers ──────────────────────────────────────────────────────────────────

const makeFinding = (overrides: Partial<Finding> = {}): Finding => ({
  rule: "test-rule",
  severity: "high",
  message: "Test message — extra info",
  file: "src/index.ts",
  ...overrides,
});

const baseOptions = () => ({
  owner: "test-owner",
  repo: "test-repo",
  ref: "refs/heads/main",
  pusher: "user1",
  headSha: "abc1234567890",
  findings: [makeFinding()],
});

// ─── Setup / teardown ─────────────────────────────────────────────────────────

let fetchMock: jest.Mock;

const SAVED_ENV: Record<string, string | undefined> = {};
const ENV_KEYS = [
  "SLACK_WEBHOOK_URL",
  "SLACK_BOT_TOKEN",
  "SLACK_CHANNEL_ID",
  "ALERT_WEBHOOK_URL",
];

beforeEach(() => {
  fetchMock = jest.fn().mockResolvedValue({
    json: jest.fn().mockResolvedValue({ ok: false }),
  });
  global.fetch = fetchMock as unknown as typeof fetch;

  // Save and clear env vars
  for (const key of ENV_KEYS) {
    SAVED_ENV[key] = process.env[key];
    delete process.env[key];
  }

  jest.clearAllMocks();
});

afterEach(() => {
  // Restore env vars
  for (const key of ENV_KEYS) {
    if (SAVED_ENV[key] !== undefined) {
      process.env[key] = SAVED_ENV[key];
    } else {
      delete process.env[key];
    }
  }
});

// ─── 1. No env vars set ──────────────────────────────────────────────────────

describe("sendAlert — no env vars", () => {
  it("should only log, no fetch calls", async () => {
    await sendAlert(baseOptions());

    expect(logger.warn).toHaveBeenCalledTimes(1);
    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining("SECURITY ALERT:")
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

// ─── 2. SLACK_WEBHOOK_URL only (no bot token) ────────────────────────────────

describe("sendAlert — SLACK_WEBHOOK_URL only", () => {
  it("should call fetch with Slack webhook URL and blocks payload", async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";

    await sendAlert(baseOptions());

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://hooks.slack.com/services/test",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
      })
    );

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body).toHaveProperty("blocks");
    expect(Array.isArray(body.blocks)).toBe(true);
  });
});

// ─── 3. SLACK_BOT_TOKEN + SLACK_CHANNEL_ID (bot token path) ──────────────────

describe("sendAlert — Slack bot token path", () => {
  it("should call chat.postMessage with Authorization header", async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";
    process.env.SLACK_BOT_TOKEN = "xoxb-test-token";
    process.env.SLACK_CHANNEL_ID = "C12345";

    fetchMock.mockResolvedValue({
      json: jest.fn().mockResolvedValue({ ok: false }),
    });

    await sendAlert(baseOptions());

    expect(fetchMock).toHaveBeenCalledWith(
      "https://slack.com/api/chat.postMessage",
      expect.objectContaining({
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer xoxb-test-token",
        },
      })
    );

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.channel).toBe("C12345");
    expect(body).toHaveProperty("blocks");
  });
});

// ─── 4. Slack bot token with thread reply ────────────────────────────────────

describe("sendAlert — Slack thread reply", () => {
  it("should post a thread reply when mainData.ok and repoList is set", async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";
    process.env.SLACK_BOT_TOKEN = "xoxb-test-token";
    process.env.SLACK_CHANNEL_ID = "C12345";

    fetchMock.mockResolvedValueOnce({
      json: jest.fn().mockResolvedValue({
        ok: true,
        ts: "1234567890.123456",
        channel: "C12345",
      }),
    }).mockResolvedValueOnce({
      json: jest.fn().mockResolvedValue({ ok: true }),
    });

    await sendAlert({
      ...baseOptions(),
      repoList: ["repo-a", "repo-b"],
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);

    // Second call should be the thread reply
    const secondCall = fetchMock.mock.calls[1];
    expect(secondCall[0]).toBe("https://slack.com/api/chat.postMessage");

    const threadBody = JSON.parse(secondCall[1].body);
    expect(threadBody.thread_ts).toBe("1234567890.123456");
    expect(threadBody.text).toContain("Full repo list (2):");
    expect(threadBody.text).toContain("repo-a");
    expect(threadBody.text).toContain("repo-b");
  });

  it("should NOT post a thread reply when repoList is empty", async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";
    process.env.SLACK_BOT_TOKEN = "xoxb-test-token";
    process.env.SLACK_CHANNEL_ID = "C12345";

    fetchMock.mockResolvedValueOnce({
      json: jest.fn().mockResolvedValue({
        ok: true,
        ts: "1234567890.123456",
        channel: "C12345",
      }),
    });

    await sendAlert({
      ...baseOptions(),
      repoList: [],
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("should NOT post a thread reply when mainData.ok is false", async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";
    process.env.SLACK_BOT_TOKEN = "xoxb-test-token";
    process.env.SLACK_CHANNEL_ID = "C12345";

    fetchMock.mockResolvedValueOnce({
      json: jest.fn().mockResolvedValue({ ok: false }),
    });

    await sendAlert({
      ...baseOptions(),
      repoList: ["repo-a"],
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

// ─── 5. ALERT_WEBHOOK_URL only ───────────────────────────────────────────────

describe("sendAlert — ALERT_WEBHOOK_URL only", () => {
  it("should call fetch with webhook URL and full payload JSON", async () => {
    process.env.ALERT_WEBHOOK_URL = "https://example.com/webhook";

    await sendAlert(baseOptions());

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://example.com/webhook",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
      })
    );

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body).toHaveProperty("repository", "test-owner/test-repo");
    expect(body).toHaveProperty("ref", "refs/heads/main");
    expect(body).toHaveProperty("pusher", "user1");
    expect(body).toHaveProperty("findings");
    expect(body).toHaveProperty("summary");
    expect(body).toHaveProperty("timestamp");
  });
});

// ─── 6. Both SLACK_WEBHOOK_URL and ALERT_WEBHOOK_URL ─────────────────────────

describe("sendAlert — both Slack and webhook URLs", () => {
  it("should call both Slack and webhook endpoints", async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";
    process.env.ALERT_WEBHOOK_URL = "https://example.com/webhook";

    await sendAlert(baseOptions());

    expect(fetchMock).toHaveBeenCalledTimes(2);

    const calledUrls = fetchMock.mock.calls.map(
      (call: [string, ...unknown[]]) => call[0]
    );
    expect(calledUrls).toContain("https://hooks.slack.com/services/test");
    expect(calledUrls).toContain("https://example.com/webhook");
  });
});

// ─── 7. Slack fetch failure ──────────────────────────────────────────────────

describe("sendAlert — Slack fetch failure", () => {
  it("should catch the error and log it", async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";

    fetchMock.mockRejectedValue(new Error("network down"));

    await sendAlert(baseOptions());

    expect(logger.error).toHaveBeenCalledWith(
      expect.stringContaining("Failed to send Slack alert: network down")
    );
  });

  it("should handle non-Error throw objects", async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";

    fetchMock.mockRejectedValue("raw string error");

    await sendAlert(baseOptions());

    expect(logger.error).toHaveBeenCalledWith(
      expect.stringContaining("Failed to send Slack alert: raw string error")
    );
  });
});

// ─── 8. Webhook fetch failure ────────────────────────────────────────────────

describe("sendAlert — webhook fetch failure", () => {
  it("should catch the error and log it", async () => {
    process.env.ALERT_WEBHOOK_URL = "https://example.com/webhook";

    fetchMock.mockRejectedValue(new Error("connection refused"));

    await sendAlert(baseOptions());

    expect(logger.error).toHaveBeenCalledWith(
      expect.stringContaining(
        "Failed to post to alert webhook: connection refused"
      )
    );
  });

  it("should handle non-Error throw objects", async () => {
    process.env.ALERT_WEBHOOK_URL = "https://example.com/webhook";

    fetchMock.mockRejectedValue("webhook raw error");

    await sendAlert(baseOptions());

    expect(logger.error).toHaveBeenCalledWith(
      expect.stringContaining(
        "Failed to post to alert webhook: webhook raw error"
      )
    );
  });
});

// ─── 9. Context variations ───────────────────────────────────────────────────

describe("sendAlert — context variations", () => {
  const contextExpectations: Record<
    string,
    { header: string; label: string }
  > = {
    push: { header: "🚨 Security Alert", label: "Push" },
    installation: {
      header: "📦 RepoGuard Event",
      label: "Installation Event",
    },
    branch_create: {
      header: "⚠️ Suspicious Branch",
      label: "Branch Created",
    },
    workflow_file: {
      header: "🚨 Workflow Alert",
      label: "Workflow",
    },
  };

  for (const [context, expected] of Object.entries(contextExpectations)) {
    it(`should use correct header "${expected.header}" and label "${expected.label}" for context "${context}"`, async () => {
      process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";

      await sendAlert({
        ...baseOptions(),
        context: context as AlertContext,
      });

      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      const headerBlock = body.blocks.find(
        (b: { type: string }) => b.type === "header"
      );
      expect(headerBlock.text.text).toContain(expected.header);

      const sectionBlocks = body.blocks.filter(
        (b: { type: string }) => b.type === "section"
      );
      const fieldsSection = sectionBlocks.find(
        (b: { fields?: unknown[] }) => b.fields
      );
      const triggeredByField = fieldsSection.fields.find(
        (f: { text: string }) => f.text.includes("Triggered By")
      );
      expect(triggeredByField.text).toContain(expected.label);
    });
  }

  it("should fall back to generic label for unknown context", async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";

    await sendAlert({
      ...baseOptions(),
      context: "custom_event" as AlertContext,
    });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    const headerBlock = body.blocks.find(
      (b: { type: string }) => b.type === "header"
    );
    expect(headerBlock.text.text).toContain("🚨 Alert");

    const sectionBlocks = body.blocks.filter(
      (b: { type: string }) => b.type === "section"
    );
    const fieldsSection = sectionBlocks.find(
      (b: { fields?: unknown[] }) => b.fields
    );
    const triggeredByField = fieldsSection.fields.find(
      (f: { text: string }) => f.text.includes("Triggered By")
    );
    expect(triggeredByField.text).toContain("custom_event");
  });
});

// ─── 10. Installation context findings format ────────────────────────────────

describe("sendAlert — installation context findings format", () => {
  it("should format findings without file reference for installation context", async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";

    const findings: Finding[] = [
      {
        rule: "new-repos-detected",
        severity: "medium",
        message: "3 new repos detected — repo-a, repo-b, repo-c",
        file: null,
      },
    ];

    await sendAlert({
      ...baseOptions(),
      findings,
      context: "installation",
    });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    const findingsSection = body.blocks.find(
      (b: { type: string; text?: { text: string } }) =>
        b.type === "section" &&
        b.text?.text?.includes("new-repos-detected")
    );

    // Installation format: no file reference, uses split("—")[0]
    expect(findingsSection.text.text).toContain("*new-repos-detected*");
    expect(findingsSection.text.text).toContain("3 new repos detected");
    // Should NOT contain backtick-wrapped file reference
    expect(findingsSection.text.text).not.toMatch(/`[^`]+`/);
  });

  it("should format findings WITH file reference for push context", async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";

    const findings: Finding[] = [
      {
        rule: "curl-pipe-bash",
        severity: "critical",
        message: "Remote code execution via curl|bash",
        file: "setup.sh",
      },
    ];

    await sendAlert({
      ...baseOptions(),
      findings,
      context: "push",
    });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    const findingsSection = body.blocks.find(
      (b: { type: string; text?: { text: string } }) =>
        b.type === "section" &&
        b.text?.text?.includes("curl-pipe-bash")
    );

    expect(findingsSection.text.text).toContain("`setup.sh`");
  });

  it("should show _unknown file_ when file is null in non-installation context", async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";

    const findings: Finding[] = [
      {
        rule: "test-rule",
        severity: "high",
        message: "Test message",
        file: null,
      },
    ];

    await sendAlert({
      ...baseOptions(),
      findings,
      context: "push",
    });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    const findingsSection = body.blocks.find(
      (b: { type: string; text?: { text: string } }) =>
        b.type === "section" &&
        b.text?.text?.includes("test-rule")
    );

    expect(findingsSection.text.text).toContain("_unknown file_");
  });
});

// ─── 11. Repository URL wildcard handling ────────────────────────────────────

describe("sendAlert — wildcard repository URL", () => {
  it("should strip /* from the repository URL", async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";

    await sendAlert({
      ...baseOptions(),
      repo: "*",
    });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);

    // The repo URL in the section fields should not contain /*
    const sectionBlocks = body.blocks.filter(
      (b: { type: string }) => b.type === "section"
    );
    const fieldsSection = sectionBlocks.find(
      (b: { fields?: unknown[] }) => b.fields
    );
    const repoField = fieldsSection.fields.find((f: { text: string }) =>
      f.text.includes("Repository")
    );
    const linkMatch = repoField.text.match(/<([^|]+)\|/);
    expect(linkMatch).toBeTruthy();
    const url = linkMatch[1];
    expect(url).not.toContain("/*");
    expect(url).toBe("https://github.com/test-owner");
  });
});

// ─── 12. Payload summary format ──────────────────────────────────────────────

describe("sendAlert — payload summary", () => {
  it("should count critical and high correctly with plural", async () => {
    const findings: Finding[] = [
      makeFinding({ severity: "critical", rule: "rule-1" }),
      makeFinding({ severity: "critical", rule: "rule-2" }),
      makeFinding({ severity: "high", rule: "rule-3" }),
      makeFinding({ severity: "medium", rule: "rule-4" }),
    ];

    process.env.ALERT_WEBHOOK_URL = "https://example.com/webhook";
    await sendAlert({ ...baseOptions(), findings });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.summary).toBe("4 findings: 2 critical, 1 high");
  });

  it("should use singular 'finding' for exactly 1 finding", async () => {
    const findings: Finding[] = [
      makeFinding({ severity: "critical", rule: "rule-1" }),
    ];

    process.env.ALERT_WEBHOOK_URL = "https://example.com/webhook";
    await sendAlert({ ...baseOptions(), findings });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.summary).toBe("1 finding: 1 critical, 0 high");
  });

  it("should show 0 critical, 0 high when only medium findings exist", async () => {
    const findings: Finding[] = [
      makeFinding({ severity: "medium", rule: "rule-1" }),
      makeFinding({ severity: "medium", rule: "rule-2" }),
    ];

    process.env.ALERT_WEBHOOK_URL = "https://example.com/webhook";
    await sendAlert({ ...baseOptions(), findings });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.summary).toBe("2 findings: 0 critical, 0 high");
  });
});

// ─── 13. headSha null ────────────────────────────────────────────────────────

describe("sendAlert — headSha null", () => {
  it('should set commit field to "N/A" when headSha is null', async () => {
    process.env.ALERT_WEBHOOK_URL = "https://example.com/webhook";

    await sendAlert({
      ...baseOptions(),
      headSha: null,
    });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.commit).toBe("N/A");
  });

  it("should show _N/A_ in Slack commit field when headSha is null", async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";

    await sendAlert({
      ...baseOptions(),
      headSha: null,
    });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    const sectionBlocks = body.blocks.filter(
      (b: { type: string }) => b.type === "section"
    );
    const fieldsSection = sectionBlocks.find(
      (b: { fields?: unknown[] }) => b.fields
    );
    const commitField = fieldsSection.fields.find((f: { text: string }) =>
      f.text.includes("Commit")
    );
    expect(commitField.text).toContain("_N/A_");
  });

  it("should slice headSha to 7 chars when provided", async () => {
    process.env.ALERT_WEBHOOK_URL = "https://example.com/webhook";

    await sendAlert({
      ...baseOptions(),
      headSha: "abcdef1234567890",
    });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.commit).toBe("abcdef1");
  });
});

// ─── Slack severity bar ──────────────────────────────────────────────────────

describe("sendAlert — Slack severity bar", () => {
  it("should include severity emojis for critical, high, and medium findings (non-installation)", async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";

    const findings: Finding[] = [
      makeFinding({ severity: "critical", rule: "r1" }),
      makeFinding({ severity: "high", rule: "r2" }),
      makeFinding({ severity: "medium", rule: "r3" }),
    ];

    await sendAlert({ ...baseOptions(), findings, context: "push" });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    const summarySection = body.blocks.find(
      (b: { type: string; text?: { text: string } }) =>
        b.type === "section" &&
        b.text?.text?.includes("Finding")
    );
    expect(summarySection.text.text).toContain("🔴 1 Critical");
    expect(summarySection.text.text).toContain("🟠 1 High");
    expect(summarySection.text.text).toContain("🟡 1 Medium");
  });

  it("should omit the findings count block for installation context", async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";

    await sendAlert({
      ...baseOptions(),
      context: "installation",
    });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    const findingsCountSection = body.blocks.find(
      (b: { type: string; text?: { text: string } }) =>
        b.type === "section" &&
        b.text?.text?.includes("Finding") &&
        b.text?.text?.includes("Detected")
    );
    expect(findingsCountSection).toBeUndefined();
  });
});

// ─── Action button ───────────────────────────────────────────────────────────

describe("sendAlert — action button", () => {
  it('should render "View Repository" danger button for push context', async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";

    await sendAlert({ ...baseOptions(), context: "push" });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    const actionBlock = body.blocks.find(
      (b: { type: string }) => b.type === "actions"
    );
    expect(actionBlock.elements[0].text.text).toBe("View Repository");
    expect(actionBlock.elements[0].style).toBe("danger");
  });

  it('should render "View Profile" primary button for installation context', async () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";

    await sendAlert({ ...baseOptions(), context: "installation" });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    const actionBlock = body.blocks.find(
      (b: { type: string }) => b.type === "actions"
    );
    expect(actionBlock.elements[0].text.text).toBe("View Profile");
    expect(actionBlock.elements[0].style).toBe("primary");
  });
});
