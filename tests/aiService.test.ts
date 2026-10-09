import {
  isAIEnabled,
  scrubPotentialSecrets,
  analyzeSuspiciousCode,
  generateAIPatch,
  summarizeForcePushSecurityImpact,
} from "../src/services/aiService";
import type { Finding } from "../src/types";

describe("aiService", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
    delete process.env.GEMINI_API_KEY;
    delete process.env.OPENAI_API_KEY;
    global.fetch = jest.fn();
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe("isAIEnabled", () => {
    it("returns false when no API keys are present", () => {
      expect(isAIEnabled()).toBe(false);
    });

    it("returns true when GEMINI_API_KEY is present", () => {
      process.env.GEMINI_API_KEY = "test-gemini-key";
      expect(isAIEnabled()).toBe(true);
    });

    it("returns false when tenantOptIn is explicitly false even with key", () => {
      process.env.GEMINI_API_KEY = "test-gemini-key";
      expect(isAIEnabled(false)).toBe(false);
    });

    it("returns true when OPENAI_API_KEY is present", () => {
      process.env.OPENAI_API_KEY = "test-openai-key";
      expect(isAIEnabled()).toBe(true);
    });
  });

  describe("scrubPotentialSecrets", () => {
    it("scrubs GitHub PATs, AWS keys, and Bearer tokens", () => {
      const sensitiveCode =
        'const pat = "ghp_123456789012345678901234567890123456"; const aws = "AKIAIOSFODNN7EXAMPLE"; const auth = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.xyz";';
      const scrubbed = scrubPotentialSecrets(sensitiveCode);
      expect(scrubbed).not.toContain("ghp_123456789012345678901234567890123456");
      expect(scrubbed).not.toContain("AKIAIOSFODNN7EXAMPLE");
      expect(scrubbed).toContain("[SCRUBBED_GITHUB_TOKEN]");
      expect(scrubbed).toContain("[SCRUBBED_AWS_KEY]");
    });
  });

  describe("analyzeSuspiciousCode", () => {
    it("returns null when AI is disabled", async () => {
      const result = await analyzeSuspiciousCode("const x = 1;", "index.js");
      expect(result).toBeNull();
    });

    it("calls Gemini API and parses response when GEMINI_API_KEY is set", async () => {
      process.env.GEMINI_API_KEY = "test-gemini-key";

      const mockResponse = {
        candidates: [
          {
            content: {
              parts: [
                {
                  text: JSON.stringify({
                    isMalicious: true,
                    confidence: 0.95,
                    reasoning: "Obfuscated malware with reverse shell payload",
                    extractedEndpoints: ["198.51.100.24"],
                    shouldDelete: true,
                  }),
                },
              ],
            },
          },
        ],
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValueOnce(mockResponse),
      });

      const findings: Finding[] = [
        {
          rule: "obfuscated-malware-pattern",
          severity: "critical",
          message: "Malware detected",
          file: "api.js",
        },
      ];

      const result = await analyzeSuspiciousCode("function evil() {}", "api.js", findings);
      expect(result).not.toBeNull();
      expect(result?.isMalicious).toBe(true);
      expect(result?.confidence).toBe(0.95);
      expect(result?.shouldDelete).toBe(true);
      expect(result?.extractedEndpoints).toContain("198.51.100.24");
    });

    it("calls OpenAI API when OPENAI_API_KEY is set and Gemini is not", async () => {
      process.env.OPENAI_API_KEY = "test-openai-key";

      const mockResponse = {
        choices: [
          {
            message: {
              content: JSON.stringify({
                isMalicious: false,
                confidence: 0.9,
                reasoning: "Safe configuration file",
                extractedEndpoints: [],
                shouldDelete: false,
              }),
            },
          },
        ],
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValueOnce(mockResponse),
      });

      const result = await analyzeSuspiciousCode("export default {};", "config.js");
      expect(result).not.toBeNull();
      expect(result?.isMalicious).toBe(false);
      expect(result?.shouldDelete).toBe(false);
    });

    it("handles API error responses gracefully", async () => {
      process.env.GEMINI_API_KEY = "test-gemini-key";

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 429,
        text: jest.fn().mockResolvedValueOnce("Rate limit exceeded"),
      });

      const result = await analyzeSuspiciousCode("test code", "test.js");
      expect(result).toBeNull();
    });
  });

  describe("generateAIPatch", () => {
    it("returns null when AI is disabled", async () => {
      const result = await generateAIPatch("const x = 1;", "index.js", []);
      expect(result).toBeNull();
    });

    it("generates surgical patch removing malware", async () => {
      process.env.GEMINI_API_KEY = "test-gemini-key";

      const mockResponse = {
        candidates: [
          {
            content: {
              parts: [
                {
                  text: JSON.stringify({
                    shouldDelete: false,
                    patchedContent: "const safe = true;\nexport default safe;",
                    reasoning: "Stripped malicious global assignment",
                  }),
                },
              ],
            },
          },
        ],
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValueOnce(mockResponse),
      });

      const findings: Finding[] = [
        {
          rule: "obfuscated-malware-pattern",
          severity: "critical",
          message: "Malware detected",
          file: "index.js",
        },
      ];

      const result = await generateAIPatch(
        "const safe = true;\nglobal.i = 'malicious';\nexport default safe;",
        "index.js",
        findings,
      );

      expect(result).not.toBeNull();
      expect(result?.shouldDelete).toBe(false);
      expect(result?.patchedContent).toBe("const safe = true;\nexport default safe;");
      expect(result?.reasoning).toContain("Stripped malicious");
    });
  });

  describe("summarizeForcePushSecurityImpact", () => {
    it("returns summarized markdown bullet points", async () => {
      process.env.GEMINI_API_KEY = "test-gemini-key";

      const mockResponse = {
        candidates: [
          {
            content: {
              parts: [
                {
                  text: JSON.stringify({
                    summary: "- Removed injected api.js\n- Cleaned package.json postinstall script",
                  }),
                },
              ],
            },
          },
        ],
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValueOnce(mockResponse),
      });

      const result = await summarizeForcePushSecurityImpact(["api.js", "package.json"], []);
      expect(result).toContain("Removed injected api.js");
    });
  });
});
