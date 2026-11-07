import {
  isAuthorizedForOwner,
  isSystemAdminLogin,
  verifySessionToken,
  signSessionToken,
  getCurrentUser,
  type SessionPayload,
} from "../src/controllers/auth";
import {
  saveServerSession,
  getServerSession,
  updateServerSessionTokens,
  deleteServerSession,
} from "../src/services/sessionStore";
import { isAIEnabled } from "../src/services/aiService";
import { isAuthorizedFixBranchPusher } from "../src/utils/botAuth";
import type { Request, Response } from "express";

describe("Security Hardening & Authorization Controls", () => {
  describe("Admin & Tenant Authorization (isAuthorizedForOwner & isSystemAdminLogin)", () => {
    it("should correctly identify system admins using exact match, preventing substring bugs", () => {
      // In tests, ADMIN_GITHUB_LOGINS isn't set or set in test env
      expect(isSystemAdminLogin("attacker_admin_victim")).toBe(false);
      expect(isSystemAdminLogin("")).toBe(false);
      expect(isSystemAdminLogin(null)).toBe(false);
    });

    it("should authorize repository owners and org accounts, and reject unauthorized tenants", () => {
      const mockSession: SessionPayload = {
        sessionId: "sess_12345",
        user: {
          id: 101,
          login: "alice",
          name: "Alice",
          email: "alice@example.com",
          avatarUrl: "https://avatar",
          isSystemAdmin: false,
          role: "org_admin",
        },
        accounts: [
          {
            login: "alice",
            name: "Alice",
            avatarUrl: "",
            isOrg: false,
            hasInstallation: true,
            role: "org_admin",
          },
          {
            login: "org-security",
            name: "Org Security",
            avatarUrl: "",
            isOrg: true,
            hasInstallation: true,
            role: "member",
          },
        ],
        exp: Math.floor(Date.now() / 1000) + 3600,
      };

      // Personal account: authorized
      expect(isAuthorizedForOwner(mockSession, "alice")).toBe(true);
      expect(isAuthorizedForOwner(mockSession, "ALICE")).toBe(true);

      // Org account: authorized
      expect(isAuthorizedForOwner(mockSession, "org-security")).toBe(true);
      expect(isAuthorizedForOwner(mockSession, "ORG-SECURITY")).toBe(true);

      // Other tenant / victim: rejected (BOLA prevention)
      expect(isAuthorizedForOwner(mockSession, "bob")).toBe(false);
      expect(isAuthorizedForOwner(mockSession, "evil-corp")).toBe(false);
      expect(isAuthorizedForOwner(mockSession, "")).toBe(false);
      expect(isAuthorizedForOwner(undefined, "alice")).toBe(false);

      // System Admin override: authorized for all tenants
      const adminSession: SessionPayload = {
        ...mockSession,
        user: { ...mockSession.user, isSystemAdmin: true },
      };
      expect(isAuthorizedForOwner(adminSession, "bob")).toBe(true);
      expect(isAuthorizedForOwner(adminSession, "any-victim")).toBe(true);
    });
  });

  describe("Server-Side Session Store", () => {
    it("should save, retrieve, update tokens, and delete server session data", async () => {
      const sessionId = "test-session-abc-123";
      const sessionData = {
        sessionId,
        user: {
          id: 42,
          login: "octocat",
          name: "Octocat",
          email: "octocat@github.com",
          avatarUrl: "https://avatar",
          isSystemAdmin: false,
          role: "org_admin" as const,
          accessToken: "gho_secret_access_token_123",
          refreshToken: "ghr_secret_refresh_token_456",
          accessTokenExpiresAt: Math.floor(Date.now() / 1000) + 28800,
        },
        accounts: [],
        exp: Math.floor(Date.now() / 1000) + 3600,
      };

      await saveServerSession(sessionId, sessionData);

      const retrieved = await getServerSession(sessionId);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.user.login).toBe("octocat");
      expect(retrieved?.user.accessToken).toBe("gho_secret_access_token_123");

      // Update tokens
      const updated = await updateServerSessionTokens(sessionId, {
        accessToken: "gho_new_access_token_999",
        refreshToken: "ghr_new_refresh_token_888",
        accessTokenExpiresAt: Math.floor(Date.now() / 1000) + 36000,
      });
      expect(updated).toBe(true);

      const afterUpdate = await getServerSession(sessionId);
      expect(afterUpdate?.user.accessToken).toBe("gho_new_access_token_999");
      expect(afterUpdate?.user.refreshToken).toBe("ghr_new_refresh_token_888");

      // Delete session
      await deleteServerSession(sessionId);
      const afterDelete = await getServerSession(sessionId);
      expect(afterDelete).toBeNull();
    });
  });

  describe("Token Redaction & /auth/me Security", () => {
    it("should never return accessToken or refreshToken in /auth/me", () => {
      const signedToken = signSessionToken({
        sessionId: "sess_xyz",
        user: {
          id: 99,
          login: "developer",
          name: "Developer",
          email: "dev@example.com",
          avatarUrl: "",
          isSystemAdmin: false,
          role: "member",
          accessToken: "LEAKED_ACCESS_TOKEN",
          refreshToken: "LEAKED_REFRESH_TOKEN",
        },
        accounts: [],
      });

      const req = {
        headers: {
          authorization: `Bearer ${signedToken}`,
        },
        query: {},
      } as unknown as Request;

      let responseJson: any = null;
      let statusCode = 200;
      const res = {
        status: jest.fn().mockImplementation((code: number) => {
          statusCode = code;
          return res;
        }),
        json: jest.fn().mockImplementation((data: any) => {
          responseJson = data;
        }),
      } as unknown as Response;

      getCurrentUser(req, res);

      expect(statusCode).toBe(200);
      expect(responseJson).not.toBeNull();
      expect(responseJson.user.login).toBe("developer");
      expect(responseJson.user.accessToken).toBeUndefined();
      expect(responseJson.user.refreshToken).toBeUndefined();
      expect(responseJson.user.accessTokenExpiresAt).toBeUndefined();
    });
  });

  describe("AI Service Tenant Opt-in", () => {
    const originalEnv = process.env;

    beforeEach(() => {
      process.env = { ...originalEnv };
      process.env.GEMINI_API_KEY = "test-gemini-key";
      delete process.env.AI_DEFAULT_OPT_IN;
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it("should default to disabled unless tenantOptIn is explicitly true or AI_DEFAULT_OPT_IN=true", () => {
      // Default: tenantOptIn is false
      expect(isAIEnabled()).toBe(false);
      expect(isAIEnabled(false)).toBe(false);

      // Explicit opt-in
      expect(isAIEnabled(true)).toBe(true);

      // Global env opt-in
      process.env.AI_DEFAULT_OPT_IN = "true";
      expect(isAIEnabled()).toBe(true);
      expect(isAIEnabled(false)).toBe(true);
    });
  });

  describe("Bot Pusher Authorization Restrictions", () => {
    it("should strictly authorize configured bot logins and reject individual user accounts", () => {
      expect(isAuthorizedFixBranchPusher("repoguard[bot]")).toBe(true);
      expect(isAuthorizedFixBranchPusher("repoguard-ifecodes[bot]")).toBe(true);
      expect(isAuthorizedFixBranchPusher(undefined, "repoguard[bot]")).toBe(true);

      // Rejects usernames without [bot]
      expect(isAuthorizedFixBranchPusher("repoguard")).toBe(false);
      expect(isAuthorizedFixBranchPusher("repoguard-ifecodes")).toBe(false);

      // Rejects non-configured bot names
      expect(isAuthorizedFixBranchPusher("malicious-bot[bot]")).toBe(false);
      expect(isAuthorizedFixBranchPusher("unauthorized-repoguard[bot]")).toBe(false);
    });
  });
});
