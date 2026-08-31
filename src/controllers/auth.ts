import { type Request, type Response } from "express";
import crypto from "crypto";
import { Installation } from "../models";
import logger from "../utils/logger";

const JWT_SECRET = process.env.SESSION_SECRET!;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
const ADMIN_LOGINS = process.env.ADMIN_GITHUB_LOGINS!;

export interface SessionPayload {
  user: {
    id: number;
    login: string;
    name: string;
    email: string | null;
    avatarUrl: string;
    isSystemAdmin: boolean;
    role: "system_admin" | "org_admin" | "member";
  };
  accounts: {
    login: string;
    name: string;
    avatarUrl: string;
    isOrg: boolean;
    hasInstallation: boolean;
    installationId?: number;
    plan?: string | null;
  }[];
  exp: number;
}

/**
 * Sign a base64url encoded HMAC-SHA256 session token
 */
export function signSessionToken(payload: Omit<SessionPayload, "exp">): string {
  const exp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7; // 7 days
  const data = JSON.stringify({ ...payload, exp });
  const dataB64 = Buffer.from(data).toString("base64url");
  const signature = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(dataB64)
    .digest("base64url");
  return `${dataB64}.${signature}`;
}

/**
 * Verify and decode an HMAC-SHA256 session token
 */
export function verifySessionToken(token: string): SessionPayload | null {
  try {
    const [dataB64, signature] = token.split(".");
    if (!dataB64 || !signature) return null;

    const expectedSig = crypto
      .createHmac("sha256", JWT_SECRET)
      .update(dataB64)
      .digest("base64url");

    if (signature !== expectedSig) return null;

    const payload = JSON.parse(Buffer.from(dataB64, "base64url").toString("utf8")) as SessionPayload;
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null; // Expired
    }

    return payload;
  } catch {
    return null;
  }
}

/**
 * GET /auth/github
 * Initiates GitHub OAuth sign-in flow
 */
export const initiateGitHubOAuth = (req: Request, res: Response): void => {
  const clientId = process.env.GITHUB_CLIENT_ID;
  if (!clientId) {
    logger.warn("[auth] GITHUB_CLIENT_ID not configured, redirecting to frontend demo");
    res.redirect(`${FRONTEND_URL}/dashboard`);
    return;
  }

  const redirectUri = `${req.protocol}://${req.get("host")}/auth/github/callback`;
  const scope = "read:user user:email read:org";
  const state = crypto.randomBytes(16).toString("hex");

  const authUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(
    redirectUri
  )}&scope=${encodeURIComponent(scope)}&state=${state}`;

  res.redirect(authUrl);
};

/**
 * GET /auth/github/callback
 * Handles OAuth callback from GitHub, fetches user profile & installs, signs session token
 */
export const handleGitHubOAuthCallback = async (req: Request, res: Response): Promise<void> => {
  try {
    const { code } = req.query;
    if (!code || typeof code !== "string") {
      res.redirect(`${FRONTEND_URL}/auth/login?error=missing_code`);
      return;
    }

    const clientId = process.env.GITHUB_CLIENT_ID;
    const clientSecret = process.env.GITHUB_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
      logger.error("[auth] Missing GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET");
      res.redirect(`${FRONTEND_URL}/dashboard`);
      return;
    }

    // 1. Exchange code for access token
    const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        code,
      }),
    });

    const tokenData = (await tokenRes.json()) as { access_token?: string; error?: string };
    if (!tokenData.access_token) {
      logger.error(`[auth] Token exchange failed: ${tokenData.error}`);
      res.redirect(`${FRONTEND_URL}/auth/login?error=token_exchange_failed`);
      return;
    }

    const accessToken = tokenData.access_token;

    // 2. Fetch user profile
    const userRes = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "User-Agent": "RepoGuard-App",
      },
    });
    const ghUser = (await userRes.json()) as {
      id: number;
      login: string;
      name: string;
      email?: string | null;
      avatar_url: string;
    };

    // 2b. Fetch verified primary email
    let userEmail: string | null = ghUser.email || null;
    try {
      const emailsRes = await fetch("https://api.github.com/user/emails", {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "User-Agent": "RepoGuard-App",
        },
      });
      const emails = (await emailsRes.json()) as Array<{
        email: string;
        primary: boolean;
        verified: boolean;
      }>;
      if (Array.isArray(emails)) {
        const primaryEmail = emails.find((e) => e.primary && e.verified) || emails.find((e) => e.verified) || emails[0];
        if (primaryEmail?.email) {
          userEmail = primaryEmail.email;
        }
      }
    } catch {
      // Fall back to ghUser.email if emails endpoint fails
    }

    // 3. Fetch user's organizations
    const orgsRes = await fetch("https://api.github.com/user/orgs", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "User-Agent": "RepoGuard-App",
      },
    });
    const ghOrgs = (await orgsRes.json()) as Array<{
      login: string;
      avatar_url: string;
    }>;

    const allAccountLogins = [ghUser.login, ...(Array.isArray(ghOrgs) ? ghOrgs.map((o) => o.login) : [])];

    // 4. Query active installations from MongoDB
    const installations = await Installation.find({
      owner: { $in: allAccountLogins.map((login) => new RegExp(`^${login}$`, "i")) },
      uninstalledAt: null,
    }).lean();

    const isSystemAdmin = ADMIN_LOGINS.includes(ghUser.login.toLowerCase());
    const role = isSystemAdmin ? "system_admin" : installations.length > 0 ? "org_admin" : "member";

    const accounts = allAccountLogins.map((login) => {
      const isOrg = login !== ghUser.login;
      const orgObj = isOrg ? ghOrgs.find((o) => o.login === login) : null;
      const inst = installations.find((i) => i.owner.toLowerCase() === login.toLowerCase());

      return {
        login,
        name: isOrg ? login : ghUser.name || login,
        avatarUrl: isOrg ? orgObj?.avatar_url || "" : ghUser.avatar_url,
        isOrg,
        hasInstallation: Boolean(inst),
        installationId: inst?.installationId,
        plan: inst?.marketplacePlan || "Free",
      };
    });

    // 5. Sign Session Token
    const sessionToken = signSessionToken({
      user: {
        id: ghUser.id,
        login: ghUser.login,
        name: ghUser.name || ghUser.login,
        email: userEmail,
        avatarUrl: ghUser.avatar_url,
        isSystemAdmin,
        role,
      },
      accounts,
    });

    logger.info(`[auth] User @${ghUser.login} successfully authenticated (Role: ${role})`);

    // Redirect to frontend dashboard with session token
    res.redirect(`${FRONTEND_URL}/dashboard?token=${sessionToken}`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`[auth] OAuth callback exception: ${message}`);
    res.redirect(`${FRONTEND_URL}/auth/login?error=internal_auth_error`);
  }
};

/**
 * GET /auth/me
 * Returns current authenticated user profile, role, and connected installations
 */
export const getCurrentUser = async (req: Request, res: Response): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    const token =
      authHeader?.startsWith("Bearer ") ? authHeader.substring(7) : (req.query.token as string) || null;

    if (!token) {
      res.status(401).json({ error: "No session token provided" });
      return;
    }

    const session = verifySessionToken(token);
    if (!session) {
      res.status(401).json({ error: "Invalid or expired session token" });
      return;
    }

    res.json(session);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`[auth] /auth/me error: ${message}`);
    res.status(500).json({ error: "Internal server error" });
  }
};
