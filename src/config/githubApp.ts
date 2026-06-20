import fs from "fs";
import path from "path";
import { App } from "@octokit/app";
import logger from "../utils/logger";
import { handlePush } from "../webhooks/push";
import { handleWorkflowRun } from "../webhooks/workflowRun";
import { handleCreate } from "../webhooks/create";
import { handleInstallation, handleInstallationRepositories } from "../webhooks/installation";
import { handlePullRequestOpened } from "../webhooks/pullRequest";

// ─── Validate required env vars ───────────────────────────────────────────────

const REQUIRED_ENV = [
  "APP_ID",
  "WEBHOOK_SECRET",
  "GITHUB_CLIENT_ID",
  "GITHUB_CLIENT_SECRET",
] as const;

for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    logger.error(`Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

// ─── Load private key ─────────────────────────────────────────────────────────

function loadPrivateKey(): string {
  if (process.env.PRIVATE_KEY_PATH) {
    const keyPath = path.resolve(process.env.PRIVATE_KEY_PATH);
    if (!fs.existsSync(keyPath)) {
      logger.error(`PRIVATE_KEY_PATH file not found: ${keyPath}`);
      process.exit(1);
    }
    logger.info(`Loading private key from file: ${keyPath}`);
    return fs.readFileSync(keyPath, "utf8");
  }
  if (process.env.PRIVATE_KEY) {
    return process.env.PRIVATE_KEY.replace(/\\n/g, "\n");
  }
  logger.error("Either PRIVATE_KEY_PATH or PRIVATE_KEY must be set in .env");
  process.exit(1);
}

const privateKey = loadPrivateKey();

// ─── GitHub App setup ─────────────────────────────────────────────────────────

export const githubApp = new App({
  appId: process.env.APP_ID!,
  privateKey,
  webhooks: { secret: process.env.WEBHOOK_SECRET! },
  oauth: {
    clientId: process.env.GITHUB_CLIENT_ID!,
    clientSecret: process.env.GITHUB_CLIENT_SECRET!,
  },
});

// ─── Register webhook handlers ────────────────────────────────────────────────

githubApp.webhooks.on(
  "installation",
  handleInstallation(githubApp) as unknown as (event: unknown) => Promise<void>,
);
githubApp.webhooks.on(
  "push",
  handlePush(githubApp) as unknown as (event: unknown) => Promise<void>,
);
githubApp.webhooks.on(
  "workflow_run",
  handleWorkflowRun(githubApp) as unknown as (event: unknown) => Promise<void>,
);
githubApp.webhooks.on(
  "create",
  handleCreate(githubApp) as unknown as (event: unknown) => Promise<void>,
);

githubApp.webhooks.on(
  "installation_repositories",
  handleInstallationRepositories(githubApp) as unknown as (event: unknown) => Promise<void>,
);

githubApp.webhooks.on(
  "pull_request.opened",
  handlePullRequestOpened(githubApp) as unknown as (event: unknown) => Promise<void>,
);

githubApp.webhooks.on(
  "pull_request.synchronize",
  handlePullRequestOpened(githubApp) as unknown as (event: unknown) => Promise<void>,
);

githubApp.webhooks.onError((error) => {
  logger.error(`Webhook error: ${error.message}`);
});
