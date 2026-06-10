import type { AlertOptions, AlertPayload } from "../types";
import logger from "../utils/logger";

export async function sendAlert({
  owner,
  repo,
  ref,
  pusher,
  headSha,
  findings,
  context = "push",
}: AlertOptions): Promise<void> {
  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const totalFindings = findings.length;

  const payload: AlertPayload = {
    timestamp: new Date().toISOString(),
    repository: `${owner}/${repo}`,
    ref,
    pusher,
    commit: headSha?.slice(0, 7) ?? "N/A",
    context,
    summary: `${totalFindings} finding${totalFindings > 1 ? "s" : ""}: ${criticalCount} critical, ${highCount} high`,
    findings,
  };

  logger.warn(`SECURITY ALERT: ${JSON.stringify(payload, null, 2)}`);

  const tasks: Promise<void>[] = [];

  if (process.env.SLACK_WEBHOOK_URL) {
    tasks.push(postSlackAlert(payload));
  }

  if (process.env.ALERT_WEBHOOK_URL) {
    tasks.push(postWebhookAlert(payload));
  }

  await Promise.allSettled(tasks);
}

async function postSlackAlert(payload: AlertPayload): Promise<void> {
  const slackUrl = process.env.SLACK_WEBHOOK_URL;
  if (!slackUrl) return;

  const blocks = [
    {
      type: "header",
      text: { type: "plain_text", text: `🚨 RepoGuard — ${payload.repository}` },
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Repo:*\n${payload.repository}` },
        { type: "mrkdwn", text: `*Pusher:*\n${payload.pusher}` },
        { type: "mrkdwn", text: `*Ref:*\n${payload.ref}` },
        { type: "mrkdwn", text: `*Commit:*\n\`${payload.commit}\`` },
      ],
    },
    {
      type: "section",
      text: { type: "mrkdwn", text: `*Summary:* ${payload.summary}` },
    },
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: payload.findings
          .map((f) => `• \`${f.rule}\` (${f.severity}) — ${f.file ?? "N/A"}`)
          .join("\n"),
      },
    },
  ];

  try {
    await fetch(slackUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ blocks }),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to send Slack alert: ${message}`);
  }
}

async function postWebhookAlert(payload: AlertPayload): Promise<void> {
  const webhookUrl = process.env.ALERT_WEBHOOK_URL;
  if (!webhookUrl) return;

  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to post to alert webhook: ${message}`);
  }
}
