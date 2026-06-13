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

  logger.info(`[slack] Sending Slack alert: ${JSON.stringify(payload, null, 2)}`);

  const criticalCount = payload.findings.filter((f) => f.severity === "critical").length;
  const highCount = payload.findings.filter((f) => f.severity === "high").length;
  const mediumCount = payload.findings.filter((f) => f.severity === "medium").length;

  const severityBar = [
    criticalCount > 0 ? `🔴 ${criticalCount} Critical` : "",
    highCount > 0 ? `🟠 ${highCount} High` : "",
    mediumCount > 0 ? `🟡 ${mediumCount} Medium` : "",
  ].filter(Boolean).join("   ");

  const contextConfig: Record<string, { label: string; header: string; emoji: string }> = {
    push: { label: "Push", header: "🚨 Security Alert", emoji: "🚨" },
    branch_create: { label: "Branch Created", header: "⚠️ Suspicious Branch", emoji: "⚠️" },
    workflow_file: { label: "Workflow", header: "🚨 Workflow Alert", emoji: "🚨" },
    installation: { label: "Installation Event", header: "📦 RepoGuard Event", emoji: "📦" },
  };

  const ctx = contextConfig[payload.context] ?? { label: payload.context, header: "🚨 Alert", emoji: "🚨" };

  const findingLines = payload.findings
    .map((f) => {
      const emoji = { critical: "🔴", high: "🟠", medium: "🟡", low: "🟢" }[f.severity] ?? "⚪";
      const file = f.file ? `\`${f.file}\`` : "_unknown file_";
      return `${emoji} *${f.rule}* — ${file}\n    ${f.message}`;
    })
    .join("\n\n");

  // ── Repository URL ──
  const repoUrl = payload.repository.endsWith("/*")
    ? `https://github.com/${payload.repository.replace("/*", "")}`  // owner profile URL
    : `https://github.com/${payload.repository}`;  // specific repo URL
  const commitText = payload.commit !== "N/A"
    ? `<${repoUrl}/commit/${payload.commit}|\`${payload.commit}\`>`
    : "_N/A_";

  const blocks = [
    // ── Header ──
    {
      type: "header",
      text: {
        type: "plain_text",
        text: `${ctx.header} — ${payload.repository}`,
        emoji: true,
      },
    },
    { type: "divider" },

    // ── Meta ──
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Repository*\n<${repoUrl}|${payload.repository}>` },
        { type: "mrkdwn", text: `*Triggered By*\n${ctx.label}` },
        { type: "mrkdwn", text: `*Pusher*\n${payload.pusher}` },
        { type: "mrkdwn", text: `*Commit*\n${commitText}` },
        { type: "mrkdwn", text: `*Ref*\n\`${payload.ref}\`` },
        { type: "mrkdwn", text: `*Time*\n<!date^${Math.floor(new Date(payload.timestamp).getTime() / 1000)}^{date_short_pretty} at {time}|${payload.timestamp}>` },
      ],
    },
    { type: "divider" },

    // ── Severity summary ──
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*${payload.findings.length} Finding${payload.findings.length > 1 ? "s" : ""} Detected*\n${severityBar}`,
      },
    },

    // ── Findings list ──
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: findingLines || "_No findings detail available_",
      },
    },
    { type: "divider" },

    // ── Action button ──
    {
      type: "actions",
      elements: [
        {
          type: "button",
          text: {
            type: "plain_text",
            text: payload.context === "installation" ? "View Profile" : "View Repository",
            emoji: true
          },
          url: repoUrl,
          style: payload.context === "installation" ? "primary" : "danger",
        },
      ],
    },
  ];

  try {
    logger.info(`[slack] Sending Slack alert blocks: ${JSON.stringify(blocks, null, 2)}`);
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
