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
  repoList
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
    repoList,
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

  const criticalCount = payload.findings.filter((f) => f.severity === "critical").length;
  const highCount = payload.findings.filter((f) => f.severity === "high").length;
  const mediumCount = payload.findings.filter((f) => f.severity === "medium").length;

  const severityBar = [
    criticalCount > 0 ? `🔴 ${criticalCount} Critical` : "",
    highCount > 0 ? `🟠 ${highCount} High` : "",
    mediumCount > 0 ? `🟡 ${mediumCount} Medium` : "",
  ].filter(Boolean).join("   ");

  const contextConfig: Record<string, { label: string; header: string }> = {
    push: { label: "Push", header: "🚨 Security Alert" },
    branch_create: { label: "Branch Created", header: "⚠️ Suspicious Branch" },
    workflow_file: { label: "Workflow", header: "🚨 Workflow Alert" },
    installation: { label: "Installation Event", header: "📦 RepoGuard Event" },
  };

  const ctx = contextConfig[payload.context] ?? { label: payload.context, header: "🚨 Alert" };
  const isInstallation = payload.context === "installation";

  const repoUrl = payload.repository.endsWith("/*")
    ? `https://github.com/${payload.repository.replace("/*", "")}`
    : `https://github.com/${payload.repository}`;

  const commitText = payload.commit !== "N/A"
    ? `<${repoUrl}/commit/${payload.commit}|\`${payload.commit}\`>`
    : "_N/A_";

  // ── For installation events, show a clean summary line only ──
  const findingLines = isInstallation
    ? payload.findings
        .map((f) => {
          const emoji = { critical: "🔴", high: "🟠", medium: "🟡", low: "🟢" }[f.severity] ?? "⚪";
          return `${emoji} *${f.rule}*\n    ${f.message.split("—")[0].trim()}`; // just the short part
        })
        .join("\n\n")
    : payload.findings
        .map((f) => {
          const emoji = { critical: "🔴", high: "🟠", medium: "🟡", low: "🟢" }[f.severity] ?? "⚪";
          const file = f.file ? `\`${f.file}\`` : "_unknown file_";
          return `${emoji} *${f.rule}* — ${file}\n    ${f.message}`;
        })
        .join("\n\n");

  const blocks: object[] = [
    {
      type: "header",
      text: {
        type: "plain_text",
        text: `${ctx.header} — ${payload.repository}`,
        emoji: true,
      },
    },
    { type: "divider" },
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

    // ── Only show severity summary for non-installation events ──
    ...(!isInstallation ? [{
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*${payload.findings.length} Finding${payload.findings.length > 1 ? "s" : ""} Detected*\n${severityBar}`,
      },
    }] : []),

    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: findingLines || "_No details available_",
      },
    },
    { type: "divider" },
    {
      type: "actions",
      elements: [
        {
          type: "button",
          text: {
            type: "plain_text",
            text: isInstallation ? "View Profile" : "View Repository",
            emoji: true,
          },
          url: repoUrl,
          style: isInstallation ? "primary" : "danger",
        },
      ],
    },
  ];

  // ── Post main message and capture ts for thread reply ──
  try {
    if (process.env.SLACK_BOT_TOKEN && process.env.SLACK_CHANNEL_ID) {
      // ── Use bot token for full threading support ──
      const mainRes = await fetch("https://slack.com/api/chat.postMessage", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${process.env.SLACK_BOT_TOKEN}`,
        },
        body: JSON.stringify({
          channel: process.env.SLACK_CHANNEL_ID,
          blocks,
        }),
      });
  
      const mainData = await mainRes.json() as { ok: boolean; ts?: string; channel?: string };
  
      // ── Post repo list as thread reply if applicable ──
      if (mainData.ok && mainData.ts && payload.repoList && payload.repoList.length > 0) {
        await fetch("https://slack.com/api/chat.postMessage", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${process.env.SLACK_BOT_TOKEN}`,
          },
          body: JSON.stringify({
            channel: process.env.SLACK_CHANNEL_ID,
            thread_ts: mainData.ts,
            text: `📋 *Full repo list (${payload.repoList.length}):*\n${payload.repoList.map(r => `• <https://github.com/${payload.repository.split("/")[0]}/${r}|${r}>`).join("\n")}`,
          }),
        });
      }
    } else {
      // ── Fallback to incoming webhook (no threading) ──
      await fetch(slackUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ blocks }),
      });
    }
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
