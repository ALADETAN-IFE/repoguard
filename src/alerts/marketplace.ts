import logger from "../utils/logger";
import type { MarketplaceContext } from "../webhooks/marketplace";

export interface MarketplaceAlertOptions extends MarketplaceContext {
  emoji: string;
  label: string;
}

/**
 * Sends a Slack notification for Marketplace billing events.
 * Uses SLACK_BOT_TOKEN + SLACK_CHANNEL_ID for threading if available,
 * falls back to SLACK_WEBHOOK_URL incoming webhook.
 */
export async function sendMarketplaceAlert(
  opts: MarketplaceAlertOptions,
): Promise<void> {
  const {
    emoji,
    label,
    buyer,
    sender,
    plan,
    previousPlan,
    billingCycle,
    onFreeTrial,
    freeTrialEndsOn,
    effectiveDate,
  } = opts;

  const buyerUrl = `https://github.com/${buyer}`;
  const effectiveDateShort = effectiveDate.slice(0, 10);

  const blocks: object[] = [
    {
      type: "header",
      text: {
        type: "plain_text",
        text: `${emoji} ${label} — ${buyer}`,
        emoji: true,
      },
    },
    { type: "divider" },
    {
      type: "section",
      fields: [
        {
          type: "mrkdwn",
          text: `*Buyer*\n<${buyerUrl}|${buyer}>`,
        },
        {
          type: "mrkdwn",
          text: `*Triggered By*\n${sender !== buyer ? sender : "_self_"}`,
        },
        {
          type: "mrkdwn",
          text: `*Plan*\n${plan}`,
        },
        {
          type: "mrkdwn",
          text: `*Billing Cycle*\n${billingCycle.charAt(0).toUpperCase() + billingCycle.slice(1)}`,
        },
        ...(previousPlan
          ? [
              {
                type: "mrkdwn",
                text: `*Previous Plan*\n${previousPlan}`,
              },
            ]
          : []),
        {
          type: "mrkdwn",
          text: `*Effective Date*\n${effectiveDateShort}`,
        },
        ...(onFreeTrial
          ? [
              {
                type: "mrkdwn",
                text: `*Free Trial Ends*\n${freeTrialEndsOn?.slice(0, 10) ?? "Unknown"}`,
              },
            ]
          : []),
      ],
    },
    { type: "divider" },
    {
      type: "actions",
      elements: [
        {
          type: "button",
          text: { type: "plain_text", text: "View Profile", emoji: true },
          url: buyerUrl,
          style: "primary",
        },
        {
          type: "button",
          text: {
            type: "plain_text",
            text: "Marketplace Listing",
            emoji: true,
          },
          url: "https://github.com/marketplace/repoguard-ifecodes",
        },
      ],
    },
  ];

  // Use bot token for full threading support if available
  if (process.env.SLACK_BOT_TOKEN && process.env.SLACK_CHANNEL_ID) {
    try {
      await fetch("https://slack.com/api/chat.postMessage", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.SLACK_BOT_TOKEN}`,
        },
        body: JSON.stringify({
          channel: process.env.SLACK_CHANNEL_ID,
          blocks,
          text: `${emoji} ${label} — ${buyer} on plan "${plan}"`, // fallback text
        }),
      });
      logger.info(`[marketplace] Slack alert sent for "${label}" — ${buyer}`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(`[marketplace] Failed to send Slack alert: ${message}`);
    }
    return;
  }

  // Fallback to incoming webhook
  if (process.env.SLACK_WEBHOOK_URL) {
    try {
      await fetch(process.env.SLACK_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ blocks }),
      });
      logger.info(
        `[marketplace] Slack webhook alert sent for "${label}" — ${buyer}`,
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(
        `[marketplace] Failed to send Slack webhook alert: ${message}`,
      );
    }
    return;
  }

  logger.warn(
    "[marketplace] No Slack credentials configured — alert not sent. Set SLACK_BOT_TOKEN + SLACK_CHANNEL_ID or SLACK_WEBHOOK_URL",
  );
}
