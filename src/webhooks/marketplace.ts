import crypto from "crypto";
import type { Request, Response } from "express";
import { Installation } from "../models";
import logger from "../utils/logger";
import { sendMarketplaceAlert } from "../alerts/marketplace";

// ─── Payload types ────────────────────────────────────────────────────────────

export type MarketplaceAction =
  | "purchased"
  | "pending_change"
  | "pending_change_cancelled"
  | "changed"
  | "cancelled";

interface MarketplacePlan {
  id: number;
  name: string;
  monthly_price_in_cents: number;
  yearly_price_in_cents: number;
  price_model: "flat-rate" | "per-unit" | "free";
}

interface MarketplacePurchasePayload {
  action: MarketplaceAction;
  effective_date: string;
  sender: { login: string; id: number };
  marketplace_purchase: {
    account: { login: string; id: number; type: "User" | "Organization" };
    billing_cycle: "monthly" | "yearly";
    unit_count: number | null;
    on_free_trial: boolean;
    free_trial_ends_on: string | null;
    next_billing_date: string | null;
    plan: MarketplacePlan;
  };
  previous_marketplace_purchase?: {
    plan: MarketplacePlan;
    unit_count: number | null;
  };
  installation?: { id: number };
}

// ─── Signature verification ───────────────────────────────────────────────────

function verifySignature(
  rawBody: string,
  signature: string | undefined,
  secret: string,
): boolean {
  if (!signature) return false;
  const expected = `sha256=${crypto
    .createHmac("sha256", secret)
    .update(rawBody, "utf8")
    .digest("hex")}`;
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected),
    );
  } catch {
    return false;
  }
}

// ─── Route handler ────────────────────────────────────────────────────────────

export function handleMarketplaceWebhook(req: Request, res: Response): void {
  const secret = process.env.MARKETPLACE_WEBHOOK_SECRET;

  if (!secret) {
    logger.error("[marketplace] MARKETPLACE_WEBHOOK_SECRET is not set");
    res.status(500).json({ error: "Server misconfiguration" });
    return;
  }

  const rawBody =
    typeof req.body === "string"
      ? req.body
      : Buffer.isBuffer(req.body)
        ? req.body.toString("utf8")
        : JSON.stringify(req.body);

  const signature = req.headers["x-hub-signature-256"] as string | undefined;

  if (!verifySignature(rawBody, signature, secret)) {
    logger.warn(`[marketplace] Invalid signature from ${req.ip ?? "unknown"}`);
    res.status(401).json({ error: "Invalid signature" });
    return;
  }

  let payload: MarketplacePurchasePayload;
  try {
    payload = JSON.parse(rawBody) as MarketplacePurchasePayload;
  } catch {
    res.status(400).json({ error: "Invalid JSON payload" });
    return;
  }

  const {
    action,
    sender,
    marketplace_purchase,
    previous_marketplace_purchase,
    effective_date,
  } = payload;
  const buyer = marketplace_purchase.account.login;
  const plan = marketplace_purchase.plan.name;
  const previousPlan = previous_marketplace_purchase?.plan.name ?? null;

  logger.info(
    `[marketplace] ${action} — buyer: ${buyer}, plan: "${plan}"${previousPlan ? `, previous: "${previousPlan}"` : ""}`,
  );

  // Respond immediately — GitHub retries if it doesn't get 200 quickly
  res.status(200).json({ received: true });

  void (async (): Promise<void> => {
    try {
      await handleAction({
        action,
        buyer,
        sender: sender.login,
        plan,
        previousPlan,
        billingCycle: marketplace_purchase.billing_cycle,
        onFreeTrial: marketplace_purchase.on_free_trial,
        freeTrialEndsOn: marketplace_purchase.free_trial_ends_on,
        effectiveDate: effective_date,
        installationId: payload.installation?.id ?? null,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(
        `[marketplace] Error handling "${action}" for ${buyer}: ${message}`,
      );
    }
  })();
}

// ─── Shared context type ──────────────────────────────────────────────────────

export interface MarketplaceContext {
  action: MarketplaceAction;
  buyer: string;
  sender: string;
  plan: string;
  previousPlan: string | null;
  billingCycle: "monthly" | "yearly";
  onFreeTrial: boolean;
  freeTrialEndsOn: string | null;
  effectiveDate: string;
  installationId: number | null;
}

// ─── Action router ────────────────────────────────────────────────────────────

async function handleAction(ctx: MarketplaceContext): Promise<void> {
  switch (ctx.action) {
    case "purchased":
      await onPurchased(ctx);
      break;
    case "changed":
      await onChanged(ctx);
      break;
    case "cancelled":
      await onCancelled(ctx);
      break;
    case "pending_change":
      await onPendingChange(ctx);
      break;
    case "pending_change_cancelled":
      logger.info(`[marketplace] Pending change cancelled for ${ctx.buyer}`);
      await sendMarketplaceAlert({
        ...ctx,
        emoji: "↩️",
        label: "Pending Change Cancelled",
      });
      break;
    default: {
      const exhaustive: never = ctx.action;
      logger.warn(`[marketplace] Unhandled action: ${String(exhaustive)}`);
    }
  }
}

// ─── Individual handlers ──────────────────────────────────────────────────────

async function onPurchased(ctx: MarketplaceContext): Promise<void> {
  logger.info(
    `[marketplace] New purchase — ${ctx.buyer} on plan "${ctx.plan}"${ctx.onFreeTrial ? " (free trial)" : ""}`,
  );

  if (ctx.installationId) {
    await Installation.findOneAndUpdate(
      { installationId: ctx.installationId },
      {
        $set: {
          marketplacePlan: ctx.plan,
          billingCycle: ctx.billingCycle,
          onFreeTrial: ctx.onFreeTrial,
          freeTrialEndsOn: ctx.freeTrialEndsOn
            ? new Date(ctx.freeTrialEndsOn)
            : null,
          marketplaceUpdatedAt: new Date(),
        },
      },
    );
  }

  await sendMarketplaceAlert({
    ...ctx,
    emoji: ctx.onFreeTrial ? "🆓" : "🎉",
    label: ctx.onFreeTrial ? "Free Trial Started" : "New Purchase",
  });
}

async function onChanged(ctx: MarketplaceContext): Promise<void> {
  const isUpgrade = ctx.previousPlan !== null && ctx.plan !== ctx.previousPlan;

  logger.info(
    `[marketplace] Plan changed for ${ctx.buyer}: "${ctx.previousPlan ?? "unknown"}" → "${ctx.plan}"`,
  );

  if (ctx.installationId) {
    await Installation.findOneAndUpdate(
      { installationId: ctx.installationId },
      {
        $set: {
          marketplacePlan: ctx.plan,
          billingCycle: ctx.billingCycle,
          marketplaceUpdatedAt: new Date(),
        },
      },
    );
  }

  await sendMarketplaceAlert({
    ...ctx,
    emoji: isUpgrade ? "⬆️" : "⬇️",
    label: isUpgrade ? "Plan Upgraded" : "Plan Downgraded",
  });
}

async function onCancelled(ctx: MarketplaceContext): Promise<void> {
  logger.info(
    `[marketplace] Cancellation — ${ctx.buyer} cancelled "${ctx.plan}"`,
  );

  if (ctx.installationId) {
    await Installation.findOneAndUpdate(
      { installationId: ctx.installationId },
      {
        $set: {
          marketplacePlan: null,
          marketplaceCancelledAt: new Date(),
          marketplaceUpdatedAt: new Date(),
        },
      },
    );
  }

  await sendMarketplaceAlert({
    ...ctx,
    emoji: "😢",
    label: "Subscription Cancelled",
  });
}

async function onPendingChange(ctx: MarketplaceContext): Promise<void> {
  logger.info(
    `[marketplace] Pending change — ${ctx.buyer} changing from "${ctx.previousPlan ?? "unknown"}" to "${ctx.plan}" on ${ctx.effectiveDate}`,
  );

  await sendMarketplaceAlert({
    ...ctx,
    emoji: "⏳",
    label: `Plan Change Pending (effective ${ctx.effectiveDate.slice(0, 10)})`,
  });
}
