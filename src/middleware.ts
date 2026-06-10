import { type Request, type Response, type NextFunction } from "express";
import { createNodeMiddleware, type Webhooks } from "@octokit/webhooks";
import { githubApp } from "./config/githubApp";

const webhookMiddleware = createNodeMiddleware(
  githubApp.webhooks as unknown as Webhooks<unknown>,
  { path: "/" },
);

export function handleWebhook(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  void webhookMiddleware(req, res, next);
}
