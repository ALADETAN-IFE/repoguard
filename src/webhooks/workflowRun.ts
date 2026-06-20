import type { App } from "@octokit/app";
import { scanWorkflowContent } from "../scanner";
import { sendAlert } from "../alerts";
import logger from "../utils/logger";
import type { WebhookEvent, WorkflowRunEventPayload } from "../types/index";
import { normaliseOctokit } from "../utils/normaliseOctokit";

export function handleWorkflowRun(_app: App): (event: WebhookEvent<WorkflowRunEventPayload>) => Promise<void> {
  return async ({ octokit, payload }) => {
    if (payload.action !== "requested") return;
    
    const { workflow_run, repository } = payload;
    const owner = repository.owner.login ?? repository.owner.name ?? "unknown";
    const repo = repository.name;
    
    logger.info(
      `[workflow_run] ${owner}/${repo} — "${workflow_run.name}" by ${workflow_run.triggering_actor?.login ?? "unknown"}`,
    );

    const workflowPath = workflow_run.path;
    if (!workflowPath) return;
    
    const client = normaliseOctokit(octokit); 
    try {
      const { data } = await client.request(
        "GET /repos/{owner}/{repo}/contents/{path}",
        { owner, repo, path: workflowPath, ref: workflow_run.head_sha },
      );

      if (Array.isArray(data) || data.type !== "file" || !("content" in data))
        return;

      const content = Buffer.from(data.content || "", "base64").toString(
        "utf8",
      );
      const findings = scanWorkflowContent(content, workflowPath);

      if (findings.length > 0) {
        logger.warn(
          `[workflow_run] Suspicious workflow: ${workflowPath} in ${owner}/${repo}`,
        );
        await sendAlert({
          owner,
          repo,
          ref: workflow_run.head_branch ?? "unknown",
          pusher: workflow_run.triggering_actor?.login ?? "unknown",
          headSha: workflow_run.head_sha,
          findings,
          context: "workflow_file",
        });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error(
        `[workflow_run] Error scanning ${workflowPath} in ${owner}/${repo}: ${message}`,
      );
    }
  };
}
