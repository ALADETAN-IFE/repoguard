import type { OctokitClient } from "../types";

export function normaliseOctokit(octokit: unknown): OctokitClient {
  if (octokit && typeof octokit === "object") {
    if ("octokit" in octokit && (octokit as Record<string, unknown>).octokit) {
      return (octokit as Record<string, unknown>).octokit as OctokitClient;
    }
  }
  return octokit as OctokitClient;
}