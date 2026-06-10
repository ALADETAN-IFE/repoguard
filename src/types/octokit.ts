import type { Octokit } from "@octokit/rest";

/**
 * The subset of the Octokit API surface used throughout RepoGuard.
 * We use the concrete `Octokit` class from `@octokit/rest` because:
 *  - it covers both `.rest.*` typed helpers and the generic `.request()` method.
 *  - `@octokit/app` authentication contexts return an instance that is
 *    structurally compatible with this type.
 */
export type OctokitClient = Octokit;
