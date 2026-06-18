// ─── Shared GitHub API shapes ─────────────────────────────────────────────────

export interface GitHubRepositoryOwner {
  login?: string;
  name?: string;
}

export interface GitHubRepository {
  name: string;
  owner: GitHubRepositoryOwner;
  default_branch?: string;
}

// ─── push event ───────────────────────────────────────────────────────────────

export interface GitHubCommit {
  id: string;
  added?: string[];
  modified?: string[];
}

export interface PushEventPayload {
  repository: GitHubRepository;
  commits: GitHubCommit[];
  pusher: { name: string };
  ref: string;
  after: string; // head SHA
  forced?: boolean;
}

// ─── workflow_run event ───────────────────────────────────────────────────────

export interface TriggeringActor {
  login: string;
}

export interface WorkflowRunData {
  name: string;
  path: string;
  head_sha: string;
  head_branch: string;
  triggering_actor?: TriggeringActor;
}

export interface WorkflowRunEventPayload {
  action: string;
  workflow_run: WorkflowRunData;
  repository: GitHubRepository;
}

// ─── create event (branch / tag creation) ────────────────────────────────────

export interface GitHubSender {
  login: string;
}

export interface CreateEventPayload {
  ref_type: string;
  ref: string;
  sender: GitHubSender;
  repository: GitHubRepository;
}

// ─── installation event ───────────────────────────────────────────────────────

export interface GitHubInstallationAccount {
  login?: string;
  name?: string;
  email?: string | null;
}

export interface GitHubInstallation {
  id: number;
  account: GitHubInstallationAccount;
}

export interface InstallationEventPayload {
  action: string;
  installation: GitHubInstallation;
  repositories: Array<{ full_name: string; name: string }>;
}

// ─── Generic webhook event wrapper ───────────────────────────────────────────

export interface WebhookEvent<TPayload> {
  octokit: import("./octokit").OctokitClient;
  payload: TPayload;
}
