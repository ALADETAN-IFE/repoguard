# RepoGuard

> Automated security scanning and remediation for GitHub repositories.

RepoGuard is a GitHub App that scans your repositories for malicious code, obfuscated payloads, hardcoded secrets, and supply chain attacks. On every push, RepoGuard detects threats and automatically opens a fix PR — so vulnerabilities are caught and patched before they reach production.

---

## Features

- **Full codebase scan on install** — scans every file immediately after installation
- **Push scanning** — every commit to your default branch is automatically scanned
- **Automated fix PRs** — malicious code is patched and a PR is opened with full findings documentation
- **Security issues** — falls back to a GitHub issue when write access is unavailable
- **Workflow protection** — detects suspicious GitHub Actions triggers and secret exfiltration
- **Supply chain detection** — catches typosquatted packages and malicious postinstall scripts
- **Branch monitoring** — flags suspicious branch creation by non-org members
- **Checkpoint resumption** — large installs resume automatically if interrupted

---

## Detection Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `obfuscated-malware-pattern` | Critical | Obfuscated string array payloads and createRequire bypasses |
| `obfuscated-base64` | Critical | Base64-encoded eval payloads |
| `reverse-shell` | Critical | Bash and netcat reverse shell patterns |
| `curl-pipe-bash` | Critical | Remote code execution via curl/wget piped to shell |
| `hardcoded-secret` | High | API keys, tokens, and passwords hardcoded in source |
| `env-exfiltration` | High | Environment variables sent to external endpoints |
| `suspicious-npm-postinstall` | High | Malicious postinstall scripts in package.json |
| `suspicious-registry-url` | High | Non-standard npm registry references |
| `crypto-miner-keywords` | High | Cryptocurrency miner indicators |
| `workflow-exfiltrate-secrets` | High | GitHub Actions workflows leaking secrets externally |
| `workflow-suspicious-trigger` | Medium | Overly broad workflow triggers |
| `workflow-unpinned-action` | Medium | Third-party Actions not pinned to a commit SHA |
| `suspicious-branch-create` | High | Branch creation by non-org members |

---

## How It Works

```
Install RepoGuard
       │
       ▼
Scans entire codebase
       │
       ├── No findings → Opens & closes a "clean scan" issue
       │
       └── Findings found → Opens fix PR with patches applied
                │
                └── Write access unavailable → Opens security issue instead

Every push to default branch
       │
       ▼
Scans all changed files
       │
       ├── Clean → Closes any open RepoGuard PRs/issues
       │
       └── Findings → Creates check run + fix PR
```

---

## Installation

1. Go to the [RepoGuard](https://github.com/apps/repoguard-ifecodes)
2. Click Install
3. Select the repositorie(s) in the account/org you want to protect
4. RepoGuard immediately scans your codebase and reports findings

<!-- 1. Go to the [RepoGuard GitHub Marketplace listing](https://github.com/marketplace/repoguard-ifecodes) -->
<!-- 2. Select the account/org you want to protect -->
<!-- 3. Click **Install it for free** -->
<!-- 4. Select the repositorie(s) in the account/org you want to protect -->
<!-- 5. RepoGuard immediately scans your codebase and reports findings -->

---

## Permissions Required

| Permission | Access | Reason |
|------------|--------|--------|
| Repository contents | Read & Write | Scan files and commit patches |
| Issues | Read & Write | Open security issues and scan reports |
| Pull requests | Read & Write | Open and manage fix PRs |
| Checks | Read & Write | Report scan status on commits |
| Workflows | Read | Scan GitHub Actions workflow files |
| Members | Read | Detect non-org branch creation |

---

## Self-Hosting

### Prerequisites

- Node.js >= 24
- MongoDB (Atlas or self-hosted)
- A GitHub App with the permissions listed above

### Environment Variables

```env
# GitHub App
APP_ID=
PRIVATE_KEY=
WEBHOOK_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

# MongoDB
MONGODB_URI=

# Server
PORT=3000
```

### Running Locally

```bash
# Install dependencies
npm install

# Build
npm run build

# Start
npm start

# Development (with hot reload)
npm run dev
```

### Webhook Forwarding (Local Development)

Use [Smee](https://smee.io) to forward GitHub webhooks to localhost:

```bash
npx smee-client --url https://smee.io/your-channel --target http://localhost:3000/api/webhook
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Health check |
| `/health` | GET | App status and version |
| `/api/webhook` | POST | GitHub webhook receiver |
| `/api/scans` | GET | List recent scans (paginated) |
| `/api/scans/:scanId/findings` | GET | Findings for a specific scan |
| `/auth/callback` | GET | GitHub App OAuth callback |

---

## Tech Stack

- **Runtime:** Node.js + TypeScript
- **Framework:** Express
- **GitHub Integration:** `@octokit/app`, `@octokit/webhooks`
- **Database:** MongoDB via Mongoose
- **Logging:** Winston
- **Deployment:** Railway

---

## License

MIT