# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in RepoGuard, please **do not open a public GitHub issue**. Public disclosure before a fix is in place puts users at risk.

Instead, report it privately:

**Email:** [security@reach-repoguard.ifecodes.xyz]  
**Subject:** `[SECURITY] RepoGuard Vulnerability Report`

Please include:
- A description of the vulnerability
- Steps to reproduce it
- The potential impact
- Any suggested fixes if you have them

## What to Expect

- **Acknowledgement** within 48 hours
- **Status update** within 7 days with an assessment and expected fix timeline
- **Credit** in the fix commit and changelog if you'd like to be named

## Scope

The following are in scope for security reports:

- False negative detection — malware that RepoGuard fails to catch
- Authentication or signature verification bypass on webhook endpoints
- Injection vulnerabilities in the API endpoints
- Unauthorized access to scan data or findings
- Supply chain vulnerabilities in RepoGuard's own dependencies

The following are **out of scope:**

- Vulnerabilities in repos that RepoGuard is installed on (those are for the repo owners to fix)
- Rate limiting on public endpoints
- Issues requiring physical access to the server

## Responsible Disclosure

We ask that you:

- Give us reasonable time to fix the issue before public disclosure
- Do not access or modify other users' data during testing
- Do not disrupt the service for other users

We commit to:

- Respond promptly and transparently
- Fix confirmed vulnerabilities as quickly as possible
- Never take legal action against good-faith security researchers

---

_RepoGuard is a security tool — we take reports about our own security seriously._