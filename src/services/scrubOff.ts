/**
 * Privacy Guard: Scrubs API keys, bearer tokens, and secrets from code
 * before sending to LLMs, ensuring zero secret leakage.
 */
export function scrubPotentialSecrets(code: string): string {
  return (
    code
      // GitHub PATs and tokens
      .replace(/gh[pousr]_[A-Za-z0-9_]{36,255}/g, "[SCRUBBED_GITHUB_TOKEN]")
      .replace(/github_pat_[A-Za-z0-9_]{80,255}/g, "[SCRUBBED_GITHUB_PAT]")

      // AWS Access Keys
      .replace(/(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g, "[SCRUBBED_AWS_KEY]")

      // Slack tokens
      .replace(/xox[baprs]-[0-9a-zA-Z-]{10,255}/g, "[SCRUBBED_SLACK_TOKEN]")

      // Generic Bearer / API Keys / JWTs
      .replace(
        /Bearer\s+[A-Za-z0-9\-._ ~+/]+=*/gi,
        "Bearer [SCRUBBED_BEARER_TOKEN]",
      )
      .replace(
        /ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+/g,
        "[SCRUBBED_JWT]",
      )

      // Google API Keys & Firebase
      .replace(/AIza[0-9A-Za-z-_]{35}/g, "[SCRUBBED_GOOGLE_API_KEY]")

      // Stripe API Keys (Live & Test)
      .replace(/sk_(?:live|test)_[0-9a-zA-Z]{24,99}/g, "[SCRUBBED_STRIPE_KEY]")
      .replace(
        /pk_(?:live|test)_[0-9a-zA-Z]{24,99}/g,
        "[SCRUBBED_STRIPE_PUBLIC_KEY]",
      )

      // Private Keys (SSH, RSA, PGP, etc.)
      .replace(
        /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE)\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE)\s+PRIVATE\s+KEY-----/g,
        "[SCRUBBED_PRIVATE_KEY]",
      )

      // Heroku API Keys
      .replace(
        /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
        "[SCRUBBED_UUID_OR_HEROKU_KEY]",
      ) // Note: Use carefully if your app uses standard UUIDs

      // SendGrid API Keys
      .replace(
        /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/g,
        "[SCRUBBED_SENDGRID_KEY]",
      )

      // Telegram Bot API Tokens
      .replace(/[0-9]{9}:[a-zA-Z0-9_-]{35}/g, "[SCRUBBED_TELEGRAM_TOKEN]")

      // Discord Bot Tokens / Client Secrets
      .replace(
        /[MN][A-Za-z\d]{23,}.[\w-]{6}.[\w-]{27}/g,
        "[SCRUBBED_DISCORD_TOKEN]",
      )

      // NPM Access Tokens
      .replace(/npm_[A-Za-z0-9]{36}/g, "[SCRUBBED_NPM_TOKEN]")

      // PyPI Upload Tokens
      .replace(/pypi-[A-Za-z0-9-_]{50,}/g, "[SCRUBBED_PYPI_TOKEN]")

      // Twilio API Keys & Account SIDs
      .replace(/SK[0-9a-fA-F]{32}/g, "[SCRUBBED_TWILIO_API_KEY]")
      .replace(/AC[0-9a-fA-F]{32}/g, "[SCRUBBED_TWILIO_ACCOUNT_SID]")

      // Mailgun API Keys
      .replace(/key-[0-9a-zA-Z]{32}/g, "[SCRUBBED_MAILGUN_KEY]")

      // Square Access Tokens / Secrets
      .replace(/sq0atp-[0-9A-Za-z\-_]{22}/g, "[SCRUBBED_SQUARE_TOKEN]")
      .replace(/sq0csp-[0-9A-Za-z\-_]{43}/g, "[SCRUBBED_SQUARE_SECRET]")

      // Generic hardcoded assignments (e.g., password = "...", api_key: '...')
      .replace(
        /(?:password|passwd|secret|api[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-.!@#$%^&*()+=]{8,64})["']/gi,
        (match: string, p1?: string): string => {
          if (!p1) return match;
          return match.replace(p1, "[SCRUBBED_SECRET_VALUE]");
        },
      )

      // Azure Storage Account Keys
      .replace(
        /(?:DefaultEndpointsProtocol|AccountName|AccountKey)=[^;]+/gi,
        "[SCRUBBED_AZURE_STORAGE_KEY]",
      )

      // Google Cloud Service Account JSON private keys
      .replace(
        /"private_key":\s*"-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----"/g,
        '"private_key":"[SCRUBBED_GCP_PRIVATE_KEY]"',
      )

      // Facebook App Secrets
      .replace(/[0-9a-f]{32}/gi, "[SCRUBBED_FACEBOOK_SECRET]")

      // JWT variations (shorter or longer)
      .replace(
        /[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g,
        "[SCRUBBED_JWT]",
      )

      // Dropbox API Tokens
      .replace(/[A-Za-z0-9-_]{64}/g, "[SCRUBBED_DROPBOX_TOKEN]")

      // DigitalOcean Personal Access Tokens
      .replace(/[0-9a-f]{64}/g, "[SCRUBBED_DIGITALOCEAN_TOKEN]")

      // Shopify API Keys
      .replace(/shpat_[0-9a-f]{32}/g, "[SCRUBBED_SHOPIFY_KEY]")

      // GitLab Personal Access Tokens
      .replace(/glpat-[A-Za-z0-9]{20}/g, "[SCRUBBED_GITLAB_TOKEN]")

      // Cloudflare API Tokens
      .replace(/[A-Za-z0-9-_]{40}/g, "[SCRUBBED_CLOUDFLARE_TOKEN]")

      // Generic OAuth Client Secrets
      .replace(
        /client_secret\s*[:=]\s*["'][A-Za-z0-9_-]{16,64}["']/gi,
        'client_secret: "[SCRUBBED_OAUTH_SECRET]"',
      )

      // Generic API Key assignments (catch-all)
      .replace(
        /api[_-]?key\s*[:=]\s*["'][A-Za-z0-9]{16,64}["']/gi,
        'api_key: "[SCRUBBED_API_KEY]"',
      )

      // PostgreSQL connection strings
      .replace(
        /postgres:\/\/([^:]+):([^@]+)@([^:/]+)(:\d+)?\/([^\s"']+)/gi,
        "postgres://[SCRUBBED_USER]:[SCRUBBED_PASSWORD]@[SCRUBBED_HOST]/[SCRUBBED_DB]",
      )

      // MySQL connection strings
      .replace(
        /mysql:\/\/([^:]+):([^@]+)@([^:/]+)(:\d+)?\/([^\s"']+)/gi,
        "mysql://[SCRUBBED_USER]:[SCRUBBED_PASSWORD]@[SCRUBBED_HOST]/[SCRUBBED_DB]",
      )

      // MongoDB connection strings
      .replace(
        /mongodb(?:\+srv)?\/\/([^:]+):([^@]+)@([^/]+)\/([^\s"']+)/gi,
        "mongodb://[SCRUBBED_USER]:[SCRUBBED_PASSWORD]@[SCRUBBED_HOST]/[SCRUBBED_DB]",
      )

      // SQL Server connection strings
      .replace(
        /Server=[^;]+;Database=[^;]+;User Id=[^;]+;Password=[^;]+;/gi,
        "Server=[SCRUBBED_HOST];Database=[SCRUBBED_DB];User Id=[SCRUBBED_USER];Password=[SCRUBBED_PASSWORD];",
      )

      // Oracle DB connection strings
      .replace(
        /User Id=[^;]+;Password=[^;]+;Data Source=[^;]+;/gi,
        "User Id=[SCRUBBED_USER];Password=[SCRUBBED_PASSWORD];Data Source=[SCRUBBED_SOURCE];",
      )

      // Generic JDBC connection strings
      .replace(
        /jdbc:[a-z]+:\/\/([^:]+):([^@]+)@([^:/]+)(:\d+)?\/([^\s"']+)/gi,
        "jdbc:[SCRUBBED_DBTYPE]://[SCRUBBED_USER]:[SCRUBBED_PASSWORD]@[SCRUBBED_HOST]/[SCRUBBED_DB]",
      )

      // Generic .env style secrets
      .replace(
        /(DB_PASSWORD|DATABASE_URL|REDIS_URL|MONGO_URI|MYSQL_URL|POSTGRES_URL|SECRET|TOKEN|KEY)[ \t]*=[ \t]*.+/gi,
        (match) => {
          const key = match.split("=")[0].trim();
          return `${key}=[SCRUBBED_ENV_SECRET]`;
        },
      )
  );
}
