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

      // OpenAI / Anthropic API Keys
      .replace(/sk-[A-Za-z0-9]{20,}/g, "[SCRUBBED_OPENAI_KEY]")

      // Hugging Face Tokens
      .replace(/hf_[A-Za-z0-9_]{30,}/g, "[SCRUBBED_HUGGINGFACE_TOKEN]")

      // HashiCorp Vault Tokens
      .replace(/hvs\.[A-Za-z0-9_]{90,}/g, "[SCRUBBED_VAULT_TOKEN]")

      // Databricks Personal Access Tokens
      .replace(/dapi[a-f0-9]{32}/g, "[SCRUBBED_DATABRICKS_TOKEN]")

      // Supabase API Keys
      .replace(/sb[ap]_[A-Za-z0-9_]{20,}/g, "[SCRUBBED_SUPABASE_KEY]")

      // Basic Auth Headers
      .replace(
        /Authorization:\s*Basic\s+[A-Za-z0-9+/=]+/gi,
        "Authorization: Basic [SCRUBBED_BASIC_AUTH]",
      )

      // Okta API Tokens
      .replace(/SSWS\s+[A-Za-z0-9_-]{40,}/g, "[SCRUBBED_OKTA_TOKEN]")

      // Jira API Tokens
      .replace(
        /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+:[A-Za-z0-9]{24}/g,
        "[SCRUBBED_JIRA_TOKEN]",
      )

      // Kubernetes / kubeconfig Tokens
      .replace(/token:\s*[A-Za-z0-9._-]{100,}/g, "token: [SCRUBBED_K8S_TOKEN]")

      // AWS STS Session Tokens
      .replace(/ASIA[0-9A-Z]{16}/g, "[SCRUBBED_AWS_STS_TOKEN]")

      // Azure Storage SAS URLs
      .replace(/sv=\d{4}-\d{2}-\d{2}&[^"'<>\s]+/gi, "sv=[SCRUBBED_AZURE_SAS]")

      // Google OAuth Refresh Tokens
      .replace(/1\/\/[A-Za-z0-9_-]{50,}/g, "[SCRUBBED_GOOGLE_OAUTH_REFRESH]")

      // PagerDuty API Keys
      .replace(/u\+[A-Za-z0-9]{20}/g, "[SCRUBBED_PAGERDUTY_KEY]")

      // Snyk API Tokens
      .replace(/snyk_[A-Za-z0-9]{40,}/g, "[SCRUBBED_SNYK_TOKEN]")

      // New Relic API Keys
      .replace(/NRAK-[A-Za-z0-9]{29}/g, "[SCRUBBED_NEWRELIC_KEY]")

      // Segment API Keys
      .replace(
        /write_key['":\s]+["']([A-Za-z0-9]{40})["']/gi,
        'write_key: "[SCRUBBED_SEGMENT_KEY]"',
      )

      // Twitch API Tokens
      .replace(
        /[A-Za-z0-9]{30}oauth[A-Za-z0-9]{30}/g,
        "[SCRUBBED_TWITCH_TOKEN]",
      )

      // Firebase Database URLs
      .replace(
        /https?:\/\/[A-Za-z0-9-]+\.firebaseio\.com/gi,
        "https://[SCRUBBED_FIREBASE_URL]",
      )

      // API Keys in URL paths
      .replace(
        /\/api\/[^/]+\/key[=/]([A-Za-z0-9_-]{20,})/gi,
        "/api/[SCRUBBED]/key=[SCRUBBED_API_KEY]",
      )

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

      // Grafana API Tokens
      .replace(/eyJrIjoi[A-Za-z0-9_-]+/g, "[SCRUBBED_GRAFANA_TOKEN]")
      .replace(/glc_[A-Za-z0-9_-]{30,}/g, "[SCRUBBED_GRAFANA_CLOUD_TOKEN]")

      // Datadog API Keys
      .replace(
        /[a-f0-9]{32}(?=\s*#.*datadog|".*datadog)/gi,
        "[SCRUBBED_DATADOG_KEY]",
      )

      // Elasticsearch API Keys
      .replace(
        /ApiKey\s+[A-Za-z0-9_-]{20,}/gi,
        "ApiKey [SCRUBBED_ELASTICSEARCH_KEY]",
      )

      // Pulumi API Tokens
      .replace(/pul-[A-Za-z0-9_]{30,}/g, "[SCRUBBED_PULUMI_TOKEN]")

      // Terraform Cloud API Tokens
      .replace(
        /[a-z0-9]{14}\.atlasv1\.[a-z0-9_-]{60,}/g,
        "[SCRUBBED_TERRAFORM_TOKEN]",
      )

      // CircleCI API Tokens
      .replace(/circle[a-f0-9]{40}/gi, "[SCRUBBED_CIRCLECI_TOKEN]")

      // Artifactory API Keys
      .replace(
        /AKCp[A-Za-z0-9]{10}[A-Za-z0-9]{40}/g,
        "[SCRUBBED_ARTIFACTORY_KEY]",
      )

      // BitBucket App Passwords
      .replace(/AppPassword_[A-Za-z0-9]{40}/g, "[SCRUBBED_BITBUCKET_PASSWORD]")

      // GitKraken Access Tokens
      .replace(/[A-Za-z0-9]{40}(?=.*gitkraken)/i, "[SCRUBBED_GITKRAKEN_TOKEN]")

      // LaunchDarkly SDK Keys
      .replace(/sdk-[a-f0-9]{32}/g, "[SCRUBBED_LAUNCHDARKLY_KEY]")

      // Stripe Restricted API Keys
      .replace(
        /rk_(?:live|test)_[A-Za-z0-9]{24,}/g,
        "[SCRUBBED_STRIPE_RESTRICTED_KEY]",
      )

      // Kubernetes Service Account Tokens (JWT format)
      .replace(/eyJhbGc[A-Za-z0-9_-]{100,}/g, "[SCRUBBED_K8S_SA_TOKEN]")

      // PostgreSQL connection strings
      .replace(
        /postgres:\/\/([^:]+):([^@]+)@([^:/]+)(:\d+)?\/([^\s"']+)/gi,
        "postgres://[SCRUBBED_USER]:[SCRUBBED_PASSWORD]@[SCRUBBED_HOST]/[SCRUBBED_DB]",
      )

      // CockroachDB connection strings
      .replace(
        /postgresql:\/\/([^:]+):([^@]+)@([^:/]+)(:\d+)?\/([^\s"']+)/gi,
        "postgresql://[SCRUBBED_USER]:[SCRUBBED_PASSWORD]@[SCRUBBED_HOST]/[SCRUBBED_DB]",
      )

      // MySQL connection strings
      .replace(
        /mysql:\/\/([^:]+):([^@]+)@([^:/]+)(:\d+)?\/([^\s"']+)/gi,
        "mysql://[SCRUBBED_USER]:[SCRUBBED_PASSWORD]@[SCRUBBED_HOST]/[SCRUBBED_DB]",
      )

      // Redis connection strings
      .replace(
        /rediss?:\/\/([^:]+):([^@]+)@([^/]+)/gi,
        "redis://[SCRUBBED_USER]:[SCRUBBED_PASSWORD]@[SCRUBBED_HOST]",
      )

      // RabbitMQ connection strings
      .replace(
        /amqps?:\/\/([^:]+):([^@]+)@([^/]+)/gi,
        "amqp://[SCRUBBED_USER]:[SCRUBBED_PASSWORD]@[SCRUBBED_HOST]",
      )

      // Memcached connection strings
      .replace(/memcache(?:d)?:\/\/[^/\s]+/gi, "memcached://[SCRUBBED_HOST]")

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

      // Sentry DSN
      .replace(
        /https?:\/\/[A-Za-z0-9]+@sentry\.io\/\d+/gi,
        "https://[SCRUBBED]@sentry.io/[SCRUBBED]",
      )

      // Slack Webhook URLs
      .replace(
        /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9_-]+/g,
        "https://hooks.slack.com/services/[SCRUBBED]",
      )

      // Vercel API Tokens
      .replace(/vercel_[A-Za-z0-9_]{40,}/g, "[SCRUBBED_VERCEL_TOKEN]")

      // Netlify API Tokens
      .replace(/netlify_[A-Za-z0-9_]{40,}/g, "[SCRUBBED_NETLIFY_TOKEN]")

      // Twitter/X Bearer Tokens
      .replace(/AAAA[A-Za-z0-9_-]{100,}/g, "[SCRUBBED_TWITTER_BEARER]")

      // Auth0 API Tokens
      .replace(/[A-Za-z0-9_-]{40}(?=.*auth0)/gi, "[SCRUBBED_AUTH0_TOKEN]")

      // Cloudinary URLs with credentials
      .replace(
        /cloudinary:\/\/[^:]+:[^@]+@[^/]+/gi,
        "cloudinary://[SCRUBBED_KEY]:[SCRUBBED_SECRET]@[SCRUBBED_HOST]",
      )

      // AWS S3 presigned URLs
      .replace(
        /s3\.amazonaws\.com\/[^?]+\?.*?(?:X-Amz-Signature|AWSAccessKeyId)=[^&\s"']+/gi,
        "s3.amazonaws.com/[SCRUBBED_URL]",
      )

      // Docker Registry Authentication
      .replace(
        /"auth"\s*:\s*"[A-Za-z0-9+/]{20,}"(?=\s*[},])/g,
        '"auth":"[SCRUBBED_DOCKER_AUTH]"',
      )

      // AWS CLI Credentials Format
      .replace(
        /aws_(?:secret_)?access_key(?:_id)?\s*=\s*[A-Za-z0-9/+=]{20,}/gi,
        "aws_access_key=[SCRUBBED_AWS_KEY]",
      )

      // PayPal Signature
      .replace(
        /Signature\s*=\s*[A-Za-z0-9_%-]{50,}/gi,
        "Signature=[SCRUBBED_PAYPAL_SIGNATURE]",
      )

      // Braintree Keys
      .replace(
        /braintree_(?:private|public)_[A-Za-z0-9_]{32,}/g,
        "[SCRUBBED_BRAINTREE_KEY]",
      )

      // Replicate API Tokens
      .replace(/rp_[a-f0-9]{32}/g, "[SCRUBBED_REPLICATE_TOKEN]")

      // Together AI API Keys
      .replace(/[a-f0-9]{64}(?=.*together)/gi, "[SCRUBBED_TOGETHER_AI_KEY]")

      // PKCS#12/PFX Private Keystores
      .replace(/MIIF[A-Za-z0-9+/=]{100,}/g, "[SCRUBBED_PKCS12_KEYSTORE]")

      // Notion API Tokens
      .replace(/Notion_[A-Za-z0-9_-]{50,}/g, "[SCRUBBED_NOTION_TOKEN]")

      // Linear API Keys
      .replace(/lin_[A-Za-z0-9]{40}/g, "[SCRUBBED_LINEAR_KEY]")

      // Figma API Tokens
      .replace(/figd_[A-Za-z0-9_-]{40,}/g, "[SCRUBBED_FIGMA_TOKEN]")

      // Zendesk API Tokens
      .replace(/zendesk_[A-Za-z0-9]{40,}/gi, "[SCRUBBED_ZENDESK_TOKEN]")

      // HubSpot API Keys
      .replace(
        /(?:pat-|hapikey\s*=\s*)[A-Za-z0-9-]{40,}/gi,
        "[SCRUBBED_HUBSPOT_KEY]",
      )

      // Mailchimp API Keys
      .replace(/[A-Za-z0-9]{32}-us\d+/g, "[SCRUBBED_MAILCHIMP_KEY]")

      // SendInBlue / Brevo API Keys
      .replace(/xkeysib-[A-Za-z0-9]{64,}/g, "[SCRUBBED_BREVO_KEY]")

      // Cohere API Keys
      .replace(/[A-Za-z0-9_-]{40}(?=.*cohere)/gi, "[SCRUBBED_COHERE_KEY]")

      // Claude API Keys (Anthropic)
      .replace(/sk-ant-[A-Za-z0-9_-]{48,}/g, "[SCRUBBED_CLAUDE_KEY]")

      // IBM Cloud API Keys
      .replace(/apikey-[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_IBM_CLOUD_KEY]")

      // Mapbox API Tokens
      .replace(/[ps]k\.[A-Za-z0-9_-]{80,}/g, "[SCRUBBED_MAPBOX_TOKEN]")

      // Stripe Webhook Signing Secrets
      .replace(/whsec_[A-Za-z0-9_]{40,}/g, "[SCRUBBED_STRIPE_WEBHOOK_SECRET]")

      // Plaid API Secrets
      .replace(/plaid_[a-z]+_[A-Za-z0-9]{40,}/gi, "[SCRUBBED_PLAID_SECRET]")

      // Google Cloud Storage presigned URLs
      .replace(
        /https:\/\/storage\.googleapis\.com\/[^?]+\?[^"'<>\s]*(?:X-Goog-Credential|X-Goog-Signature)=[^&\s"']+/gi,
        "https://storage.googleapis.com/[SCRUBBED_URL]",
      )

      // DigitalOcean Spaces Access Keys
      .replace(/DO[A-Z0-9]{20,}/g, "[SCRUBBED_DIGITALOCEAN_SPACE_KEY]")

      // Strapi API Tokens
      .replace(/strapi_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_STRAPI_TOKEN]")

      // Contentful API Tokens
      .replace(
        /[A-Za-z0-9_-]{43}(?=.*contentful)/gi,
        "[SCRUBBED_CONTENTFUL_TOKEN]",
      )

      // Weights & Biases API Keys
      .replace(/wandb_[A-Za-z0-9]{40,}/g, "[SCRUBBED_WANDB_KEY]")

      // Kaggle API Credentials
      .replace(/kaggle_[A-Za-z0-9_]{40,}/gi, "[SCRUBBED_KAGGLE_KEY]")

      // MLflow Tracking Tokens
      .replace(/mlflow_[A-Za-z0-9_]{40,}/gi, "[SCRUBBED_MLFLOW_TOKEN]")

      // Honeycomb API Keys
      .replace(/hny_[A-Za-z0-9_]{40,}/g, "[SCRUBBED_HONEYCOMB_KEY]")

      // Lightstep API Tokens
      .replace(/lightstep_[A-Za-z0-9_]{40,}/gi, "[SCRUBBED_LIGHTSTEP_TOKEN]")

      // Rollbar API Tokens
      .replace(/rollbar_[A-Za-z0-9_]{40,}/gi, "[SCRUBBED_ROLLBAR_TOKEN]")

      // Microsoft Teams Webhooks
      .replace(
        /https:\/\/outlook\.webhook\.office\.com\/webhookb2\/[^\s"']+/gi,
        "https://outlook.webhook.office.com/webhookb2/[SCRUBBED]",
      )

      // Discord Webhooks
      .replace(
        /https:\/\/discord\.com\/api\/webhooks\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+/g,
        "https://discord.com/api/webhooks/[SCRUBBED]",
      )

      // Mattermost Webhooks
      .replace(
        /https?:\/\/[A-Za-z0-9.-]+\/hooks\/[A-Za-z0-9]{26}/gi,
        "https://[SCRUBBED]/hooks/[SCRUBBED]",
      )

      // CodeClimate API Tokens
      .replace(
        /codeclimate_[A-Za-z0-9_]{40,}/gi,
        "[SCRUBBED_CODECLIMATE_TOKEN]",
      )

      // SonarQube Tokens
      .replace(/squ_[A-Za-z0-9]{40,}/g, "[SCRUBBED_SONARQUBE_TOKEN]")

      // Codecov Upload Tokens
      .replace(/codecov_[A-Za-z0-9_]{40,}/gi, "[SCRUBBED_CODECOV_TOKEN]")

      // 1Password API Tokens
      .replace(
        /op_service_account_token_[A-Za-z0-9_-]{40,}/gi,
        "[SCRUBBED_1PASSWORD_TOKEN]",
      )

      // Vault Service Account Tokens
      .replace(/s\.[A-Za-z0-9]{20,}/g, "[SCRUBBED_VAULT_SA_TOKEN]")

      // Parse Server Master Keys
      .replace(
        /parse_master_[A-Za-z0-9_]{40,}/gi,
        "[SCRUBBED_PARSE_MASTER_KEY]",
      )

      // OneSignal API Keys
      .replace(/os_[A-Za-z0-9]{40,}/g, "[SCRUBBED_ONESIGNAL_KEY]")

      // Pinecone API Keys
      .replace(/pinecone_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_PINECONE_KEY]")

      // Weaviate API Keys
      .replace(/weaviate_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_WEAVIATE_KEY]")

      // Milvus/Zilliz Tokens
      .replace(/zilliz_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_ZILLIZ_TOKEN]")

      // Backblaze B2 API Keys
      .replace(/b2_[A-Za-z0-9]{40,}/g, "[SCRUBBED_B2_KEY]")

      // MinIO Access Keys
      .replace(/minioadmin[A-Za-z0-9]{32,}/gi, "[SCRUBBED_MINIO_KEY]")

      // Linode API Tokens
      .replace(/[a-f0-9]{40}(?=.*linode)/gi, "[SCRUBBED_LINODE_TOKEN]")

      // Vultr API Keys
      .replace(/[a-f0-9]{40}(?=.*vultr)/gi, "[SCRUBBED_VULTR_KEY]")

      // Hetzner API Tokens
      .replace(/hcloud_[A-Za-z0-9]{40,}/g, "[SCRUBBED_HETZNER_TOKEN]")

      // SMTP Credentials
      .replace(
        /smtp:\/\/[^:]+:[^@]+@[^/\s]+/gi,
        "smtp://[SCRUBBED_USER]:[SCRUBBED_PASSWORD]@[SCRUBBED_HOST]",
      )

      // FTP/SFTP Credentials
      .replace(
        /s?ftps?:\/\/[^:]+:[^@]+@[^/\s]+/gi,
        "ftp://[SCRUBBED_USER]:[SCRUBBED_PASSWORD]@[SCRUBBED_HOST]",
      )

      // Atlantis API Tokens
      .replace(/atlantis_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_ATLANTIS_TOKEN]")

      // Buildkite API Tokens
      .replace(/bk_[A-Za-z0-9]{40,}/g, "[SCRUBBED_BUILDKITE_TOKEN]")

      // Harness API Keys
      .replace(/harness_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_HARNESS_KEY]")

      // Telegram Bot API Tokens
      .replace(/\d{9,10}:[A-Za-z0-9_-]{35,}/g, "[SCRUBBED_TELEGRAM_BOT_TOKEN]")

      // WhatsApp Business API Tokens
      .replace(/whatsapp_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_WHATSAPP_TOKEN]")

      // AWS IAM User Access Keys
      .replace(
        /AKIA[0-9A-Z]{16}\s*\n\s*[A-Za-z0-9/+=]{40}/g,
        "[SCRUBBED_AWS_CREDENTIALS]",
      )

      // Google Cloud JSON Service Account
      .replace(
        /"type"\s*:\s*"service_account"[\s\S]*?"private_key_id"\s*:\s*"[^"]+"/g,
        '"type":"service_account"..."private_key_id":"[SCRUBBED]"',
      )

      // Ethereum/Bitcoin Private Keys
      .replace(/0x[a-f0-9]{64}(?=\s|[,})\]])/gi, "0x[SCRUBBED_PRIVATE_KEY]")

      // Salesforce OAuth Tokens
      .replace(/salesforce_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_SALESFORCE_TOKEN]")

      // SAP API Tokens
      .replace(/sap_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_SAP_TOKEN]")

      // Mixpanel API Tokens
      .replace(/mixpanel_[A-Za-z0-9_]{40,}/gi, "[SCRUBBED_MIXPANEL_TOKEN]")

      // Vonage API Keys
      .replace(/vonage_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_VONAGE_KEY]")

      // Telnyx API Tokens
      .replace(/telnyx_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_TELNYX_TOKEN]")

      // Alibaba Cloud Access Keys
      .replace(/LTAI[A-Za-z0-9]{20}/g, "[SCRUBBED_ALIBABA_KEY]")

      // Huawei Cloud API Keys
      .replace(/huawei_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_HUAWEI_KEY]")

      // Splunk HEC Tokens
      .replace(/splunk_hec_[A-Za-z0-9_-]{36,}/gi, "[SCRUBBED_SPLUNK_TOKEN]")

      // Datadog App Keys
      .replace(/app_[a-f0-9]{32}/gi, "[SCRUBBED_DATADOG_APP_KEY]")

      // Loggly API Tokens
      .replace(/loggly_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_LOGGLY_TOKEN]")

      // Gitea API Tokens
      .replace(/gitea_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_GITEA_TOKEN]")

      // OpenStack Tokens
      .replace(/openstack_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_OPENSTACK_TOKEN]")

      // Keycloak Tokens
      .replace(/keycloak_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_KEYCLOAK_TOKEN]")

      // DynamoDB Access Keys
      .replace(/dynamodb_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_DYNAMODB_KEY]")

      // Firestore Credentials
      .replace(
        /"database":\s*"projects\/[^"]+\/databases\/\(default\)"[\s\S]*?"private_key"/g,
        '"database":"[SCRUBBED]"...',
      )

      // Stability AI API Keys
      .replace(/stability_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_STABILITY_AI_KEY]")

      // Mistral AI API Keys
      .replace(/mistral_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_MISTRAL_KEY]")

      // Groq API Keys
      .replace(/groq_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_GROQ_KEY]")

      // ElevenLabs API Keys
      .replace(/elevenlabs_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_ELEVENLABS_KEY]")

      // Zapier API Keys / Webhooks
      .replace(/zapier_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_ZAPIER_KEY]")

      // IFTTT Webhooks
      .replace(
        /https:\/\/maker\.ifttt\.com\/use\/[A-Za-z0-9_-]{20,}/gi,
        "https://maker.ifttt.com/use/[SCRUBBED]",
      )

      // Make.com (Integromat) API Tokens
      .replace(/make_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_MAKE_TOKEN]")

      // Railway API Tokens
      .replace(/railway_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_RAILWAY_TOKEN]")

      // Render API Keys
      .replace(/render_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_RENDER_KEY]")

      // Fly.io API Tokens
      .replace(/fly_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_FLY_TOKEN]")

      // Replit API Tokens
      .replace(/replit_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_REPLIT_TOKEN]")

      // Typeform API Tokens
      .replace(/typeform_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_TYPEFORM_TOKEN]")

      // Airtable API Keys
      .replace(/airtable_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_AIRTABLE_KEY]")

      // Webflow API Tokens
      .replace(/webflow_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_WEBFLOW_TOKEN]")

      // Algolia API Keys
      .replace(/algolia_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_ALGOLIA_KEY]")

      // Coinbase API Keys
      .replace(/coinbase_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_COINBASE_KEY]")

      // Clerk API Keys (Auth)
      .replace(/clerk_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_CLERK_KEY]")

      // Perplexity API Keys
      .replace(/perplexity_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_PERPLEXITY_KEY]")

      // Fireworks AI Tokens
      .replace(/fireworks_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_FIREWORKS_TOKEN]")

      // Cerebras API Keys
      .replace(/cerebras_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_CEREBRAS_KEY]")

      // Qdrant API Keys
      .replace(/qdrant_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_QDRANT_KEY]")

      // Vespa Cloud Tokens
      .replace(/vespa_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_VESPA_TOKEN]")

      // Infura API Keys
      .replace(/infura_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_INFURA_KEY]")

      // Alchemy API Keys
      .replace(/alchemy_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_ALCHEMY_KEY]")

      // QuickNode RPC Endpoints
      .replace(/quicknode_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_QUICKNODE_TOKEN]")

      // Amplitude API Tokens
      .replace(/amplitude_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_AMPLITUDE_TOKEN]")

      // Heap Analytics Keys
      .replace(/heap_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_HEAP_KEY]")

      // Sanity.io API Tokens
      .replace(/sanity_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_SANITY_TOKEN]")

      // Prismic API Tokens
      .replace(/prismic_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_PRISMIC_TOKEN]")

      // Ghost CMS Keys
      .replace(/ghost_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_GHOST_KEY]")

      // Asana API Tokens
      .replace(/asana_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_ASANA_TOKEN]")

      // Monday.com API Keys
      .replace(/monday_[A-Za-z0-9_-]{40,}/gi, "[SCRUBBED_MONDAY_KEY]")

      // BrowserStack API Keys
      .replace(
        /browserstack_[A-Za-z0-9_-]{40,}/gi,
        "[SCRUBBED_BROWSERSTACK_KEY]",
      )

      // Hex-encoded credentials
      .replace(/[a-f0-9]{32}(?=['":])/gi, "[SCRUBBED_HEX_SECRET]")
  );
}
