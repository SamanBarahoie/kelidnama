PATTERNS = {
    # Cloud Providers - AWS
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]",
    "AWS STS Assumed Role ARN": r"arn:aws:sts::\d{12}:assumed-role/[\w+=,.@-]+/[\w+=,.@-]+",

    # Cloud Providers - Azure
    "Azure Storage Key": r"(?i)azure[_-]?storage[_-]?key\s*=\s*['\"][A-Za-z0-9+/=]{88}['\"]",

    # Cloud Providers - DigitalOcean
    "DigitalOcean Personal Access Token": r"do[0-9a-f]{62}",

    # Cloud Providers - Heroku
    "Heroku API Key": r"(?i)heroku_api_key\s*=\s*['\"][A-Za-z0-9]{32}['\"]",

    # Version Control & CI/CD
    "GitHub Personal Access Token (ghp)": r"ghp_[A-Za-z0-9]{36}",
    "GitHub OAuth Token (gho/ghs/ghu/ghr/ghc)": r"gh[opsu]_[A-Za-z0-9]{36}",
    "GitLab Personal Access Token": r"glpat-[A-Za-z0-9]{20}",
    "Netlify API Token": r"[a-z0-9]{40}",

    # Webhooks
    "Slack Webhook URL": r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+",
    "Microsoft Teams Webhook URL": r"https://outlook\.office\.com/webhook/[A-Za-z0-9-]+/IncomingWebhook/[A-Za-z0-9-]+/[A-Za-z0-9-]+",
    "Stripe Webhook Secret": r"whsec_[A-Za-z0-9]{32}",

    # Messaging & Chat
    "Telegram Bot Token": r"\d{9}:[A-Za-z0-9_-]{35,}",
    "Discord Bot Token": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z-]{10,48}",

    # OAuth & JWT
    "JSON Web Token (JWT)": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "Google OAuth Access Token": r"ya29\.[0-9A-Za-z\-_]+",
    "Google OAuth Refresh Token": r"1/[0-9A-Za-z\-_]+",
    "Auth0 ID Token": r"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "OAuth1 Consumer Secret": r"[0-9a-fA-F]{32}",
    "OAuth2 Access Token Parameter": r"access_token=[A-Za-z0-9\-_.]+",

    # Payment
    "Stripe Secret Key": r"sk_(live|test)_[0-9a-zA-Z]{24}",
    "Stripe Publishable Key": r"pk_(live|test)_[0-9a-zA-Z]{24}",
    "Twilio Account SID": r"AC[0-9a-fA-F]{32}",
    "Twilio Auth Token": r"[0-9a-fA-F]{32}",
    "Shopify Access Token": r"shpat_[a-fA-F0-9]{32}",

    # API Keys
    "Firebase API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Generic API Key": r"(?i)api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{16,45}['\"]?",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Mailchimp API Key": r"[0-9a-f]{32}-us[0-9]+",
    "SendGrid API Key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "Cloudflare API Token": r"(?i)cloudflare_api_token\s*=\s*['\"][A-Za-z0-9_\-]{40,50}['\"]",
    "Terraform Cloud API Token": r"tfc-[A-Za-z0-9]{40}",

    # Databases & Connections
    "MongoDB Connection URI": r"mongodb(?:\+srv)?:\/\/[A-Za-z0-9._%+-]+:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+(?:\/[A-Za-z0-9_-]+)?",
    "PostgreSQL Connection String": r"postgres:\/\/[A-Za-z0-9]+:[A-Za-z0-9@%._+~#=]+@[A-Za-z0-9.-]+:[0-9]+\/[A-Za-z0-9_-]+",

    # SSH & PGP Keys
    "SSH Private Key (RSA)": r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----",
    "SSH Private Key (PKCS8)": r"-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----",
    "SSH Public Key (RSA)": r"ssh-rsa AAAA[0-9A-Za-z+/]+={0,3}(\s.+)?",
    "PGP Private Key Block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----",

    # Miscellaneous
    "Base64 Long Strings": r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
    "IPv4 Private (10.x.x.x)": r"\b10(?:\.\d{1,3}){3}\b",
    "Docker Hub Auth Field": r"\"auth\"\s*:\s*\"[A-Za-z0-9+/=]{20,}\"",
    "Sentry DSN": r"https://[0-9a-f]+@sentry\.io/\d+",

    # Credentials in Code
    "Password Assignment": r"(?i)password\s*=\s*[\"'].*?[\"']",
    "Generic Secret Assignment": r"(?i)secret\s*=\s*[\"'].*?[\"']",
}
