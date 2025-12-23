"""
Secrets Detection Payloads

Patterns and paths for detecting leaked secrets including:
- API keys (AWS, Stripe, GitHub, etc.)
- Credentials in source code
- Exposed configuration files
- Environment variable leakage
"""

import re

# Secret patterns with regex and descriptions
SECRET_PATTERNS = {
    # AWS
    "aws_access_key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "description": "AWS Access Key ID",
        "severity": "critical",
    },
    "aws_secret_key": {
        "pattern": r"(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
        "description": "AWS Secret Access Key",
        "severity": "critical",
    },
    "aws_mws_key": {
        "pattern": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "description": "Amazon MWS Auth Token",
        "severity": "high",
    },

    # Google Cloud
    "gcp_api_key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "description": "Google Cloud API Key",
        "severity": "high",
    },
    "gcp_oauth": {
        "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "description": "Google OAuth Client ID",
        "severity": "medium",
    },
    "gcp_service_account": {
        "pattern": r'"type"\s*:\s*"service_account"',
        "description": "Google Cloud Service Account JSON",
        "severity": "critical",
    },
    "firebase_api_key": {
        "pattern": r"(?i)firebase[_\-]?(?:api[_\-]?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{39})",
        "description": "Firebase API Key",
        "severity": "high",
    },

    # Azure
    "azure_storage_key": {
        "pattern": r"(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{86,}",
        "description": "Azure Storage Account Key",
        "severity": "critical",
    },
    "azure_sas_token": {
        "pattern": r"(?i)sv=[\d]{4}-[\d]{2}-[\d]{2}&s[a-z]=[\w%]+",
        "description": "Azure SAS Token",
        "severity": "high",
    },

    # Stripe
    "stripe_secret_key": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
        "description": "Stripe Live Secret Key",
        "severity": "critical",
    },
    "stripe_publishable_key": {
        "pattern": r"pk_live_[0-9a-zA-Z]{24,}",
        "description": "Stripe Live Publishable Key",
        "severity": "low",
    },
    "stripe_test_secret": {
        "pattern": r"sk_test_[0-9a-zA-Z]{24,}",
        "description": "Stripe Test Secret Key",
        "severity": "medium",
    },
    "stripe_restricted_key": {
        "pattern": r"rk_live_[0-9a-zA-Z]{24,}",
        "description": "Stripe Restricted API Key",
        "severity": "high",
    },

    # GitHub
    "github_token": {
        "pattern": r"ghp_[0-9a-zA-Z]{36}",
        "description": "GitHub Personal Access Token",
        "severity": "critical",
    },
    "github_oauth": {
        "pattern": r"gho_[0-9a-zA-Z]{36}",
        "description": "GitHub OAuth Access Token",
        "severity": "critical",
    },
    "github_app_token": {
        "pattern": r"(?:ghu|ghs)_[0-9a-zA-Z]{36}",
        "description": "GitHub App Token",
        "severity": "high",
    },
    "github_refresh_token": {
        "pattern": r"ghr_[0-9a-zA-Z]{36}",
        "description": "GitHub Refresh Token",
        "severity": "high",
    },
    "github_fine_grained": {
        "pattern": r"github_pat_[0-9a-zA-Z_]{22,}",
        "description": "GitHub Fine-Grained PAT",
        "severity": "critical",
    },

    # GitLab
    "gitlab_token": {
        "pattern": r"glpat-[0-9a-zA-Z\-_]{20,}",
        "description": "GitLab Personal Access Token",
        "severity": "critical",
    },
    "gitlab_runner_token": {
        "pattern": r"GR1348941[0-9a-zA-Z\-_]{20,}",
        "description": "GitLab Runner Registration Token",
        "severity": "high",
    },

    # Slack
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        "description": "Slack Token",
        "severity": "high",
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{24}",
        "description": "Slack Webhook URL",
        "severity": "high",
    },

    # Discord
    "discord_token": {
        "pattern": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
        "description": "Discord Bot Token",
        "severity": "high",
    },
    "discord_webhook": {
        "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
        "description": "Discord Webhook URL",
        "severity": "medium",
    },

    # Twilio
    "twilio_api_key": {
        "pattern": r"SK[0-9a-fA-F]{32}",
        "description": "Twilio API Key",
        "severity": "high",
    },
    "twilio_account_sid": {
        "pattern": r"AC[0-9a-fA-F]{32}",
        "description": "Twilio Account SID",
        "severity": "medium",
    },

    # SendGrid
    "sendgrid_api_key": {
        "pattern": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
        "description": "SendGrid API Key",
        "severity": "high",
    },

    # Mailgun
    "mailgun_api_key": {
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "description": "Mailgun API Key",
        "severity": "high",
    },

    # Mailchimp
    "mailchimp_api_key": {
        "pattern": r"[0-9a-f]{32}-us[0-9]{1,2}",
        "description": "Mailchimp API Key",
        "severity": "high",
    },

    # PayPal
    "paypal_braintree": {
        "pattern": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        "description": "PayPal Braintree Access Token",
        "severity": "critical",
    },

    # Square
    "square_access_token": {
        "pattern": r"sq0atp-[0-9A-Za-z\-_]{22}",
        "description": "Square Access Token",
        "severity": "critical",
    },
    "square_oauth_secret": {
        "pattern": r"sq0csp-[0-9A-Za-z\-_]{43}",
        "description": "Square OAuth Secret",
        "severity": "critical",
    },

    # Shopify
    "shopify_shared_secret": {
        "pattern": r"shpss_[0-9a-fA-F]{32}",
        "description": "Shopify Shared Secret",
        "severity": "high",
    },
    "shopify_access_token": {
        "pattern": r"shpat_[0-9a-fA-F]{32}",
        "description": "Shopify Access Token",
        "severity": "critical",
    },
    "shopify_custom_app": {
        "pattern": r"shpca_[0-9a-fA-F]{32}",
        "description": "Shopify Custom App Access Token",
        "severity": "critical",
    },

    # Heroku
    "heroku_api_key": {
        "pattern": r"(?i)heroku[_\-]?api[_\-]?key['\"]?\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        "description": "Heroku API Key",
        "severity": "high",
    },

    # OpenAI
    "openai_api_key": {
        "pattern": r"sk-[0-9a-zA-Z]{48}",
        "description": "OpenAI API Key",
        "severity": "high",
    },
    "openai_api_key_proj": {
        "pattern": r"sk-proj-[0-9a-zA-Z]{48,}",
        "description": "OpenAI Project API Key",
        "severity": "high",
    },

    # Anthropic
    "anthropic_api_key": {
        "pattern": r"sk-ant-[0-9a-zA-Z\-_]{80,}",
        "description": "Anthropic API Key",
        "severity": "high",
    },

    # Generic patterns
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "description": "Private Key",
        "severity": "critical",
    },
    "private_key_pkcs8": {
        "pattern": r"-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "description": "Encrypted Private Key (PKCS8)",
        "severity": "critical",
    },
    "pgp_private_key": {
        "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "description": "PGP Private Key",
        "severity": "critical",
    },
    "ssh_private_key": {
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "description": "OpenSSH Private Key",
        "severity": "critical",
    },

    # JWT
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
        "description": "JWT Token",
        "severity": "medium",
    },

    # Database connection strings
    "mongodb_uri": {
        "pattern": r"mongodb(?:\+srv)?://[^\s\"'<>]+",
        "description": "MongoDB Connection String",
        "severity": "critical",
    },
    "postgresql_uri": {
        "pattern": r"postgres(?:ql)?://[^\s\"'<>]+",
        "description": "PostgreSQL Connection String",
        "severity": "critical",
    },
    "mysql_uri": {
        "pattern": r"mysql://[^\s\"'<>]+",
        "description": "MySQL Connection String",
        "severity": "critical",
    },
    "redis_uri": {
        "pattern": r"redis://[^\s\"'<>]+",
        "description": "Redis Connection String",
        "severity": "high",
    },

    # Generic API keys
    "generic_api_key": {
        "pattern": r"(?i)(?:api[_\-]?key|apikey|api_secret|apisecret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})",
        "description": "Generic API Key",
        "severity": "medium",
    },
    "generic_secret": {
        "pattern": r"(?i)(?:secret|password|passwd|pwd|token|auth)[_\-]?(?:key)?['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-!@#$%^&*]{8,})['\"]?",
        "description": "Generic Secret/Password",
        "severity": "medium",
    },
    "bearer_token": {
        "pattern": r"(?i)bearer\s+[a-zA-Z0-9_\-\.]+",
        "description": "Bearer Token",
        "severity": "high",
    },
    "basic_auth": {
        "pattern": r"(?i)basic\s+[a-zA-Z0-9+/=]{20,}",
        "description": "Basic Auth Credentials",
        "severity": "high",
    },

    # npm
    "npm_token": {
        "pattern": r"npm_[A-Za-z0-9]{36}",
        "description": "NPM Access Token",
        "severity": "high",
    },

    # PyPI
    "pypi_token": {
        "pattern": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}",
        "description": "PyPI API Token",
        "severity": "high",
    },

    # NuGet
    "nuget_api_key": {
        "pattern": r"oy2[a-z0-9]{43}",
        "description": "NuGet API Key",
        "severity": "high",
    },

    # Telegram
    "telegram_bot_token": {
        "pattern": r"[0-9]{8,10}:[0-9A-Za-z_-]{35}",
        "description": "Telegram Bot Token",
        "severity": "high",
    },

    # Facebook
    "facebook_access_token": {
        "pattern": r"EAACEdEose0cBA[0-9A-Za-z]+",
        "description": "Facebook Access Token",
        "severity": "high",
    },
    "facebook_oauth": {
        "pattern": r"(?i)facebook[_\-]?(?:app[_\-]?)?secret['\"]?\s*[:=]\s*['\"]?([0-9a-f]{32})",
        "description": "Facebook App Secret",
        "severity": "critical",
    },

    # Twitter/X
    "twitter_access_token": {
        "pattern": r"(?i)twitter[_\-]?(?:access[_\-]?)?token['\"]?\s*[:=]\s*['\"]?([0-9]{18}-[a-zA-Z0-9]{40})",
        "description": "Twitter Access Token",
        "severity": "high",
    },
    "twitter_bearer": {
        "pattern": r"AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+",
        "description": "Twitter Bearer Token",
        "severity": "high",
    },

    # Datadog
    "datadog_api_key": {
        "pattern": r"(?i)datadog[_\-]?api[_\-]?key['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})",
        "description": "Datadog API Key",
        "severity": "high",
    },

    # New Relic
    "newrelic_license_key": {
        "pattern": r"(?i)new[_\-]?relic[_\-]?license[_\-]?key['\"]?\s*[:=]\s*['\"]?([a-f0-9]{40})",
        "description": "New Relic License Key",
        "severity": "high",
    },

    # Sentry
    "sentry_dsn": {
        "pattern": r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+",
        "description": "Sentry DSN",
        "severity": "medium",
    },
}

# Paths to check for exposed configuration files
CONFIG_EXPOSURE_PATHS = [
    # Environment files
    "/.env",
    "/.env.local",
    "/.env.development",
    "/.env.production",
    "/.env.staging",
    "/.env.test",
    "/.env.backup",
    "/.env.bak",
    "/.env.old",
    "/.env.save",
    "/.env.example",  # Sometimes contains real values
    "/.env.sample",
    "/env",
    "/env.js",
    "/env.json",

    # Config files
    "/config.json",
    "/config.yaml",
    "/config.yml",
    "/config.xml",
    "/config.php",
    "/config.py",
    "/config.js",
    "/config.ini",
    "/config.cfg",
    "/configuration.json",
    "/settings.json",
    "/settings.yaml",
    "/settings.py",
    "/settings.php",

    # Backup files
    "/config.json.bak",
    "/config.yaml.bak",
    "/config.php.bak",
    "/config.py.bak",
    "/config.json.backup",
    "/config.yaml.backup",
    "/config.json.old",
    "/config.yaml.old",
    "/config.json~",
    "/config.yaml~",
    "/database.yml.bak",
    "/database.yml.backup",

    # Framework-specific
    "/application.properties",
    "/application.yml",
    "/application.yaml",
    "/application-dev.properties",
    "/application-prod.properties",
    "/appsettings.json",
    "/appsettings.Development.json",
    "/appsettings.Production.json",
    "/web.config",
    "/web.config.bak",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.php.backup",
    "/wp-config.php~",
    "/wp-config.old",
    "/configuration.php",
    "/local_settings.py",
    "/secrets.yaml",
    "/secrets.yml",
    "/secrets.json",
    "/credentials.json",
    "/credentials.yaml",
    "/credentials.xml",

    # Database configs
    "/database.yml",
    "/database.json",
    "/db.json",
    "/db_config.php",
    "/database_config.php",
    "/db_connection.php",

    # AWS/Cloud configs
    "/.aws/credentials",
    "/.aws/config",
    "/aws_credentials",
    "/gcp_credentials.json",
    "/azure_credentials.json",
    "/service_account.json",
    "/google_credentials.json",
    "/firebase-adminsdk.json",
    "/firebase.json",

    # SSH/Keys
    "/.ssh/id_rsa",
    "/.ssh/id_rsa.pub",
    "/.ssh/id_ed25519",
    "/.ssh/authorized_keys",
    "/id_rsa",
    "/id_rsa.pub",
    "/server.key",
    "/private.key",
    "/privatekey.pem",
    "/key.pem",
    "/cert.pem",
    "/server.pem",

    # Version control
    "/.git/config",
    "/.gitconfig",
    "/.svn/entries",
    "/.hg/hgrc",

    # IDE/Editor configs
    "/.idea/workspace.xml",
    "/.vscode/settings.json",
    "/.vscode/launch.json",

    # Docker
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/docker-compose.override.yml",
    "/.docker/config.json",
    "/Dockerfile",

    # CI/CD
    "/.travis.yml",
    "/.github/workflows/",
    "/.gitlab-ci.yml",
    "/Jenkinsfile",
    "/bitbucket-pipelines.yml",

    # Package managers
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/composer.json",
    "/composer.lock",
    "/Gemfile",
    "/Gemfile.lock",
    "/requirements.txt",
    "/Pipfile",
    "/Pipfile.lock",
    "/poetry.lock",
    "/pyproject.toml",
    "/pom.xml",
    "/build.gradle",

    # Logs (may contain secrets)
    "/debug.log",
    "/error.log",
    "/access.log",
    "/app.log",
    "/application.log",
    "/server.log",
    "/npm-debug.log",
    "/yarn-error.log",

    # Miscellaneous
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/dump.sql",
    "/backup.sql",
    "/database.sql",
    "/db.sql",
    "/.htpasswd",
    "/.htaccess",
    "/server-status",
    "/server-info",
]

# JavaScript file patterns to check
JS_FILE_PATTERNS = [
    "/main.js",
    "/app.js",
    "/bundle.js",
    "/vendor.js",
    "/config.js",
    "/env.js",
    "/settings.js",
    "/constants.js",
    "/api.js",
    "/client.js",
    "/index.js",
    "/runtime.js",
    "/chunk-vendors.js",
    "/static/js/main.*.js",
    "/static/js/bundle.js",
    "/assets/js/app.js",
    "/dist/main.js",
    "/dist/bundle.js",
    "/build/main.js",
    "/build/bundle.js",
    "/js/app.js",
    "/js/main.js",
    "/js/config.js",
]

# Source map files (may expose source code with secrets)
SOURCE_MAP_PATTERNS = [
    "/main.js.map",
    "/app.js.map",
    "/bundle.js.map",
    "/vendor.js.map",
    "/static/js/main.*.js.map",
    "/dist/main.js.map",
    "/build/main.js.map",
]


def compile_secret_patterns():
    """Compile regex patterns for efficiency."""
    compiled = {}
    for name, info in SECRET_PATTERNS.items():
        try:
            compiled[name] = {
                "regex": re.compile(info["pattern"]),
                "description": info["description"],
                "severity": info["severity"],
            }
        except re.error:
            pass  # Skip invalid patterns
    return compiled


COMPILED_SECRET_PATTERNS = compile_secret_patterns()
