"""
Ninja-API-Hunter v4.0
Shared defaults, wordlists and regex signatures used across modules.
"""

DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 20
DEFAULT_USER_AGENT = "Ninja-API-Hunter/4.0"

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# Common locations where API documentation files are published.
SWAGGER_PATHS = [
    "swagger.json", "openapi.json", "swagger.yaml", "openapi.yaml",
    "v2/swagger.json", "v2/api-docs", "v3/api-docs", "api-docs",
    "api-docs.json", "swagger/v1/swagger.json", "docs/swagger.json",
    "api/swagger.json", "api/openapi.json", ".well-known/openapi.json",
]

# Small, conservative list of commonly-exposed sensitive paths.
# Extend this for your own engagements as needed.
SENSITIVE_FILES = [
    ".git/config", ".git/HEAD", ".env", ".env.local", ".env.production",
    ".env.backup", "config.php.bak", "web.config", ".DS_Store",
    "backup.zip", "backup.sql", "dump.sql", ".aws/credentials",
    "id_rsa", "id_rsa.pub", "docker-compose.yml", ".npmrc",
    "composer.json.bak", ".htpasswd", "server-status",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
]

STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"at\s+[\w.$]+\(.*\.java:\d+\)",
    r"Microsoft OLE DB Provider",
    r"Fatal error:.*on line \d+",
    r"Warning:.*in\s+/.*on line \d+",
    r"System\.Exception",
    r"django\.core\.exceptions",
    r"org\.springframework",
    r"at Object\.<anonymous>",
]

# Regex signatures for likely-sensitive values in response bodies.
# This is pattern matching, not entropy analysis -- expect some false
# positives, and extend this dict with signatures relevant to your
# target's stack.
SENSITIVE_PATTERNS = {
    "API Key": [
        r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
        r'x-api-key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
    ],
    "AWS Access Key": [r'AKIA[0-9A-Z]{16}'],
    "AWS Secret Key": [
        r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})',
    ],
    "JWT Token": [
        r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    ],
    "Bearer Token": [
        r'Bearer\s+[a-zA-Z0-9_\-\.=]{20,}',
        r'access[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})',
    ],
    "GitHub Token": [
        r'ghp_[A-Za-z0-9]{36}',
        r'gho_[A-Za-z0-9]{36}',
        r'github_pat_[A-Za-z0-9_]{82}',
    ],
    "Google API Key": [r'AIza[0-9A-Za-z\-_]{35}'],
    "Slack Token": [r'xox[baprs]-[A-Za-z0-9\-]{10,}'],
    "Stripe Key": [
        r'sk_live_[A-Za-z0-9]{24}',
        r'pk_live_[A-Za-z0-9]{24}',
    ],
    "Private Key": [r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'],
    "Database URL": [
        r'(mongodb|postgres|mysql|redis)://[^\s@]+:[^\s@]+@[^\s]+',
    ],
    "Email + Password": [
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["\']?\s*[:=]\s*["\']?[a-zA-Z0-9!@#$%^&*()]{6,}',
    ],
    "Internal IP": [
        r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
    ],
    "Admin Flag": [
        r'"admin"\s*:\s*true',
        r'"is_admin"\s*:\s*true',
        r'"role"\s*:\s*"admin"',
    ],
    "SSN Pattern": [r'\b\d{3}-\d{2}-\d{4}\b'],
    "Credit Card": [
        r'\b4[0-9]{12}(?:[0-9]{3})?\b',
        r'\b5[1-5][0-9]{14}\b',
    ],
}

RATE_LIMIT_STATUS_CODES = {429, 503}
