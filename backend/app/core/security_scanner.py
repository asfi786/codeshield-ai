"""Rule-based security scanner for CodeShield AI.

Scans file contents line-by-line for hardcoded secrets (9 patterns) and
common vulnerability patterns (9 patterns), checks for sensitive files
committed to the repo, and produces a 0-100 security score.

Pure logic: no network access, no side effects. Every regex is compiled
at import time so misconfigurations fail fast.
"""

import re

#: Severity ordering used for sorting findings (lower = more severe).
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

#: Score penalty subtracted per finding, per severity.
_SEVERITY_PENALTY = {
    "critical": 20.0,
    "high": 12.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.5,
}

#: Max lines scanned per file (bounds CPU on huge generated files).
_MAX_LINES_PER_FILE = 2000

#: Values that look like placeholders rather than real passwords.
_PASSWORD_PLACEHOLDERS = {"xxx", "***", "password", "changeme", "example"}

#: IP addresses that are not real hardcoded targets.
_IGNORED_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}

SECRET_PATTERNS: list[dict] = [
    {
        "id": "aws-access-key",
        "title": "AWS access key ID exposed",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "critical",
        "category": "Secrets",
        "cwe": "CWE-798",
        "description": "Hardcoded AWS access key ID. Rotate the key and move it to a secrets manager.",
    },
    {
        "id": "aws-secret-key",
        "title": "AWS secret access key exposed",
        "pattern": r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}",
        "severity": "critical",
        "category": "Secrets",
        "cwe": "CWE-798",
        "description": "Hardcoded AWS secret access key. Rotate it immediately and use IAM roles or a secrets manager.",
    },
    {
        "id": "github-token",
        "title": "GitHub token exposed",
        "pattern": r"(ghp_|ghs_|ghu_|ghr_)[A-Za-z0-9_]{20,}",
        "severity": "critical",
        "category": "Secrets",
        "cwe": "CWE-798",
        "description": "Hardcoded GitHub personal access token. Revoke it and store tokens in CI secrets.",
    },
    {
        "id": "private-key",
        "title": "Private key block exposed",
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "critical",
        "category": "Secrets",
        "cwe": "CWE-321",
        "description": "Private cryptographic key committed to the repository. Rotate the key pair and remove it from history.",
    },
    {
        "id": "generic-api-key",
        "title": "Generic API key exposed",
        "pattern": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
        "severity": "high",
        "category": "Secrets",
        "cwe": "CWE-798",
        "description": "Hardcoded API key. Move it to environment variables or a secrets manager.",
    },
    {
        "id": "hardcoded-password",
        "title": "Hardcoded password",
        "pattern": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,})['\"]",
        "severity": "high",
        "category": "Secrets",
        "cwe": "CWE-259",
        "description": "Hardcoded password in source. Use environment variables or a secrets manager instead.",
    },
    {
        "id": "jwt-token",
        "title": "Hardcoded JWT token",
        "pattern": r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "severity": "high",
        "category": "Secrets",
        "cwe": "CWE-798",
        "description": "Hardcoded JSON Web Token. Tokens must never be committed; issue them at runtime.",
    },
    {
        "id": "db-connection-string",
        "title": "Database connection string exposed",
        "pattern": r"(?i)(mongodb(\+srv)?|postgres(ql)?|mysql|redis)://[^\s'\"]+",
        "severity": "high",
        "category": "Secrets",
        "cwe": "CWE-798",
        "description": "Database connection string with embedded credentials. Externalize it to configuration.",
    },
    {
        "id": "slack-webhook",
        "title": "Slack webhook URL exposed",
        "pattern": r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+",
        "severity": "medium",
        "category": "Secrets",
        "cwe": "CWE-798",
        "description": "Slack incoming-webhook URL committed. Anyone with it can post to the channel; rotate it.",
    },
]

VULN_PATTERNS: list[dict] = [
    {
        "id": "sql-injection",
        "title": "Possible SQL injection",
        "pattern": r"(?i)\.(execute|executemany)\s*\(\s*f['\"]|\.(execute|executemany)\s*\([^)]*['\"]\s*%",
        "severity": "high",
        "category": "Injection",
        "cwe": "CWE-89",
        "description": "SQL query built with string interpolation. Use parameterized queries instead.",
    },
    {
        "id": "command-injection",
        "title": "Command injection risk (shell=True)",
        "pattern": r"(?i)shell\s*=\s*True",
        "severity": "high",
        "category": "Injection",
        "cwe": "CWE-78",
        "description": "Subprocess invoked with shell=True. Avoid the shell or sanitize arguments strictly.",
    },
    {
        "id": "eval-exec",
        "title": "Dangerous eval()/exec() usage",
        "pattern": r"(?<![A-Za-z0-9_])(eval|exec)\s*\(",
        "severity": "high",
        "category": "Code Injection",
        "cwe": "CWE-95",
        "description": "eval()/exec() executes arbitrary code. Replace with safe parsing or an allowlist.",
        "skip_comments": True,
    },
    {
        "id": "pickle-deserialization",
        "title": "Insecure deserialization (pickle)",
        "pattern": r"pickle\.loads?\(",
        "severity": "high",
        "category": "Deserialization",
        "cwe": "CWE-502",
        "description": "pickle deserialization can execute arbitrary code on untrusted data. Use a safe format like JSON.",
    },
    {
        "id": "yaml-load",
        "title": "Unsafe yaml.load() without SafeLoader",
        "pattern": r"yaml\.load\(",
        "severity": "high",
        "category": "Deserialization",
        "cwe": "CWE-502",
        "description": "yaml.load() without SafeLoader can execute arbitrary code. Use yaml.safe_load().",
    },
    {
        "id": "ssl-verify-disabled",
        "title": "TLS certificate verification disabled",
        "pattern": r"verify\s*=\s*False",
        "severity": "high",
        "category": "Cryptography",
        "cwe": "CWE-295",
        "description": "Disabling TLS verification enables man-in-the-middle attacks. Keep verification enabled.",
    },
    {
        "id": "xss-innerhtml",
        "title": "Potential XSS via innerHTML",
        "pattern": r"\.innerHTML\s*=",
        "severity": "medium",
        "category": "XSS",
        "cwe": "CWE-79",
        "description": "Assigning to innerHTML with untrusted data enables XSS. Use textContent or sanitize first.",
    },
    {
        "id": "debug-mode",
        "title": "Debug mode enabled",
        "pattern": r"(?i)(app\.run\(.*debug\s*=\s*True|DEBUG\s*=\s*True)",
        "severity": "medium",
        "category": "Configuration",
        "cwe": "CWE-489",
        "description": "Debug mode leaks stack traces and can allow code execution. Disable it in production.",
    },
    {
        "id": "insecure-random",
        "title": "Insecure random number generator",
        "pattern": r"random\.(random|randint|choice)",
        "severity": "low",
        "category": "Cryptography",
        "cwe": "CWE-338",
        "description": "The random module is not cryptographically secure. Use secrets for tokens or keys.",
    },
    {
        "id": "hardcoded-ip",
        "title": "Hardcoded IP address",
        "pattern": r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
        "severity": "low",
        "category": "Configuration",
        "cwe": "CWE-547",
        "description": "Hardcoded IP address. Prefer hostnames or configuration values.",
    },
]

#: Sensitive files that must never be committed: match rules plus finding metadata.
_SENSITIVE_FILES: list[dict] = [
    {
        "id": "sensitive-env-file",
        "title": "Environment file (.env) committed",
        "severity": "critical",
        "category": "Secrets",
        "cwe": "CWE-798",
        "description": ".env files usually hold secrets and must not be committed. Delete it and rotate exposed values.",
        "basename": ".env",
    },
    {
        "id": "sensitive-ssh-key",
        "title": "Private SSH key committed",
        "severity": "critical",
        "category": "Secrets",
        "cwe": "CWE-321",
        "description": "Private SSH key found in the repo. Generate a new key pair and remove this one from history.",
        "basename": "id_rsa",
    },
    {
        "id": "sensitive-ssh-key",
        "title": "Private SSH key committed",
        "severity": "critical",
        "category": "Secrets",
        "cwe": "CWE-321",
        "description": "Private SSH key found in the repo. Generate a new key pair and remove this one from history.",
        "basename": "id_dsa",
    },
    {
        "id": "sensitive-pem",
        "title": "PEM certificate/key file committed",
        "severity": "critical",
        "category": "Secrets",
        "cwe": "CWE-321",
        "description": ".pem files often contain private keys. Remove the file and rotate the credentials.",
        "suffix": ".pem",
    },
    {
        "id": "sensitive-credentials-json",
        "title": "Credentials file committed",
        "severity": "high",
        "category": "Secrets",
        "cwe": "CWE-798",
        "description": "credentials.json typically holds secrets. Remove it and rotate exposed values.",
        "basename": "credentials.json",
    },
    {
        "id": "sensitive-secrets-json",
        "title": "Secrets file committed",
        "severity": "high",
        "category": "Secrets",
        "cwe": "CWE-798",
        "description": "secrets.json typically holds secrets. Remove it and rotate exposed values.",
        "basename": "secrets.json",
    },
    {
        "id": "sensitive-aws-credentials",
        "title": "AWS credentials file committed",
        "severity": "critical",
        "category": "Secrets",
        "cwe": "CWE-798",
        "description": ".aws/credentials holds AWS keys in plaintext. Delete it and rotate the keys.",
        "suffix": ".aws/credentials",
    },
]

# Pre-compile every pattern at import time (fails fast on bad regex).
_COMPILED_SECRETS: list[tuple[dict, re.Pattern]] = [
    (p, re.compile(p["pattern"])) for p in SECRET_PATTERNS
]
_COMPILED_VULNS: list[tuple[dict, re.Pattern]] = [
    (p, re.compile(p["pattern"])) for p in VULN_PATTERNS
]


def _in_comment(line: str, match_start: int) -> bool:
    """Heuristic: is the match positioned after a `#` or `//` comment marker?"""
    prefix = line[:match_start]
    return re.search(r"(^|\s)(#|//)", prefix) is not None


def _looks_like_placeholder(value: str) -> bool:
    """Check whether a captured password value is an obvious placeholder."""
    normalized = value.strip().lower().strip("*").strip()
    return normalized in _PASSWORD_PLACEHOLDERS


def _valid_ip(candidate: str) -> bool:
    """Validate a dotted-quad candidate (all octets 0-255, not ignored)."""
    if candidate in _IGNORED_IPS:
        return False
    try:
        return all(0 <= int(octet) <= 255 for octet in candidate.split("."))
    except ValueError:
        return False


def scan(files: dict[str, str], all_paths: list[str]) -> dict:
    """Scan repository files for secrets and vulnerability patterns.

    Args:
        files: mapping of repo-relative path -> decoded UTF-8 file content.
        all_paths: every blob path in the repo (used for sensitive-file
            and missing-file checks).

    Returns:
        dict with ``score`` (0-100), ``findings`` (sorted critical->info)
        and ``summary`` (per-severity counts plus total).
    """
    findings: list[dict] = []
    seen: set[tuple[str, str, int]] = set()

    def _add(
        pattern_id: str,
        title: str,
        description: str,
        severity: str,
        category: str,
        cwe: str,
        path: str,
        line: int,
        snippet: str,
    ) -> None:
        key = (pattern_id, path, line)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            {
                "id": pattern_id,
                "title": title,
                "description": description,
                "severity": severity,
                "category": category,
                "cwe": cwe,
                "file": path,
                "line": line,
                "snippet": snippet[:120],
            }
        )

    # 1) Content patterns, line by line (bounded per file).
    for path, content in files.items():
        for lineno, line in enumerate(content.splitlines()[:_MAX_LINES_PER_FILE], start=1):
            stripped = line.strip()
            if not stripped:
                continue
            snippet = stripped[:120]

            for pattern, regex in _COMPILED_SECRETS:
                for match in regex.finditer(line):
                    if pattern["id"] == "hardcoded-password":
                        value = match.group(2) if match.lastindex and match.lastindex >= 2 else ""
                        if _looks_like_placeholder(value):
                            continue
                    _add(
                        pattern["id"], pattern["title"], pattern["description"],
                        pattern["severity"], pattern["category"], pattern["cwe"],
                        path, lineno, snippet,
                    )

            for pattern, regex in _COMPILED_VULNS:
                for match in regex.finditer(line):
                    if pattern.get("skip_comments") and _in_comment(line, match.start()):
                        continue
                    if pattern["id"] == "yaml-load" and "safeloader" in line.lower():
                        continue
                    if pattern["id"] == "hardcoded-ip" and not _valid_ip(match.group(0)):
                        continue
                    _add(
                        pattern["id"], pattern["title"], pattern["description"],
                        pattern["severity"], pattern["category"], pattern["cwe"],
                        path, lineno, snippet,
                    )

    # 2) Sensitive files committed anywhere in the repo.
    for path in all_paths:
        basename = path.rsplit("/", 1)[-1]
        for rule in _SENSITIVE_FILES:
            matched = False
            if "basename" in rule and basename == rule["basename"]:
                matched = True
            elif "suffix" in rule and path.endswith(rule["suffix"]):
                matched = True
            if matched:
                _add(
                    rule["id"], rule["title"], rule["description"],
                    rule["severity"], rule["category"], rule["cwe"],
                    path, 0, basename,
                )

    # 3) Missing hygiene files.
    basenames = {p.rsplit("/", 1)[-1].lower() for p in all_paths}
    if ".gitignore" not in basenames:
        _add(
            "missing-gitignore", "Missing .gitignore", "No .gitignore file — high risk of committing secrets or build artifacts.",
            "info", "Configuration", "", "", 0, "",
        )
    if "security.md" not in basenames:
        _add(
            "missing-security-md", "Missing SECURITY.md", "No SECURITY.md — contributors have no documented way to report vulnerabilities.",
            "info", "Configuration", "", "", 0, "",
        )

    # 4) Score and sort.
    score = 100.0
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = finding["severity"]
        score -= _SEVERITY_PENALTY.get(severity, 0.0)
        counts[severity] = counts.get(severity, 0) + 1
    score = round(max(0.0, min(100.0, score)), 1)
    findings.sort(
        key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9), f["file"], f["line"])
    )

    return {
        "score": score,
        "findings": findings,
        "summary": {**counts, "total": len(findings)},
    }
