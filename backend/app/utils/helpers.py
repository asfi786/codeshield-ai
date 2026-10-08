"""Pure helper functions for CodeShield AI.

No network access and no side effects: GitHub URL parsing, letter
grading, language detection and number formatting.
"""

import re
from urllib.parse import urlparse

#: Maps file extensions (lowercase, without dot) to language names.
EXTENSION_LANGUAGE_MAP: dict[str, str] = {
    "py": "Python", "pyw": "Python", "pyi": "Python",
    "js": "JavaScript", "mjs": "JavaScript", "cjs": "JavaScript", "jsx": "JavaScript",
    "ts": "TypeScript", "mts": "TypeScript", "cts": "TypeScript", "tsx": "TypeScript",
    "java": "Java", "go": "Go", "rs": "Rust", "rb": "Ruby",
    "php": "PHP", "cs": "C#",
    "cpp": "C++", "cc": "C++", "cxx": "C++", "hpp": "C++", "hh": "C++", "hxx": "C++",
    "c": "C", "h": "C",
    "swift": "Swift", "kt": "Kotlin", "kts": "Kotlin",
    "html": "HTML", "htm": "HTML",
    "css": "CSS", "scss": "SCSS", "sass": "SCSS", "less": "Less",
    "vue": "Vue", "svelte": "Svelte",
    "sql": "SQL", "sh": "Shell", "bash": "Shell", "zsh": "Shell", "fish": "Shell",
    "yml": "YAML", "yaml": "YAML", "json": "JSON", "xml": "XML",
    "toml": "TOML", "ini": "INI", "cfg": "INI", "env": "Env",
    "md": "Markdown", "rst": "reStructuredText",
    "tf": "Terraform", "dockerfile": "Docker",
    "r": "R", "jl": "Julia", "lua": "Lua", "pl": "Perl", "pm": "Perl",
    "scala": "Scala", "dart": "Dart", "ex": "Elixir", "exs": "Elixir",
    "hs": "Haskell", "ml": "OCaml", "mli": "OCaml",
    "groovy": "Groovy", "gradle": "Gradle",
}

#: Filenames without extensions mapped to languages (case-insensitive).
_SPECIAL_FILENAMES: dict[str, str] = {
    "dockerfile": "Docker",
    "makefile": "Makefile",
    "jenkinsfile": "Jenkins",
    "vagrantfile": "Vagrant",
    "gemfile": "Ruby",
    "rakefile": "Ruby",
}

_VALID_NAME = re.compile(r"[A-Za-z0-9_.\-]+")


def parse_github_url(url: str) -> tuple[str, str] | None:
    """Parse a GitHub repository reference into ``(owner, repo)``.

    Accepts ``https://github.com/owner/repo`` (with or without ``.git``
    suffix or trailing slash), ``www.github.com`` hosts, schemeless
    ``github.com/owner/repo`` and bare ``"owner/repo"`` strings. Query
    strings and fragments are ignored. Returns ``None`` when the input
    is not a valid GitHub repository reference.
    """
    if not isinstance(url, str):
        return None
    text = url.strip()
    if not text:
        return None
    text = text.split("#", 1)[0].split("?", 1)[0].strip().rstrip("/")
    if not text:
        return None

    if "://" not in text and text.count("/") == 1 and not text.startswith("/"):
        owner, _, repo = text.partition("/")
    else:
        candidate = text if "://" in text else f"https://{text}"
        try:
            parsed = urlparse(candidate)
        except ValueError:
            return None
        host = (parsed.hostname or "").lower()
        if host not in {"github.com", "www.github.com"}:
            return None
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) < 2:
            return None
        owner, repo = parts[0], parts[1]

    owner = owner.strip()
    repo = repo.strip()
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo:
        return None
    if not _VALID_NAME.fullmatch(owner) or not _VALID_NAME.fullmatch(repo):
        return None
    return owner, repo


def calculate_grade(score: float) -> str:
    """Map a 0-100 score to a letter grade (A+ down to F)."""
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def detect_language(filename: str) -> str:
    """Detect a programming language from a file path.

    Falls back to ``"Other"`` for unknown extensions and extensionless
    files that are not recognized special filenames.
    """
    base = filename.rsplit("/", 1)[-1]
    lowered = base.lower()
    if lowered in _SPECIAL_FILENAMES:
        return _SPECIAL_FILENAMES[lowered]
    if "." in base:
        ext = lowered.rsplit(".", 1)[-1]
        return EXTENSION_LANGUAGE_MAP.get(ext, "Other")
    return "Other"


def format_number(n: int | float) -> str:
    """Format a number compactly: 1500 -> '1.5K', 2000000 -> '2.0M'."""
    try:
        value = float(n)
    except (TypeError, ValueError):
        return str(n)
    sign = "-" if value < 0 else ""
    value = abs(value)
    if value >= 1_000_000:
        return f"{sign}{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{sign}{value / 1_000:.1f}K"
    if value.is_integer():
        return f"{sign}{int(value)}"
    return f"{sign}{value}"
