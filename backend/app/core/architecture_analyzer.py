"""Architecture analyzer for CodeShield AI.

Computes repository metrics (file counts, lines of code, language
breakdown, framework detection, depth) and evaluates 7 best-practice
checks into a 0-100 architecture score.

Pure logic: no network access, no side effects.
"""

from ..utils.helpers import EXTENSION_LANGUAGE_MAP, detect_language

#: Re-exported so callers have one canonical extension -> language map.
LANGUAGE_MAP: dict[str, str] = EXTENSION_LANGUAGE_MAP

#: 17 frameworks with detection indicators. Each indicator may specify:
#:   "file"     - exact repo-relative path must exist
#:   "basename" - any path with this basename must exist
#:   "suffix"   - any path ending with this suffix must exist
#:   "snippet"  - candidate file content must contain this string
#: An indicator with only "snippet" is searched across all analyzed files.
FRAMEWORKS: list[dict] = [
    {"name": "React", "indicators": [{"basename": "package.json", "snippet": '"react"'}]},
    {
        "name": "Next.js",
        "indicators": [
            {"basename": "next.config.js"},
            {"basename": "next.config.mjs"},
            {"basename": "next.config.cjs"},
            {"basename": "next.config.ts"},
        ],
    },
    {
        "name": "Vue",
        "indicators": [
            {"basename": "package.json", "snippet": '"vue"'},
            {"basename": "vue.config.js"},
        ],
    },
    {
        "name": "Angular",
        "indicators": [
            {"basename": "angular.json"},
            {"basename": "package.json", "snippet": "@angular/core"},
        ],
    },
    {
        "name": "Svelte",
        "indicators": [
            {"basename": "package.json", "snippet": '"svelte"'},
            {"basename": "svelte.config.js"},
        ],
    },
    {
        "name": "Nuxt.js",
        "indicators": [
            {"basename": "nuxt.config.js"},
            {"basename": "nuxt.config.ts"},
        ],
    },
    {
        "name": "Django",
        "indicators": [
            {"basename": "manage.py"},
            {"basename": "settings.py", "snippet": "django"},
        ],
    },
    {
        "name": "Flask",
        "indicators": [
            {"basename": "app.py", "snippet": "flask"},
            {"snippet": "from flask import"},
        ],
    },
    {
        "name": "FastAPI",
        "indicators": [
            {"snippet": "from fastapi import"},
            {"snippet": "import fastapi"},
        ],
    },
    {"name": "Express", "indicators": [{"basename": "package.json", "snippet": '"express"'}]},
    {
        "name": "NestJS",
        "indicators": [{"basename": "package.json", "snippet": "@nestjs/core"}],
    },
    {
        "name": "Spring Boot",
        "indicators": [{"basename": "pom.xml", "snippet": "spring-boot"}],
    },
    {
        "name": "Laravel",
        "indicators": [
            {"basename": "artisan"},
            {"basename": "composer.json", "snippet": "laravel/framework"},
        ],
    },
    {
        "name": "Ruby on Rails",
        "indicators": [{"basename": "Gemfile", "snippet": "rails"}],
    },
    {"name": ".NET", "indicators": [{"suffix": ".csproj"}]},
    {
        "name": "Flutter",
        "indicators": [{"basename": "pubspec.yaml", "snippet": "flutter"}],
    },
    {
        "name": "React Native",
        "indicators": [{"basename": "package.json", "snippet": "react-native"}],
    },
]

_BASE_SCORE = 50
_MAX_SCORE = 100


def _detect_frameworks(all_paths: list[str], files: dict[str, str]) -> list[str]:
    """Return names of frameworks whose indicators match the repo."""
    path_set = set(all_paths)
    detected: list[str] = []
    for framework in FRAMEWORKS:
        hit = False
        for indicator in framework["indicators"]:
            candidates: list[str] = []
            if "file" in indicator:
                if indicator["file"] in path_set:
                    candidates = [indicator["file"]]
            elif "basename" in indicator:
                candidates = [
                    p for p in all_paths
                    if p.rsplit("/", 1)[-1] == indicator["basename"]
                ]
            elif "suffix" in indicator:
                candidates = [p for p in all_paths if p.endswith(indicator["suffix"])]
            elif "snippet" in indicator:
                candidates = list(files.keys())
            if not candidates:
                continue
            snippet = indicator.get("snippet")
            if snippet is None:
                hit = True
                break
            for candidate in candidates:
                if candidate in files and snippet in files[candidate]:
                    hit = True
                    break
            if hit:
                break
        if hit:
            detected.append(framework["name"])
    return detected


def _best_practices(all_paths: list[str]) -> list[dict]:
    """Evaluate the 7 best-practice checks; each returns check/passed/bonus."""
    lower_basenames = {p.rsplit("/", 1)[-1].lower() for p in all_paths}
    dir_parts: set[str] = set()
    for path in all_paths:
        parts = path.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dir_parts.add("/".join(parts[:i]).lower())
    leaf_dirs = {d.rsplit("/", 1)[-1] for d in dir_parts}

    has_ci = (
        ".github/workflows" in dir_parts
        or ".circleci" in dir_parts
        or any(
            name in lower_basenames
            for name in (".gitlab-ci.yml", "jenkinsfile", ".travis.yml", "azure-pipelines.yml")
        )
    )

    return [
        {
            "check": "README.md",
            "passed": any(b == "readme.md" or b == "readme" for b in lower_basenames),
            "bonus": 10,
        },
        {
            "check": "LICENSE file",
            "passed": any(b.startswith("license") for b in lower_basenames),
            "bonus": 5,
        },
        {
            "check": "Tests directory",
            "passed": bool(leaf_dirs & {"tests", "test", "__tests__", "spec"}),
            "bonus": 10,
        },
        {"check": "CI/CD pipeline", "passed": has_ci, "bonus": 8},
        {
            "check": "Docker support",
            "passed": "dockerfile" in lower_basenames
            or "docker-compose.yml" in lower_basenames
            or "docker-compose.yaml" in lower_basenames,
            "bonus": 5,
        },
        {
            "check": "Documentation directory",
            "passed": bool(leaf_dirs & {"docs", "documentation"}),
            "bonus": 5,
        },
        {"check": ".gitignore", "passed": ".gitignore" in lower_basenames, "bonus": 3},
    ]


def analyze(all_paths: list[str], files: dict[str, str]) -> dict:
    """Analyze repository structure.

    Args:
        all_paths: repo-relative blob paths (files only).
        files: mapping of path -> decoded UTF-8 content for analyzed files.

    Returns:
        dict with ``score`` (0-100), ``metrics`` and ``best_practices``.
    """
    # Directory set (all intermediate prefixes, so nesting counts).
    dirs: set[str] = set()
    for path in all_paths:
        parts = path.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))

    # Language breakdown, sorted by lines of code descending.
    lang_files: dict[str, int] = {}
    lang_loc: dict[str, int] = {}
    for path in all_paths:
        lang = detect_language(path)
        lang_files[lang] = lang_files.get(lang, 0) + 1
        if path in files:
            lang_loc[lang] = lang_loc.get(lang, 0) + len(files[path].splitlines())
    languages = {
        lang: {"files": lang_files[lang], "loc": lang_loc.get(lang, 0)}
        for lang in sorted(lang_files, key=lambda l: lang_loc.get(l, 0), reverse=True)
    }

    total_loc = sum(len(content.splitlines()) for content in files.values())
    avg_file_size = round(sum(len(c) for c in files.values()) / len(files), 1) if files else 0.0

    metrics = {
        "total_files": len(all_paths),
        "total_dirs": len(dirs),
        "total_loc": total_loc,
        "languages": languages,
        "frameworks": _detect_frameworks(all_paths, files),
        "avg_file_size": avg_file_size,
        "max_depth": max((p.count("/") for p in all_paths), default=0),
    }

    practices = _best_practices(all_paths)
    score = min(_MAX_SCORE, _BASE_SCORE + sum(p["bonus"] for p in practices if p["passed"]))

    return {"score": score, "metrics": metrics, "best_practices": practices}
