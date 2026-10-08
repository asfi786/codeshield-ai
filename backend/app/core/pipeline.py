"""End-to-end analysis pipeline for a GitHub repository.

:func:`run_analysis` is the single entry point used by the background job
runner. It fetches the repository through :class:`GitHubClient`, runs the
security scanner and architecture analyzer (both CPU-bound, so they run in
worker threads), generates the final report, and returns the complete
report dict. Progress is reported through an async
``progress_cb(progress, stage)`` callback. All failures propagate as
exceptions with human-readable messages.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from app.config import settings
from app.core.architecture_analyzer import analyze as arch_analyze
from app.core.github_client import GitHubClient
from app.core.report_generator import generate as report_generate
from app.core.security_scanner import scan as security_scan
from app.utils.helpers import parse_github_url

logger = logging.getLogger(__name__)

#: Directory names never descended into when selecting files to fetch.
SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "__pycache__",
        "vendor",
        "dist",
        "build",
        ".venv",
        "venv",
        ".next",
        "target",
        ".idea",
        ".vscode",
    }
)

#: File extensions treated as binary — never fetched for content scanning.
BINARY_EXTS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp4",
        ".mov",
        ".sqlite",
        ".db",
    }
)

#: Blobs larger than this are skipped (GitHub also refuses huge blobs).
MAX_FILE_BYTES = 512 * 1024

#: Extensions preferred when a repo exceeds the fetch cap (code first,
#: then configs/docs where secrets commonly hide).
SOURCE_EXTS = frozenset(
    {
        ".py", ".pyi",
        ".js", ".jsx", ".mjs", ".cjs",
        ".ts", ".tsx", ".mts", ".cts",
        ".java", ".kt", ".kts", ".scala", ".groovy",
        ".go", ".rs", ".rb", ".php", ".cs", ".swift",
        ".c", ".h", ".cc", ".hh", ".cpp", ".hpp", ".cxx",
        ".dart", ".lua", ".pl", ".pm", ".r", ".jl",
        ".ex", ".exs", ".erl", ".hs", ".ml", ".fs", ".vb",
        ".sh", ".bash", ".zsh", ".ps1", ".bat",
        ".sql", ".tf",
        ".html", ".htm", ".css", ".scss", ".sass", ".less",
        ".vue", ".svelte",
        ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
        ".conf", ".env", ".xml", ".properties",
        ".md", ".rst", ".txt",
    }
)

#: Extensionless filenames preferred when over the fetch cap.
SOURCE_FILENAMES = frozenset(
    {"dockerfile", "makefile", "jenkinsfile", "gemfile", "rakefile", "vagrantfile", ".env"}
)

#: Progress callback: called as progress_cb(progress 0-100, stage text);
#: may be a sync or an async callable.
ProgressCallback = Callable[[float, str], Any]


async def _notify(
    progress_cb: ProgressCallback | None, progress: float, stage: str
) -> None:
    """Invoke the progress callback, tolerating sync or async callables."""
    if progress_cb is None:
        return
    try:
        outcome = progress_cb(progress, stage)
        if asyncio.iscoroutine(outcome):
            await outcome
    except Exception:
        logger.debug("progress callback failed", exc_info=True)


async def run_analysis(
    job_id: str,
    repo_url: str,
    github_token: str | None,
    deep_scan: bool,
    progress_cb: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Run the full audit pipeline for a GitHub repository URL.

    Raises:
        ValueError: If ``repo_url`` is not a valid GitHub repository URL.
        RuntimeError: If the repository tree cannot be read.
    """
    started = time.monotonic()
    parsed = parse_github_url(repo_url)
    if parsed is None:
        raise ValueError("Invalid GitHub repository URL")
    owner, repo = parsed
    logger.info("job %s: analyzing %s/%s (deep_scan=%s)", job_id, owner, repo, deep_scan)

    client = GitHubClient(token=github_token or settings.github_token)
    try:
        await _notify(progress_cb, 5, "Validating repository")
        repo_info = await client.get_repo_info(owner, repo)

        await _notify(progress_cb, 15, "Fetching file tree")
        branch, tree = await _fetch_tree(client, owner, repo, repo_info)

        # All blob paths in the repo (used for repo-wide checks like
        # "missing .gitignore" / "sensitive files present").
        blob_paths = [
            entry["path"]
            for entry in tree
            if entry.get("type") == "blob" and entry.get("path")
        ]
        selected = _select_files(tree, deep_scan)

        await _notify(progress_cb, 30, f"Fetching file contents (0/{len(selected)})")

        async def _on_fetch(done: int, total: int) -> None:
            frac = (done / total) if total else 1.0
            await _notify(
                progress_cb,
                30 + frac * 40,
                f"Fetching file contents ({done}/{total})",
            )

        files = await client.get_multiple_files(
            owner, repo, selected, branch, progress_cb=_on_fetch
        )
        logger.info("job %s: fetched %d/%d files", job_id, len(files), len(selected))

        await _notify(progress_cb, 75, "Running security scan")
        security = await asyncio.to_thread(security_scan, files, blob_paths)

        await _notify(progress_cb, 88, "Analyzing architecture")
        architecture = await asyncio.to_thread(arch_analyze, blob_paths, files)

        await _notify(progress_cb, 95, "Generating report")
        scan_duration = time.monotonic() - started
        report = await asyncio.to_thread(
            report_generate,
            security,
            architecture,
            repo_info,
            {
                "files_analyzed": len(files),
                "scan_duration": round(scan_duration, 2),
            },
        )

        await _notify(progress_cb, 100, "Complete")
        logger.info("job %s: complete in %.1fs", job_id, scan_duration)
        return {
            "repo": {
                "owner": owner,
                "name": repo,
                "url": f"https://github.com/{owner}/{repo}",
                "description": repo_info.get("description"),
                "stars": repo_info.get("stargazers_count", 0),
                "forks": repo_info.get("forks_count", 0),
                "language": repo_info.get("language"),
                "default_branch": branch,
            },
            "security": security,
            "architecture": architecture,
            "overall_score": report.get("overall_score"),
            "grade": report.get("grade"),
            "summary": report.get("summary"),
            "recommendations": report.get("recommendations", []),
            "files_analyzed": len(files),
            "scan_duration_seconds": round(scan_duration, 2),
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }
    finally:
        await client.close()


async def _fetch_tree(
    client: GitHubClient, owner: str, repo: str, repo_info: dict[str, Any]
) -> tuple[str, list[dict[str, Any]]]:
    """Fetch the recursive tree, trying default branch, then main, then master."""
    candidates: list[str] = []
    for branch in (repo_info.get("default_branch") or "main", "main", "master"):
        if branch and branch not in candidates:
            candidates.append(branch)
    errors: list[str] = []
    for branch in candidates:
        try:
            tree = await client.get_file_tree(owner, repo, branch)
            logger.info(
                "fetched tree for %s/%s@%s (%d entries)", owner, repo, branch, len(tree)
            )
            return branch, tree
        except Exception as exc:
            errors.append(f"{branch}: {exc}")
            logger.warning("tree fetch failed for %s@%s: %s", repo, branch, exc)
    raise RuntimeError(
        "Could not read repository tree (tried "
        + ", ".join(candidates)
        + "). "
        + "; ".join(errors)
    )


def _select_files(tree: list[dict[str, Any]], deep_scan: bool) -> list[str]:
    """Choose which blob paths to download.

    Skips vendored directories, binary extensions and oversized blobs,
    then caps the count (``max_files`` / ``max_files_deep``), preferring
    source, config and documentation files when over the cap.
    """
    kept: list[str] = []
    for entry in tree:
        if entry.get("type") != "blob":
            continue
        path = entry.get("path")
        if not path:
            continue
        if any(part in SKIP_DIRS for part in path.split("/")):
            continue
        if Path(path).suffix.lower() in BINARY_EXTS:
            continue
        size = entry.get("size") or 0
        if isinstance(size, (int, float)) and size > MAX_FILE_BYTES:
            continue
        kept.append(path)

    cap = settings.max_files_deep if deep_scan else settings.max_files
    if len(kept) > cap:
        kept.sort(key=_preference_key)
        kept = kept[:cap]
        logger.info("capped file selection to %d files (deep_scan=%s)", cap, deep_scan)
    return kept


def _preference_key(path: str) -> tuple[int, str]:
    """Sort key: preferred source/config/doc files first, then the rest."""
    name = path.rsplit("/", 1)[-1].lower()
    if Path(name).suffix in SOURCE_EXTS or name in SOURCE_FILENAMES:
        return (0, path)
    return (1, path)
