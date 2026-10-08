"""Async GitHub REST API client built on httpx.

All network I/O is async and nothing runs at import time. Failures are
surfaced as ``RuntimeError`` with human-readable messages so API routes
can translate them directly into error responses.
"""

import asyncio
import base64
import inspect
import os
from typing import Any, Callable
from urllib.parse import quote

import httpx

from ..config import settings

_API_BASE = "https://api.github.com"
_CONCURRENCY = 10


def _resolve_proxy() -> str | None:
    """Return an explicit egress proxy URL from the environment, if one is set."""
    return (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
        or None
    )


def _resolve_verify() -> str | bool:
    """Return a CA bundle path when the environment provides one.

    Sandboxed environments that MITM TLS (egress proxies) expose the proxy
    CA via SSL_CERT_FILE/REQUESTS_CA_BUNDLE. Without it, certificate
    verification fails. Falls back to True (system certs) elsewhere.
    """
    for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        path = os.environ.get(var)
        if path and os.path.exists(path):
            return path
    return True


class GitHubClient:
    """Thin async wrapper around the GitHub REST API.

    Example:
        async with GitHubClient(token="ghp_...") as gh:
            info = await gh.get_repo_info("octocat", "hello-world")
    """

    def __init__(self, token: str | None = None) -> None:
        resolved = token or settings.github_token
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "CodeShield-AI/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if resolved:
            headers["Authorization"] = f"Bearer {resolved}"
        # NOTE: trust_env=False is deliberate. httpx crashes while parsing
        # malformed ambient proxy vars (e.g. no_proxy containing "[::1]"),
        # which would 500 every GitHub-backed endpoint. We read the egress
        # proxy explicitly instead — deterministic in every environment
        # (proxied sandbox, Render, local laptop).
        self._client = httpx.AsyncClient(
            base_url=_API_BASE,
            headers=headers,
            timeout=settings.request_timeout,
            follow_redirects=True,
            trust_env=False,
            proxy=_resolve_proxy(),
            verify=_resolve_verify(),
        )

    async def __aenter__(self) -> "GitHubClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        await self._client.aclose()

    def _raise_for(self, resp: httpx.Response, context: str) -> None:
        """Raise a clean RuntimeError for failed GitHub API responses."""
        if resp.status_code < 400:
            return
        if resp.status_code == 404:
            raise RuntimeError(f"{context}: not found (404) — check the owner/repo name.")
        if resp.status_code == 401:
            raise RuntimeError(f"{context}: bad GitHub credentials (401).")
        if resp.status_code == 403:
            if resp.headers.get("X-RateLimit-Remaining") == "0":
                reset = resp.headers.get("X-RateLimit-Reset", "unknown")
                raise RuntimeError(
                    f"{context}: GitHub API rate limit exceeded "
                    f"(resets at unix timestamp {reset}). "
                    "Supply a github_token to raise the limit."
                )
            raise RuntimeError(f"{context}: access forbidden (403).")
        raise RuntimeError(f"{context}: GitHub API error {resp.status_code}.")

    async def get_repo_info(self, owner: str, repo: str) -> dict[str, Any]:
        """Fetch repository metadata (stars, default branch, description...)."""
        resp = await self._client.get(f"/repos/{owner}/{repo}")
        self._raise_for(resp, f"get_repo_info({owner}/{repo})")
        data = resp.json()
        return data if isinstance(data, dict) else {}

    async def get_file_tree(self, owner: str, repo: str, branch: str) -> list[dict[str, Any]]:
        """Fetch the full recursive file tree for a branch.

        Returns the raw tree entries (dicts with ``path``/``type`` keys).
        """
        resp = await self._client.get(
            f"/repos/{owner}/{repo}/git/trees/{quote(branch, safe='')}",
            params={"recursive": "1"},
        )
        self._raise_for(resp, f"get_file_tree({owner}/{repo}@{branch})")
        data = resp.json()
        tree = data.get("tree", []) if isinstance(data, dict) else []
        return [entry for entry in tree if isinstance(entry, dict)]

    async def get_file_content(
        self, owner: str, repo: str, path: str, ref: str
    ) -> str | None:
        """Fetch and base64-decode a single file's UTF-8 text.

        Returns ``None`` for missing files, non-200 responses, oversized
        blobs ("too large" errors), transport failures and non-UTF-8
        (binary) content.
        """
        try:
            resp = await self._client.get(
                f"/repos/{owner}/{repo}/contents/{quote(path, safe='/')}",
                params={"ref": ref},
            )
        except (httpx.TimeoutException, httpx.TransportError):
            return None
        if resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        if not isinstance(data, dict) or data.get("type") != "file":
            return None
        content = data.get("content")
        if not content or not isinstance(content, str):
            return None
        try:
            raw = base64.b64decode(content, validate=False)
        except Exception:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return None

    async def get_multiple_files(
        self,
        owner: str,
        repo: str,
        paths: list[str],
        ref: str,
        progress_cb: Callable[[int, int], Any] | None = None,
    ) -> dict[str, str]:
        """Fetch many files concurrently (max 10 in flight).

        Failures are skipped silently. ``progress_cb(done, total)`` is
        invoked after each file when provided; it may be sync or async.
        """
        semaphore = asyncio.Semaphore(_CONCURRENCY)
        total = len(paths)
        done = 0

        async def _fetch(path: str) -> tuple[str, str | None]:
            nonlocal done
            async with semaphore:
                text = await self.get_file_content(owner, repo, path, ref)
            done += 1
            if progress_cb is not None:
                outcome = progress_cb(done, total)
                if inspect.isawaitable(outcome):
                    await outcome
            return path, text

        pairs = await asyncio.gather(*(_fetch(p) for p in paths))
        return {path: text for path, text in pairs if text is not None}
