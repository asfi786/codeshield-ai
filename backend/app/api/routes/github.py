"""Repository URL validation route.

This route never raises a 500: unparseable URLs and missing repositories
return ``valid=False``; any other failure degrades to a best-effort
``valid=True`` so the UI can still let the user attempt an analysis.
"""

from fastapi import APIRouter, Query

from app.core.github_client import GitHubClient
from app.models.schemas import ValidateResponse
from app.utils.helpers import parse_github_url

router = APIRouter()


def _is_not_found(exc: Exception) -> bool:
    """Best-effort detection of a GitHub 404 across client error shapes."""
    response = getattr(exc, "response", None)
    if getattr(response, "status_code", None) == 404:
        return True
    text = str(exc).lower()
    return "404" in text and "not found" in text


@router.get("/validate", response_model=ValidateResponse)
async def validate_repo(
    url: str = Query(
        ..., min_length=3, max_length=500, description="GitHub repository URL"
    ),
) -> ValidateResponse:
    """Check that a GitHub repository URL parses and the repo exists."""
    parsed = parse_github_url(url)
    if parsed is None:
        return ValidateResponse(valid=False)
    owner, repo = parsed

    client = GitHubClient()
    try:
        try:
            info = await client.get_repo_info(owner, repo)
        except Exception as exc:
            if _is_not_found(exc):
                return ValidateResponse(valid=False)
            # Best effort: the URL parses and the repo *might* be private or
            # the API hiccuped — let the user try an analysis anyway.
            return ValidateResponse(valid=True, owner=owner, repo=repo, private=False)
    finally:
        await client.close()

    return ValidateResponse(
        valid=True,
        owner=owner,
        repo=repo,
        private=bool(info.get("private", False)),
    )
