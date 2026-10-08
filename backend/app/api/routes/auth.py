"""User authentication routes (Google OAuth sign-in).

- ``GET  /api/v1/auth/google/login``    -> 307 redirect to Google.
- ``GET  /api/v1/auth/google/callback`` -> validates state, exchanges the
  code, verifies the ID token, sets the session cookie, redirects to ``/``.
- ``GET  /api/v1/auth/me``              -> current signed-in user or 401.
- ``POST /api/v1/auth/logout``          -> clears the session cookie.

The OAuth redirect URI is derived from the incoming request host, so the
same code works on localhost and on production. Register exactly this URI
in the Google Cloud Console OAuth client:
``<origin>/api/v1/auth/google/callback``.
"""

import logging
import secrets

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from app.config import settings
from app.core import auth as auth_core
from app.core.users import UserExistsError, UserStoreUnavailableError, get_store
from app.models.schemas import LoginRequest, RegisterRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

CALLBACK_PATH = "/api/v1/auth/google/callback"


def _public_user(record: dict) -> dict:
    return {
        "name": record.get("name"),
        "email": record.get("email"),
        "picture": record.get("picture"),
    }


def _set_session_cookie(response, request: Request, user: dict) -> None:
    token = auth_core.create_session_token(
        {
            "sub": user.get("email"),
            "name": user.get("name"),
            "email": user.get("email"),
            "picture": user.get("picture"),
        }
    )
    response.set_cookie(
        auth_core.SESSION_COOKIE,
        token,
        max_age=auth_core.SESSION_TTL_SECONDS,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="lax",
        path="/",
    )


@router.post("/register", status_code=201)
async def register(payload: RegisterRequest, request: Request):
    """Create a new email/password account and sign the user in."""
    email = payload.email.strip().lower()
    if not auth_core.valid_email(email):
        return JSONResponse(status_code=400, content={"detail": "Invalid email address."})
    try:
        store = get_store()
        record = await store.create_user(
            payload.name, email, auth_core.hash_password(payload.password)
        )
    except UserExistsError:
        return JSONResponse(
            status_code=409, content={"detail": "An account with this email already exists."}
        )
    except UserStoreUnavailableError:
        return JSONResponse(
            status_code=503, content={"detail": "Sign-up is temporarily unavailable."}
        )
    response = JSONResponse(status_code=201, content={"user": _public_user(record)})
    _set_session_cookie(response, request, record)
    logger.info("user registered: %s", email)
    return response


@router.post("/login")
async def login(payload: LoginRequest, request: Request):
    """Sign in with email and password."""
    email = payload.email.strip().lower()
    try:
        record = await get_store().get_user(email)
    except UserStoreUnavailableError:
        return JSONResponse(
            status_code=503, content={"detail": "Sign-in is temporarily unavailable."}
        )
    if (
        not record
        or record.get("provider") != "password"
        or not auth_core.verify_password(payload.password, record.get("pw_hash", ""))
    ):
        return JSONResponse(
            status_code=401, content={"detail": "Invalid email or password."}
        )
    response = JSONResponse(content={"user": _public_user(record)})
    _set_session_cookie(response, request, record)
    return response


def _redirect_uri(request: Request) -> str:
    return str(request.base_url).rstrip("/") + CALLBACK_PATH


def _cookie_secure(request: Request) -> bool:
    return request.url.scheme == "https"


def _oauth_configured() -> bool:
    return bool(settings.google_client_id and settings.google_client_secret)


@router.get("/google/login", include_in_schema=False)
async def google_login(request: Request):
    """Start Google sign-in: redirect the browser to Google's consent page."""
    if not _oauth_configured():
        return JSONResponse(
            status_code=400,
            content={"detail": "Google sign-in is not configured on this server."},
        )
    state = secrets.token_urlsafe(32)
    url = auth_core.google_login_url(_redirect_uri(request), state)
    response = RedirectResponse(url, status_code=307)
    response.set_cookie(
        auth_core.OAUTH_STATE_COOKIE,
        state,
        max_age=600,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="lax",
        path="/",
    )
    return response


@router.get("/google/callback", include_in_schema=False)
async def google_callback(request: Request):
    """Handle Google's redirect: verify state, finish sign-in, set session."""
    params = request.query_params
    if params.get("error"):
        logger.info("google oauth error: %s", params.get("error"))
        return RedirectResponse("/?auth=error", status_code=303)
    code = params.get("code")
    state = params.get("state")
    expected_state = request.cookies.get(auth_core.OAUTH_STATE_COOKIE)
    if not code or not state or not expected_state or state != expected_state:
        return RedirectResponse("/?auth=error", status_code=303)

    redirect_uri = _redirect_uri(request)
    try:
        tokens = await auth_core.exchange_code(code, redirect_uri)
        claims = await auth_core.verify_id_token(tokens["id_token"])
    except Exception as exc:
        logger.warning("google sign-in failed: %s", exc)
        return RedirectResponse("/?auth=error", status_code=303)

    session = auth_core.create_session_token(claims)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        auth_core.SESSION_COOKIE,
        session,
        max_age=auth_core.SESSION_TTL_SECONDS,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="lax",
        path="/",
    )
    response.delete_cookie(auth_core.OAUTH_STATE_COOKIE, path="/")
    logger.info("user signed in: %s", claims.get("email"))
    return response


@router.get("/me")
async def me(request: Request):
    """Return the currently signed-in user, or 401 when signed out."""
    user = auth_core.get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Not signed in."})
    return {
        "user": {
            "name": user.get("name"),
            "email": user.get("email"),
            "picture": user.get("picture"),
        }
    }


@router.post("/logout")
async def logout():
    """Sign out: clear the session cookie."""
    response = JSONResponse({"ok": True})
    response.delete_cookie(auth_core.SESSION_COOKIE, path="/")
    return response
