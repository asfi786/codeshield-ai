"""Google OAuth sign-in and stateless session handling.

Flow:
1. ``GET /api/v1/auth/google/login`` redirects (307) to Google with a random
   ``state`` value that is also stored in a short-lived HttpOnly cookie
   (CSRF protection, verified on callback).
2. ``GET /api/v1/auth/google/callback`` validates ``state``, exchanges the
   ``code`` for tokens, verifies the ID token via Google's tokeninfo
   endpoint, then mints our own signed session JWT.
3. The session JWT lives in an HttpOnly, Secure, SameSite=Lax cookie
   (``cs_session``); :func:`get_current_user` verifies it per request.

Stateless by design: nothing is stored server-side, so sign-in works on
serverless hosts (Vercel) where in-memory state does not survive.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import Request

from app.config import settings

logger = logging.getLogger(__name__)

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"

SESSION_COOKIE = "cs_session"
OAUTH_STATE_COOKIE = "cs_oauth_state"
SESSION_TTL_SECONDS = 30 * 24 * 3600  # 30 days

_session_secret: str | None = None


def _secret() -> str:
    """Return the session signing secret, generating an ephemeral one if unset."""
    global _session_secret
    if _session_secret is None:
        if settings.session_secret:
            _session_secret = settings.session_secret
        else:
            _session_secret = secrets.token_hex(32)
            logger.warning(
                "SESSION_SECRET is not set; using an ephemeral secret "
                "(sessions will not survive restarts)."
            )
    return _session_secret


def google_login_url(redirect_uri: str, state: str) -> str:
    """Build the Google OAuth 2.0 authorization URL."""
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    return GOOGLE_AUTH_URL + "?" + urlencode(params)


async def exchange_code(code: str, redirect_uri: str) -> dict[str, Any]:
    """Exchange an authorization code for Google tokens."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
        )
    if resp.status_code != 200:
        raise ValueError(f"Google token exchange failed (HTTP {resp.status_code}).")
    return resp.json()


async def verify_id_token(id_token: str) -> dict[str, Any]:
    """Verify a Google ID token and return its claims.

    Uses Google's tokeninfo endpoint (signature + audience + expiry are
    all checked server-side by Google).
    """
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(GOOGLE_TOKENINFO_URL, params={"id_token": id_token})
    if resp.status_code != 200:
        raise ValueError("Google ID token verification failed.")
    claims = resp.json()
    if claims.get("aud") != settings.google_client_id:
        raise ValueError("Google ID token audience mismatch.")
    return claims


def create_session_token(claims: dict[str, Any]) -> str:
    """Mint our own signed session JWT from verified Google claims."""
    now = int(time.time())
    payload = {
        "sub": claims.get("sub"),
        "name": claims.get("name"),
        "email": claims.get("email"),
        "picture": claims.get("picture"),
        "iat": now,
        "exp": now + SESSION_TTL_SECONDS,
    }
    return jwt.encode(payload, _secret(), algorithm="HS256")


def read_session_token(token: str) -> dict[str, Any] | None:
    """Verify a session JWT; return its payload or None."""
    try:
        return jwt.decode(token, _secret(), algorithms=["HS256"])
    except Exception:
        return None


def get_current_user(request: Request) -> dict[str, Any] | None:
    """Return the signed-in user from the session cookie, or None."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    return read_session_token(token)


# ---------------- Email/password credentials ----------------

_PBKDF2_ITERATIONS = 600_000  # OWASP recommendation for PBKDF2-HMAC-SHA256


def _pepper() -> bytes:
    """Server-side pepper mixed into every password hash (never stored in the DB)."""
    pepper = settings.password_pepper
    if not pepper:
        logger.warning(
            "PASSWORD_PEPPER is not set; password hashes rely on salt alone. "
            "Set a long random PASSWORD_PEPPER in production."
        )
        return b""
    return pepper.encode("utf-8")


def hash_password(password: str) -> str:
    """Hash a password with per-user salt + server pepper.

    Format: ``pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>``.
    """
    salt = secrets.token_bytes(32)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8") + _pepper(), salt, _PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time password check against a stored hash."""
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8") + _pepper(),
            bytes.fromhex(salt_hex),
            int(iters),
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def valid_email(email: str) -> bool:
    """Minimal sanity check for an email address."""
    email = email.strip()
    if "@" not in email or len(email) > 254:
        return False
    local, _, domain = email.partition("@")
    return bool(local) and "." in domain and len(domain) >= 3
