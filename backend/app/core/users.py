"""User account storage on Vercel Blob (raw REST API).

Each account is a single private JSON blob at
``users/{sha256(lowercase_email)}.json``. One file per user means
registrations never race each other, and lookups are direct (no listing).

The blob holds ``{name, email, pw_hash, created_at, provider}``. Passwords
are stored as peppered PBKDF2 hashes (see :mod:`app.core.auth`); the
pepper lives only in the server's environment, never in the blob.

We call the Blob REST API directly with httpx instead of the SDK because
the SDK cannot derive the store URL from our token/store-id format.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

USERS_PREFIX = "users/"
BLOB_API_URL = "https://vercel.com/api/blob"
_TIMEOUT = 15.0


def blob_path_for(email: str) -> str:
    """Deterministic private blob path for an email address."""
    digest = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
    return f"{USERS_PREFIX}{digest}.json"


class UserExistsError(Exception):
    """Raised when registering an email that already has an account."""


class UserStoreUnavailableError(Exception):
    """Raised when the blob store cannot be reached or configured."""


def _token() -> str:
    token = os.environ.get("BLOB_READ_WRITE_TOKEN")
    if not token:
        raise UserStoreUnavailableError(
            "Blob store is not configured (missing BLOB_READ_WRITE_TOKEN)."
        )
    return token


def _store_id() -> str:
    store_id = os.environ.get("BLOB_STORE_ID")
    if not store_id:
        raise UserStoreUnavailableError(
            "Blob store is not configured (missing BLOB_STORE_ID)."
        )
    return store_id


def _download_url(pathname: str) -> str:
    return f"https://{_store_id()}.private.blob.vercel-storage.com/{pathname}"


async def _blob_get(pathname: str) -> dict[str, Any] | None:
    """Download and parse a user blob; None when it does not exist."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                _download_url(pathname),
                headers={"Authorization": f"Bearer {_token()}"},
            )
    except Exception as exc:
        raise UserStoreUnavailableError(f"User store request failed: {exc}") from exc
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise UserStoreUnavailableError(
            f"User store returned HTTP {resp.status_code}."
        )
    try:
        return json.loads(resp.text)
    except Exception:
        logger.warning("corrupt user blob at %s", pathname)
        return None


async def _blob_put(pathname: str, record: dict[str, Any]) -> None:
    """Upload a user blob; raises UserExistsError if the path is taken."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.put(
                BLOB_API_URL,
                params={"pathname": pathname},
                content=json.dumps(record).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {_token()}",
                    "x-vercel-blob-access": "private",
                    "x-content-type": "application/json",
                    "x-allow-overwrite": "0",
                },
            )
    except Exception as exc:
        raise UserStoreUnavailableError(f"User store request failed: {exc}") from exc
    if resp.status_code in (200, 201):
        return
    # 409/400 with allow-overwrite=0 means the blob already exists.
    raise UserExistsError(pathname)


class UserStore:
    """Async user store backed by Vercel Blob."""

    async def get_user(self, email: str) -> dict[str, Any] | None:
        """Return the user record for an email, or None."""
        return await _blob_get(blob_path_for(email))

    async def create_user(
        self, name: str, email: str, pw_hash: str, provider: str = "password"
    ) -> dict[str, Any]:
        """Create a user; raises UserExistsError if the email is taken."""
        email_norm = email.strip().lower()
        if await self.get_user(email_norm) is not None:
            raise UserExistsError(email_norm)
        record = {
            "name": name.strip(),
            "email": email_norm,
            "pw_hash": pw_hash,
            "provider": provider,
            "created_at": int(time.time()),
        }
        try:
            await _blob_put(blob_path_for(email_norm), record)
        except UserExistsError:
            # Lost the race: the blob appeared between our check and the put.
            raise UserExistsError(email_norm)
        return record


def get_store() -> UserStore:
    """Build a UserStore (stateless; safe to construct per request)."""
    return UserStore()
