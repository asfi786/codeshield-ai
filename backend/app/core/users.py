"""User account storage on Vercel Blob.

Each account is a single private JSON blob at
``users/{sha256(lowercase_email)}.json``. One file per user means
registrations never race each other, and lookups are direct (no listing).

The blob holds ``{name, email, pw_hash, created_at, provider}``. Passwords
are stored as peppered PBKDF2 hashes (see :mod:`app.core.auth`); the
pepper lives only in the server's environment, never in the blob.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any

logger = logging.getLogger(__name__)

USERS_PREFIX = "users/"


def blob_path_for(email: str) -> str:
    """Deterministic private blob path for an email address."""
    digest = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
    return f"{USERS_PREFIX}{digest}.json"


class UserExistsError(Exception):
    """Raised when registering an email that already has an account."""


class UserStoreUnavailableError(Exception):
    """Raised when the blob store cannot be reached or configured."""


class UserStore:
    """Thin async wrapper around the Vercel Blob Python SDK."""

    def __init__(self) -> None:
        try:
            from vercel.blob import AsyncBlobClient
        except ImportError as exc:
            raise UserStoreUnavailableError(
                "The 'vercel' package is not installed."
            ) from exc
        # Pass the read-write token explicitly: relying on the SDK's
        # automatic credential resolution (OIDC vs. static token) is
        # ambiguous on Vercel, and a wrong guess breaks every call.
        token = os.environ.get("BLOB_READ_WRITE_TOKEN")
        if not token:
            raise UserStoreUnavailableError(
                "Blob store is not configured (missing BLOB_READ_WRITE_TOKEN)."
            )
        self._client = AsyncBlobClient(token=token)

    async def get_user(self, email: str) -> dict[str, Any] | None:
        """Return the user record for an email, or None."""
        try:
            result = await self._client.get(blob_path_for(email), access="private")
        except Exception as exc:
            # The SDK raises BlobNotFoundError on 404.
            if exc.__class__.__name__ == "BlobNotFoundError":
                return None
            logger.warning("user lookup failed for %s: %s", email, exc)
            raise UserStoreUnavailableError("User store is unavailable.") from exc
        if result is None:
            return None
        try:
            content = result.content
            if isinstance(content, (bytes, bytearray)):
                content = bytes(content).decode("utf-8")
            return json.loads(content)
        except Exception as exc:
            logger.warning("corrupt user blob for %s: %s", email, exc)
            return None

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
        body = json.dumps(record).encode("utf-8")
        try:
            # overwrite=False is a backstop against a lost race: two
            # simultaneous registrations for the same email.
            await self._client.put(
                blob_path_for(email_norm),
                body,
                access="private",
                content_type="application/json",
                overwrite=False,
            )
        except Exception as exc:
            # If the blob appeared between our check and the put, treat as taken.
            if await self.get_user(email_norm) is not None:
                raise UserExistsError(email_norm) from exc
            logger.warning("user creation failed for %s: %s", email_norm, exc)
            raise UserStoreUnavailableError("User store is unavailable.") from exc
        return record


def get_store() -> UserStore:
    """Build a UserStore (cheap; the SDK client holds no connections)."""
    return UserStore()
