"""Credentials come only from environment variables. Nothing is written to disk."""

from __future__ import annotations

import os

from nettrace.errors import CredentialError


def env_value(name: str | None, *, required: bool = True, what: str = "credential") -> str | None:
    if not name:
        if required:
            raise CredentialError(f"no environment variable configured for {what}")
        return None
    value = os.environ.get(name)
    if required and not value:
        raise CredentialError(f"environment variable {name} ({what}) is not set")
    return value or None
