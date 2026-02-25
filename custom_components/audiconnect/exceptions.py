"""Exceptions for the Audi Connect integration."""

from __future__ import annotations


class AudiAuthError(Exception):
    """Raised when authentication fails due to invalid or expired credentials."""


__all__ = ["AudiAuthError"]
