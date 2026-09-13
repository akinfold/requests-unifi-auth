"""Assertion helpers that keep authentication material out of pytest output."""

from __future__ import annotations


def assert_secret_condition(condition: bool, message: str) -> None:
    """Raise a static assertion message without exposing compared values."""
    if not condition:
        raise AssertionError(message)
