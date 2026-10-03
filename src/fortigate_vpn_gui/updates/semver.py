# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict X.Y.Z comparison. Not lexicographic string comparison."""

from __future__ import annotations


def parse_semver(value: str) -> tuple[int, int, int] | None:
    """Return ``(major, minor, patch)`` for a stable ``X.Y.Z`` version.

    A leading ``v``/``V`` is accepted. Pre-release suffixes and extra segments
    are rejected so 1.10.0 compares greater than 1.9.0.
    """
    text = str(value).strip()
    if text[:1] in {"v", "V"}:
        text = text[1:]
    parts = text.split(".")
    if len(parts) != 3:
        return None
    numbers: list[int] = []
    for part in parts:
        if not part.isdigit():
            return None
        if len(part) > 1 and part.startswith("0"):
            return None
        numbers.append(int(part, 10))
    return numbers[0], numbers[1], numbers[2]


def version_sort_key(value: str) -> tuple[int, int, int] | None:
    return parse_semver(value)


def compare_semver(left: str, right: str) -> int | None:
    """Return -1, 0, or 1 like ``cmp(left, right)``, or None if either is invalid."""
    parsed_left = parse_semver(left)
    parsed_right = parse_semver(right)
    if parsed_left is None or parsed_right is None:
        return None
    if parsed_left < parsed_right:
        return -1
    if parsed_left > parsed_right:
        return 1
    return 0
