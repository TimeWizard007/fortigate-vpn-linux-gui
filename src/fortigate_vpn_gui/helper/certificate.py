# SPDX-License-Identifier: GPL-3.0-or-later
"""Parse openfortivpn gateway certificate validation failures.

Only subject, issuer, and SHA-256 digest are extracted. Unrelated secrets in
the same stream are ignored.
"""

from __future__ import annotations

import re

from fortigate_vpn_gui.helper.protocol import CertificateInfo
from fortigate_vpn_gui.helper.validation import normalize_sha256_fingerprint

_VALIDATION_FAILED = re.compile(r"gateway certificate validation failed", re.IGNORECASE)
_SUBJECT = re.compile(r"subject:\s*(.*)$", re.IGNORECASE)
_ISSUER = re.compile(r"issuer:\s*(.*)$", re.IGNORECASE)
_SHA256_LABEL = re.compile(r"sha256(?:\s+digest)?\s*:?\s*(.*)$", re.IGNORECASE)
_HEX_LINE = re.compile(r"^[0-9A-Fa-f: ]{64,}$")
_LOG_PREFIX = re.compile(r"^(?:error|warn|warning|info|debug):\s*", re.IGNORECASE)


class CertificateFailureParser:
    """Incremental parser for a multi-line certificate validation failure."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._failed = False
        self._subject = ""
        self._issuer = ""
        self._sha256: str | None = None
        self._expect_subject_value = False
        self._expect_issuer_value = False
        self._expect_sha_value = False

    @property
    def validation_failed(self) -> bool:
        return self._failed

    def feed(self, line: str) -> CertificateInfo | None:
        """Consume one output line. Return info when subject/issuer/digest are known."""
        stripped = _strip_log_prefix(line)
        lowered = stripped.lower()
        if _VALIDATION_FAILED.search(line):
            self._failed = True
        if not self._failed and not (
            "gateway certificate" in lowered or "trusted-cert" in lowered
        ):
            return None

        if self._expect_subject_value and stripped and "issuer:" not in lowered:
            self._subject = _clean_dn(stripped)
            self._expect_subject_value = False
        elif self._expect_issuer_value and stripped and "sha256" not in lowered:
            self._issuer = _clean_dn(stripped)
            self._expect_issuer_value = False
        elif self._expect_sha_value:
            digest = normalize_sha256_fingerprint(stripped)
            if digest is not None:
                self._sha256 = digest
                self._expect_sha_value = False

        subject_match = _SUBJECT.search(stripped)
        if subject_match:
            remainder = subject_match.group(1).strip()
            if remainder:
                self._subject = _clean_dn(remainder)
            else:
                self._expect_subject_value = True
        issuer_match = _ISSUER.search(stripped)
        if issuer_match:
            remainder = issuer_match.group(1).strip()
            if remainder:
                self._issuer = _clean_dn(remainder)
            else:
                self._expect_issuer_value = True
        sha_match = _SHA256_LABEL.search(stripped)
        if sha_match:
            remainder = sha_match.group(1).strip()
            digest = normalize_sha256_fingerprint(remainder)
            if digest is not None:
                self._sha256 = digest
            else:
                self._expect_sha_value = True
        elif _HEX_LINE.fullmatch(re.sub(r"[\s:]", "", stripped)) or _HEX_LINE.fullmatch(stripped):
            digest = normalize_sha256_fingerprint(stripped)
            if digest is not None:
                self._sha256 = digest

        return self.snapshot()

    def snapshot(self) -> CertificateInfo | None:
        if not self._failed or self._sha256 is None:
            return None
        return CertificateInfo(
            subject=self._subject or "unknown",
            issuer=self._issuer or "unknown",
            sha256=self._sha256,
        )


def parse_certificate_output(text: str) -> CertificateInfo | None:
    """Parse a block of openfortivpn output for certificate metadata."""
    parser = CertificateFailureParser()
    result = None
    for line in text.splitlines():
        parsed = parser.feed(line)
        if parsed is not None:
            result = parsed
    return result


def is_certificate_validation_failure(line: str) -> bool:
    """Return True when a line reports gateway certificate validation failure."""
    return _VALIDATION_FAILED.search(line) is not None


def _strip_log_prefix(line: str) -> str:
    return _LOG_PREFIX.sub("", line.strip(), count=1).strip()


def _clean_dn(value: str) -> str:
    text = _strip_log_prefix(value)
    return text.lstrip("/").strip()
