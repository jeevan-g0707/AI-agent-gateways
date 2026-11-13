"""4-tier data classification and operation-aware protection (context / log / output).

Detection is layered: validated detectors (Luhn for cards, mod-97 for IBANs, structural SSN
rules, provider-specific secret formats) run over the raw text AND decoded views (URL/HTML
escapes, base64, hex), so wrapping a secret in an encoding does not hide it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .textviews import expand_views


class DataClassification(Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"  # PII, financial data, raw credentials


_RANK = {DataClassification.PUBLIC: 0, DataClassification.INTERNAL: 1,
         DataClassification.CONFIDENTIAL: 2, DataClassification.RESTRICTED: 3}


class Operation(str, Enum):
    INCLUDE_IN_CONTEXT = "include_in_context"
    LOG = "log"
    OUTPUT = "output"


@dataclass(frozen=True)
class Finding:
    kind: str
    classification: DataClassification
    start: int
    end: int
    view: str  # "raw" or the decoded view the match came from


# ---------------------------------------------------------------- validators
def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            d -= 9 if d > 9 else 0
        total += d
        alt = not alt
    return total % 10 == 0


def card_issuer_ok(d: str) -> bool:
    n = len(d)
    if d[0] == "4":
        return n in (13, 16, 19)
    if 51 <= int(d[:2]) <= 55 or 2221 <= int(d[:4]) <= 2720:
        return n == 16
    if d[:2] in ("34", "37"):
        return n == 15
    if d[:4] == "6011" or d[:2] == "65" or 644 <= int(d[:3]) <= 649:
        return n in (16, 19)
    if 3528 <= int(d[:4]) <= 3589:
        return n in (16, 19)
    return False


def iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    rearr = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in rearr)
    return int(num) % 97 == 1


def ssn_ok(area: str, group: str, serial: str) -> bool:
    return area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000"


# ------------------------------------------------------------------ patterns
_SECRET_PATTERNS = {
    "aws_access_key": r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b",
    "github_token": r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b",
    "slack_token": r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
    "stripe_key": r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{20,}\b",
    "google_api_key": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "jwt": r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
    "private_key": r"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY(?: BLOCK)?-----",
    "bearer_token": r"\bbearer\s+[A-Za-z0-9._~+/=-]{20,}",
    "url_credentials": r"\b[a-z][a-z0-9+.-]*://[^\s:@/]+:[^\s@/]+@[^\s/]+",
    "credential_assignment": r"(?i)\b(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|passwd|password|pwd)\b[\"']?\s*[:=]\s*[\"']?[^\s\"',;]+",
}
_SECRET_RE = {k: re.compile(v, re.IGNORECASE if k not in ("aws_access_key", "github_token", "jwt") else 0)
              for k, v in _SECRET_PATTERNS.items()}

_CARD_RE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
_SSN_SEP_RE = re.compile(r"(?<!\d)(\d{3})([- ])(\d{2})\2(\d{4})(?!\d)")
_SSN_CTX_RE = re.compile(r"(?i)\b(?:ssn|social security(?: number)?)\b\W{0,12}(\d{3})(\d{2})(\d{4})\b")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")

_CONFIDENTIAL_RE = [re.compile(p, re.IGNORECASE) for p in (
    r"\b(?:salary|salaries|bonus|compensation|severance)\b",
    r"\bconfidential\b|\binternal only\b|\battorney[- ]client\b|\btrade secret\b",
)]
_INTERNAL_RE = [re.compile(p, re.IGNORECASE) for p in (
    r"@enterprise\.com",
    r"\bdraft\b|\bnot for distribution\b|\binternal use\b",
)]


class DataProtectionPolicy:
    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------ detection
    def scan(self, content: str) -> list[Finding]:
        out: list[Finding] = []
        for view_name, text in expand_views(content):
            out.extend(self._scan_text(text, view_name))
        return out

    def _scan_text(self, text: str, view: str) -> list[Finding]:
        R, C, I = DataClassification.RESTRICTED, DataClassification.CONFIDENTIAL, DataClassification.INTERNAL
        f: list[Finding] = []
        for kind, rx in _SECRET_RE.items():
            for m in rx.finditer(text):
                f.append(Finding(kind, R, m.start(), m.end(), view))
        for m in _CARD_RE.finditer(text):
            digits = re.sub(r"[ -]", "", m.group())
            if 13 <= len(digits) <= 19 and card_issuer_ok(digits) and luhn_ok(digits):
                f.append(Finding("credit_card", R, m.start(), m.end(), view))
        for m in _SSN_SEP_RE.finditer(text):
            if ssn_ok(m.group(1), m.group(3), m.group(4)):
                f.append(Finding("ssn", R, m.start(), m.end(), view))
        for m in _SSN_CTX_RE.finditer(text):
            if ssn_ok(*m.groups()):
                f.append(Finding("ssn", R, m.start(), m.end(), view))
        for m in _IBAN_RE.finditer(text):
            if iban_ok(m.group()):
                f.append(Finding("iban", R, m.start(), m.end(), view))
        for rx in _CONFIDENTIAL_RE:
            for m in rx.finditer(text):
                f.append(Finding("confidential_term", C, m.start(), m.end(), view))
        for rx in _INTERNAL_RE:
            for m in rx.finditer(text):
                f.append(Finding("internal_marker", I, m.start(), m.end(), view))
        return f

    def classify_data(self, content: str) -> DataClassification:
        best = DataClassification.PUBLIC
        for fd in self.scan(content):
            if _RANK[fd.classification] > _RANK[best]:
                best = fd.classification
        return best

    # ----------------------------------------------------------- protection
    def apply_protection(
        self, content: str, classification: DataClassification, operation: str | Operation
    ) -> str:
        op = operation.value if isinstance(operation, Operation) else operation
        if classification is DataClassification.RESTRICTED:
            return "[REDACTED_RESTRICTED_DATA]"  # all operational modes

        if classification is DataClassification.CONFIDENTIAL:
            if op == "log":
                return "[REDACTED_CONFIDENTIAL_LOG]"
            return self._mask_partially(content)  # context + output

        if classification is DataClassification.INTERNAL:
            if op == "log":
                return self._mask_partially(content)
            return content

        return content

    def protect(self, content: str, operation: str | Operation) -> tuple[str, DataClassification]:
        cls = self.classify_data(content)
        return self.apply_protection(content, cls, operation), cls

    def redact_restricted_spans(self, content: str) -> str:
        """Span-level redaction for persisted memory (keeps the non-sensitive remainder).
        If a secret is only visible after decoding, the span cannot be mapped back, so the
        whole item is redacted instead."""
        findings = [f for f in self.scan(content) if f.classification is DataClassification.RESTRICTED]
        if not findings:
            return content
        if any(f.view != "raw" for f in findings):
            return "[REDACTED_ENCODED_SENSITIVE_DATA]"
        spans = sorted((f.start, f.end) for f in findings if f.view == "raw")
        merged: list[list[int]] = []
        for s, e in spans:
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        out, pos = [], 0
        for s, e in merged:
            out.append(content[pos:s])
            out.append("[REDACTED]")
            pos = e
        out.append(content[pos:])
        return "".join(out)

    @staticmethod
    def _mask_partially(data: str) -> str:
        if len(data) <= 4:
            return "****"
        return data[:2] + "*" * (len(data) - 4) + data[-2:]
