"""Egress / exfiltration pattern detector for proposed tool arguments."""
from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlparse

B64_RE = re.compile(r"(?:[A-Za-z0-9+/_-]{24,}={0,2})")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
MAX_PARAM_LEN = 256
MAX_URL_LEN = 512
ENTROPY_THRESHOLD = 4.2  # bits/char; base64 of random data sits ~5.5-6


@dataclass
class ExfilFinding:
    kind: str
    detail: str


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _is_b64(token: str) -> bool:
    padded = token + "=" * (-len(token) % 4)
    try:
        base64.b64decode(padded, altchars=b"-_", validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def _walk_strings(obj: Any):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _walk_strings(v)


class ExfiltrationDetector:
    def __init__(self, allowed_hosts: frozenset[str] = frozenset()):
        self.allowed_hosts = allowed_hosts

    def scan(self, arguments: dict[str, Any]) -> list[ExfilFinding]:
        findings: list[ExfilFinding] = []
        for s in _walk_strings(arguments):
            for url in URL_RE.findall(s):
                findings.extend(self._scan_url(url))
            # Base64 blobs outside URLs too (webhook bodies, etc.)
            stripped = URL_RE.sub(" ", s)
            for tok in B64_RE.findall(stripped):
                if len(tok) >= 40 and _is_b64(tok) and _entropy(tok) >= ENTROPY_THRESHOLD:
                    findings.append(ExfilFinding("base64_blob", f"{len(tok)}-char encoded blob"))
        return findings

    def _scan_url(self, url: str) -> list[ExfilFinding]:
        out: list[ExfilFinding] = []
        try:
            parsed = urlparse(url)
        except ValueError:
            return [ExfilFinding("malformed_url", "unparseable URL")]
        host = (parsed.hostname or "").lower()
        if self.allowed_hosts and host not in self.allowed_hosts:
            out.append(ExfilFinding("untrusted_host", host or "?"))
        if len(url) > MAX_URL_LEN:
            out.append(ExfilFinding("oversized_url", f"{len(url)} chars"))
        values = [v for _, v in parse_qsl(parsed.query, keep_blank_values=True)]
        values += [seg for seg in parsed.path.split("/") if seg]
        values.append(parsed.fragment)
        for v in values:
            if len(v) > MAX_PARAM_LEN:
                out.append(ExfilFinding("oversized_param", f"{len(v)} chars"))
            if len(v) >= 24 and _is_b64(v) and _entropy(v) >= ENTROPY_THRESHOLD:
                out.append(ExfilFinding("base64_in_url", "base64-encoded URL component"))
        return out
