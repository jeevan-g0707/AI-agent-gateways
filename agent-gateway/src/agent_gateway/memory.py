"""Isolated, integrity-checked, provenance-tagged agent memory."""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from .dlp import DataProtectionPolicy
from .injection import InjectionDefense

MAX_TTL_SECONDS = 24 * 3600


class Provenance(str, Enum):
    USER = "user"
    TOOL_OUTPUT = "tool_output"
    RETRIEVED_DOC = "retrieved_doc"


class Trust(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


@dataclass
class MemoryRecord:
    content: str
    actor_user_id: str
    tenant_id: str
    session_id: str
    provenance: Provenance
    origin: str
    trust: Trust
    created_at: float
    expires_at: float
    checksum: str
    quarantined: bool = False


def compute_checksum(content: str, actor_user_id: str, key: bytes) -> str:
    """HMAC-SHA256(content + actor_user_id, key).hexdigest()[:16]"""
    return hmac.new(key, (content + actor_user_id).encode(), hashlib.sha256).hexdigest()[:16]


class SecureMemoryStore:
    def __init__(
        self,
        secret_key: bytes,
        clock: Callable[[], float] = time.time,
        dlp: DataProtectionPolicy | None = None,
        injection: InjectionDefense | None = None,
    ):
        self._key = secret_key
        self._clock = clock
        self._dlp = dlp or DataProtectionPolicy()
        self._inj = injection or InjectionDefense()
        self._records: dict[tuple[str, str, str], list[MemoryRecord]] = {}

    def write(
        self,
        content: str,
        *,
        actor_user_id: str,
        tenant_id: str,
        session_id: str,
        provenance: Provenance,
        origin: str,
        ttl: int = MAX_TTL_SECONDS,
    ) -> MemoryRecord:
        ttl = min(ttl, MAX_TTL_SECONDS)
        redacted = self._dlp.redact_restricted_spans(content)  # PII/credential redaction first
        scan = self._inj.scan(redacted)
        now = self._clock()
        rec = MemoryRecord(
            content=redacted,
            actor_user_id=actor_user_id,
            tenant_id=tenant_id,
            session_id=session_id,
            provenance=provenance,
            origin=origin,
            trust=Trust.TRUSTED if provenance is Provenance.USER else Trust.UNTRUSTED,
            created_at=now,
            expires_at=now + ttl,
            checksum=compute_checksum(redacted, actor_user_id, self._key),
            quarantined=not scan.clean,  # poisoned writes are stored dark, never retrievable
        )
        self._records.setdefault((tenant_id, actor_user_id, session_id), []).append(rec)
        return rec

    def read(self, *, actor_user_id: str, tenant_id: str, session_id: str) -> list[MemoryRecord]:
        """Strict partition: only the exact (tenant, user, session) bucket is visible."""
        now = self._clock()
        out = []
        for rec in self._records.get((tenant_id, actor_user_id, session_id), []):
            if rec.quarantined or now >= rec.expires_at:
                continue
            expected = compute_checksum(rec.content, rec.actor_user_id, self._key)
            if not hmac.compare_digest(expected, rec.checksum):
                rec.quarantined = True  # tampering detected
                continue
            out.append(rec)
        return out

    def quarantine_session(self, session_id: str) -> int:
        n = 0
        for (_, _, sid), recs in self._records.items():
            if sid == session_id:
                for r in recs:
                    if not r.quarantined:
                        r.quarantined = True
                        n += 1
        return n

    def purge_expired(self) -> int:
        now = self._clock()
        n = 0
        for k, recs in self._records.items():
            keep = [r for r in recs if now < r.expires_at]
            n += len(recs) - len(keep)
            self._records[k] = keep
        return n
