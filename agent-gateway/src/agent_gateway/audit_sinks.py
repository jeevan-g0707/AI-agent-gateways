"""Durable audit destinations.

The in-memory hash chain in `EvidenceStore` proves tampering; sinks make the evidence
survive the process and resist deletion:

  * FileWORMSink    append-only JSONL segments, fsync per entry, sealed (read-only + SHA-256
                    manifest) on rotation. Point it at a WORM/append-only mount (chattr +a,
                    or a volume whose writer cannot truncate).
  * ObjectLockSink  S3 Object Lock (COMPLIANCE mode): one immutable, never-overwritten object
                    per entry. Works with any boto3-compatible client (duck-typed).
  * HTTPEventSink   SIEM forwarder (Splunk HEC-style JSON). Retries, and spools to disk when the
                    SIEM is down so nothing is lost; flushed in order on the next write.

A *required* sink that fails makes the gateway refuse the action (audit-before-execute):
we never execute what we could not record. Optional sinks (SIEM) degrade gracefully.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol
from urllib.parse import urlparse


_BIN = getattr(os, "O_BINARY", 0)  # Windows: without this, os.open translates \n to \r\n and corrupts the log


class AuditUnavailable(Exception):
    """A required audit sink could not durably record an entry."""


class AuditTampered(Exception):
    """Stored audit data fails verification."""


class AuditSink(Protocol):
    name: str
    required: bool

    def write(self, entry: dict[str, Any]) -> None: ...
    def write_checkpoint(self, checkpoint: dict[str, Any]) -> None: ...


def _line(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode()


# ---------------------------------------------------------------------------
class FileWORMSink:
    name = "file"

    def __init__(self, directory: str | Path, *, required: bool = True,
                 max_segment_bytes: int = 64 * 1024 * 1024, try_chattr: bool = False,
                 checkpoints_dir: str | Path | None = None):
        self.required = required
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        # Keep checkpoints on DIFFERENT storage from entries so one compromise cannot rewrite both.
        self._cpdir = Path(checkpoints_dir) if checkpoints_dir else self._dir
        self._cpdir.mkdir(parents=True, exist_ok=True, mode=0o750)
        self._max = max_segment_bytes
        self._try_chattr = try_chattr
        self._lock = threading.Lock()
        self._fd: int | None = None
        self._size = 0
        self._idx = 0
        self._open_current()

    # -- segment management ------------------------------------------------
    def _segments(self) -> list[Path]:
        return sorted(self._dir.glob("audit-*.jsonl"))

    @staticmethod
    def _sealed(path: Path) -> bool:
        return not (path.stat().st_mode & stat.S_IWUSR)

    def _open_current(self) -> None:
        segs = self._segments()
        if segs and not self._sealed(segs[-1]):
            path = segs[-1]
            self._idx = int(path.stem.split("-")[1])
            self._repair(path)
        else:
            self._idx = (int(segs[-1].stem.split("-")[1]) + 1) if segs else 1
            path = self._dir / f"audit-{self._idx:06d}.jsonl"
        self._fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | _BIN, 0o640)
        st = os.fstat(self._fd)
        self._size, self._ino, self._path = st.st_size, st.st_ino, path
        if self._try_chattr:
            self._chattr_append_only(path)

    @staticmethod
    def _repair(path: Path) -> None:
        """A crash mid-write leaves a partial last line that was never acknowledged: drop it."""
        data = path.read_bytes()
        if data and not data.endswith(b"\n"):
            cut = data.rfind(b"\n") + 1
            with open(path, "r+b") as f:
                f.truncate(cut)

    @staticmethod
    def _chattr_append_only(path: Path) -> None:  # best effort; needs CAP_LINUX_IMMUTABLE
        import subprocess
        try:
            subprocess.run(["chattr", "+a", str(path)], check=False, capture_output=True, timeout=5)
        except Exception:
            pass

    def _seal(self) -> None:
        assert self._fd is not None
        os.fsync(self._fd)
        os.close(self._fd)
        self._fd = None
        data = self._path.read_bytes()
        manifest = {"segment": self._path.name, "sha256": hashlib.sha256(data).hexdigest(),
                    "entries": data.count(b"\n"), "bytes": len(data)}
        mfd = os.open(self._dir / "MANIFEST.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT | _BIN, 0o640)
        try:
            os.write(mfd, _line(manifest))
            os.fsync(mfd)
        finally:
            os.close(mfd)
        os.chmod(self._path, 0o440)

    def _check_untouched(self) -> None:
        """Our open file descriptor would happily keep appending to a file someone has unlinked, silently
        losing evidence. So before every write, confirm the path still points at the file we hold and
        that nobody has truncated or edited it behind our back. Any surprise = refuse (fail closed)."""
        try:
            st = os.stat(self._path)
        except FileNotFoundError:
            raise AuditUnavailable("audit file was deleted while the gateway was running") from None
        if st.st_ino != self._ino:
            raise AuditUnavailable("audit file was replaced while the gateway was running")
        if st.st_size != self._size:
            raise AuditUnavailable("audit file was modified outside the gateway")

    # -- AuditSink ----------------------------------------------------------
    immutable = False  # a local file is only as immutable as its host; see ObjectLockSink

    def write(self, entry: dict[str, Any]) -> None:
        data = _line(entry)
        with self._lock:
            try:
                self._check_untouched()
                if self._size > 0 and self._size + len(data) > self._max:
                    self._seal()
                    self._open_current()
                os.write(self._fd, data)  # type: ignore[arg-type]
                os.fsync(self._fd)  # type: ignore[arg-type]
                self._size += len(data)
            except OSError as exc:
                raise AuditUnavailable(f"file sink write failed: {exc}") from exc

    def write_checkpoint(self, checkpoint: dict[str, Any]) -> None:
        with self._lock:
            fd = os.open(self._cpdir / "checkpoints.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT | _BIN, 0o640)
            try:
                os.write(fd, _line(checkpoint))
                os.fsync(fd)
            finally:
                os.close(fd)

    # -- reading ------------------------------------------------------------
    def entries(self) -> Iterator[dict[str, Any]]:
        for seg in self._segments():
            with open(seg, "rb") as f:
                for raw in f:
                    if not raw.endswith(b"\n"):
                        raise AuditTampered(f"{seg.name}: truncated final line")
                    yield json.loads(raw)

    def checkpoints(self) -> list[dict[str, Any]]:
        p = self._cpdir / "checkpoints.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []

    def verify_manifest(self) -> list[str]:
        """Sealed segments must still hash to what the manifest recorded."""
        problems = []
        mp = self._dir / "MANIFEST.jsonl"
        for l in (mp.read_text().splitlines() if mp.exists() else []):
            m = json.loads(l)
            seg = self._dir / m["segment"]
            if not seg.exists():
                problems.append(f"sealed segment missing: {m['segment']}")
            elif hashlib.sha256(seg.read_bytes()).hexdigest() != m["sha256"]:
                problems.append(f"sealed segment modified: {m['segment']}")
        return problems

    def close(self) -> None:
        with self._lock:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None

    def entry_count(self) -> int:
        return sum(seg.read_bytes().count(b"\n") for seg in self._segments())

    def is_append_only(self) -> bool:
        """True if the filesystem enforces append-only (chattr +a) on the active segment (best effort)."""
        import subprocess
        try:
            out = subprocess.run(["lsattr", "-d", str(self._path)], capture_output=True, text=True, timeout=5)
            return out.returncode == 0 and "a" in out.stdout.split()[0]
        except Exception:
            return False

    def reset_quarantine(self) -> Path:
        """After tampering/deletion is detected: move everything aside (kept as evidence) and start a clean
        log, so it can be rebuilt from the immutable copy. Nothing is ever deleted."""
        with self._lock:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None
            qdir = self._dir / f"quarantine-{int(time.time())}-{os.urandom(3).hex()}"
            qdir.mkdir(mode=0o750)
            for p in list(self._dir.glob("audit-*.jsonl")) + list(self._dir.glob("MANIFEST.jsonl")):
                os.replace(p, qdir / p.name)
            self._open_current()
            return qdir


# ---------------------------------------------------------------------------
class ObjectLockSink:
    """S3 Object Lock. `client` is any boto3-style S3 client. The bucket must be created with
    Object Lock enabled. Keys are zero-padded sequence numbers, written with IfNoneMatch='*' so an
    existing entry can never be overwritten, and retained in COMPLIANCE mode (nobody, including the
    account root, can delete or shorten retention until it expires). Writes are idempotent: re-sending
    an identical entry is a no-op; a *different* entry at an existing key is refused."""

    name = "s3-object-lock"

    def __init__(self, client: Any, bucket: str, prefix: str = "audit/", *, retention_days: int = 365,
                 mode: str = "COMPLIANCE", required: bool = True,
                 clock: Callable[[], float] = time.time):
        if mode not in ("COMPLIANCE", "GOVERNANCE"):
            raise ValueError("mode must be COMPLIANCE or GOVERNANCE")
        self.required = required
        self._c, self._bucket, self._prefix = client, bucket, prefix.rstrip("/") + "/"
        self._days, self._mode, self._clock = retention_days, mode, clock
        self.immutable = mode == "COMPLIANCE"  # GOVERNANCE can be bypassed by privileged principals

    @staticmethod
    def _already_exists(exc: Exception) -> bool:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "") if hasattr(exc, "response") else ""
        return code in ("PreconditionFailed", "ObjectAlreadyExists", "412") or "PreconditionFailed" in str(exc)

    def _put(self, key: str, obj: dict[str, Any]) -> None:
        body = _line(obj)
        retain = datetime.fromtimestamp(self._clock(), timezone.utc) + timedelta(days=self._days)
        try:
            self._c.put_object(
                Bucket=self._bucket, Key=key, Body=body, ContentType="application/json",
                ObjectLockMode=self._mode, ObjectLockRetainUntilDate=retain, IfNoneMatch="*",
            )
        except Exception as exc:
            if self._already_exists(exc):
                try:  # idempotent replay: identical content already stored is success
                    existing = self._c.get_object(Bucket=self._bucket, Key=key)["Body"].read()
                except Exception as exc2:
                    raise AuditUnavailable(f"object-lock readback failed: {type(exc2).__name__}") from exc2
                if existing == body:
                    return
                raise AuditUnavailable("object-lock: a DIFFERENT entry already exists at this sequence number")
            raise AuditUnavailable(f"object-lock write failed: {type(exc).__name__}") from exc

    def write(self, entry: dict[str, Any]) -> None:
        self._put(f"{self._prefix}entries/{entry['seq']:012d}.json", entry)

    def write_checkpoint(self, checkpoint: dict[str, Any]) -> None:
        self._put(f"{self._prefix}checkpoints/{checkpoint['seq']:012d}.json", checkpoint)

    # -- configuration verification --------------------------------------------
    def verify_bucket(self, *, min_retention_days: int | None = None, probe: bool = True) -> list[str]:
        """Check the bucket really is what the docs say instead of trusting that someone configured it so.
        Returns a list of problems (empty = ok). With `probe`, writes ONE throwaway object under `_probe/` (never an
        audit entry) and checks that it can be neither deleted nor have its retention shortened - so if the lock is
        misconfigured the probe is all that is ever lost. Never raises."""
        problems: list[str] = []
        if self._mode != "COMPLIANCE":
            problems.append("sink writes in GOVERNANCE mode: privileged principals can bypass it")
        if min_retention_days is not None and self._days < min_retention_days:
            problems.append(f"sink retention is {self._days} days, below the required {min_retention_days}")
        try:
            cfg = self._c.get_object_lock_configuration(Bucket=self._bucket).get("ObjectLockConfiguration", {})
        except Exception as exc:
            return problems + [f"cannot read the bucket's Object Lock configuration ({type(exc).__name__}): "
                               "Object Lock is probably not enabled on this bucket"]
        if cfg.get("ObjectLockEnabled") != "Enabled":
            problems.append("Object Lock is not enabled on the bucket")
        default = cfg.get("Rule", {}).get("DefaultRetention")
        if default:
            if default.get("Mode") != "COMPLIANCE":
                problems.append(f"bucket default retention is {default.get('Mode')}, not COMPLIANCE")
            days = default.get("Days") or (default.get("Years") or 0) * 365
            if min_retention_days is not None and days < min_retention_days:
                problems.append(f"bucket default retention is {days} days, below the required {min_retention_days}")
        try:
            if self._c.get_bucket_versioning(Bucket=self._bucket).get("Status") != "Enabled":
                problems.append("bucket versioning is not enabled")
        except Exception as exc:
            problems.append(f"cannot read bucket versioning ({type(exc).__name__})")
        if probe:
            problems += self._probe()
        return problems

    def _probe(self) -> list[str]:
        import secrets

        now = datetime.fromtimestamp(self._clock(), timezone.utc)
        key = f"{self._prefix}_probe/{int(self._clock())}-{secrets.token_hex(4)}.json"
        try:
            put = self._c.put_object(Bucket=self._bucket, Key=key, Body=b"{}", ContentType="application/json",
                                     ObjectLockMode="COMPLIANCE", ObjectLockRetainUntilDate=now + timedelta(days=1))
        except Exception as exc:
            return [f"probe write failed ({type(exc).__name__}): the gateway role cannot write locked objects"]
        out: list[str] = []
        ver = {"VersionId": put["VersionId"]} if isinstance(put, dict) and put.get("VersionId") else {}
        try:
            self._c.delete_object(Bucket=self._bucket, Key=key, **ver)
            out.append("a locked object could be DELETED during its retention period: the bucket is not immutable")
        except Exception:
            pass  # AccessDenied is the correct outcome
        try:
            self._c.put_object_retention(Bucket=self._bucket, Key=key, **ver, Retention={
                "Mode": "COMPLIANCE", "RetainUntilDate": now + timedelta(minutes=1)})
            out.append("retention of a locked object could be SHORTENED: the bucket is not immutable")
        except Exception:
            pass
        return out

    # -- read-back (recovery, watchdog) ----------------------------------------
    def _keys(self, sub: str) -> list[str]:
        keys: list[str] = []
        token = None
        while True:
            kw = {"Bucket": self._bucket, "Prefix": f"{self._prefix}{sub}/"}
            if token:
                kw["ContinuationToken"] = token
            try:
                page = self._c.list_objects_v2(**kw)
            except Exception as exc:
                raise AuditUnavailable(f"object-lock list failed: {type(exc).__name__}") from exc
            keys += [o["Key"] for o in page.get("Contents", [])]
            if not page.get("IsTruncated"):
                return sorted(keys)
            token = page.get("NextContinuationToken")

    def _read(self, key: str) -> dict[str, Any]:
        try:
            return json.loads(self._c.get_object(Bucket=self._bucket, Key=key)["Body"].read())
        except Exception as exc:
            raise AuditUnavailable(f"object-lock read failed: {type(exc).__name__}") from exc

    def entries(self) -> Iterator[dict[str, Any]]:
        for k in self._keys("entries"):
            yield self._read(k)

    def checkpoints(self) -> list[dict[str, Any]]:
        return [self._read(k) for k in self._keys("checkpoints")]

    def entry_count(self) -> int:
        return len(self._keys("entries"))


# ---------------------------------------------------------------------------
class HTTPEventSink:
    """SIEM forwarder with at-least-once delivery. Events that cannot be delivered are spooled to
    disk and replayed in order before any new event. Never `required`: the SIEM being down must
    not stop the business, but nothing is dropped silently (see `backlog`)."""

    name = "siem-http"
    required = False

    def __init__(self, url: str, token: str, http: Any, *, spool_path: str | Path,
                 sourcetype: str = "agent_gateway:audit", allow_insecure: bool = False,
                 attempts: int = 3, sleep: Callable[[float], None] = time.sleep):
        if urlparse(url).scheme != "https" and not allow_insecure:
            raise ValueError("SIEM endpoint must be https")
        self._url, self._token, self._http = url, token, http
        self._spool = Path(spool_path)
        self._spool.parent.mkdir(parents=True, exist_ok=True)
        self._type, self._attempts, self._sleep = sourcetype, attempts, sleep
        self._lock = threading.Lock()

    def _post(self, payload: dict[str, Any]) -> bool:
        for i in range(self._attempts):
            try:
                r = self._http.post(self._url, json=payload, headers={"Authorization": f"Splunk {self._token}"},
                                    timeout=5.0, follow_redirects=False)
                if r.status_code < 300:
                    return True
                if r.status_code < 500 and r.status_code != 429:
                    return False  # client error: retrying will not help
            except Exception:
                pass
            if i + 1 < self._attempts:
                self._sleep(min(2 ** i * 0.2, 2.0))
        return False

    def _spool_add(self, payload: dict[str, Any]) -> None:
        try:
            fd = os.open(self._spool, os.O_WRONLY | os.O_APPEND | os.O_CREAT | _BIN, 0o600)
            try:
                os.write(fd, _line(payload))
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            raise AuditUnavailable(f"SIEM spool write failed: {exc}") from exc

    def backlog(self) -> int:
        return sum(1 for l in self._spool.read_text().splitlines() if l.strip()) if self._spool.exists() else 0

    def flush(self) -> int:
        """Replay spooled events in order. Returns how many remain."""
        with self._lock:
            if not self._spool.exists():
                return 0
            lines = [l for l in self._spool.read_text().splitlines() if l.strip()]
            sent = 0
            for l in lines:
                if not self._post(json.loads(l)):
                    break
                sent += 1
            rest = lines[sent:]
            tmp = self._spool.with_suffix(".tmp")
            tmp.write_text("".join(l + "\n" for l in rest))
            os.replace(tmp, self._spool)
            return len(rest)

    def _send(self, payload: dict[str, Any]) -> None:
        with self._lock:
            pending = self._spool.exists() and self._spool.stat().st_size > 0
        if pending and self.flush() > 0:  # keep ordering: older events first
            self._spool_add(payload)
            return
        if not self._post(payload):
            self._spool_add(payload)

    def write(self, entry: dict[str, Any]) -> None:
        self._send({"sourcetype": self._type, "event": {"kind": "entry", **entry}})

    def write_checkpoint(self, checkpoint: dict[str, Any]) -> None:
        self._send({"sourcetype": self._type, "event": {"kind": "checkpoint", **checkpoint}})
