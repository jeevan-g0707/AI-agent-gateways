"""Shared-state backends.

Every component that must be consistent across gateway replicas (approvals, nonces,
revocations, rate windows, circuit-breaker state, live-token registry) talks to a
`StateBackend`. Two implementations:

  * MemoryBackend  - single process (tests, local dev)
  * RedisBackend   - production; atomicity via WATCH/MULTI compare-and-swap, SET NX EX,
                     and transactional sorted-set windows.

The key primitive is `atomic_update(key, fn)`: fn receives the current JSON value (or None)
and returns (new_value, result). The read-modify-write is indivisible; if fn raises, nothing
is written. This is what makes "check and consume an approval exactly once" safe under
concurrency, equivalent to a Lua EVAL / SELECT ... FOR UPDATE.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Any, Callable, Protocol, TypeVar

T = TypeVar("T")

UNCHANGED = object()  # fn returns this as new_value to skip the write


class StateBackend(Protocol):
    def get(self, key: str) -> dict | None: ...
    def atomic_update(self, key: str, fn: Callable[[dict | None], tuple[Any, T]], ttl: float | None = None) -> T: ...
    def set_nx(self, key: str, ttl: float) -> bool: ...
    def set_add(self, key: str, member: str, ttl: float | None = None) -> None: ...
    def set_contains(self, key: str, member: str) -> bool: ...
    def set_members(self, key: str) -> set[str]: ...
    def window_add(self, key: str, now: float, window: float) -> int: ...


class MemoryBackend:
    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._kv: dict[str, tuple[str, float | None]] = {}
        self._sets: dict[str, set[str]] = {}
        self._windows: dict[str, list[float]] = {}
        self._lock = threading.RLock()

    def _live(self, key: str) -> str | None:
        item = self._kv.get(key)
        if item is None:
            return None
        raw, exp = item
        if exp is not None and self._clock() >= exp:
            del self._kv[key]
            return None
        return raw

    def get(self, key: str) -> dict | None:
        with self._lock:
            raw = self._live(key)
            return json.loads(raw) if raw is not None else None

    def atomic_update(self, key, fn, ttl=None):
        with self._lock:
            raw = self._live(key)
            cur = json.loads(raw) if raw is not None else None
            new, result = fn(cur)
            if new is UNCHANGED:
                return result
            if new is None:
                self._kv.pop(key, None)
            else:
                old_exp = self._kv[key][1] if key in self._kv else None
                exp = self._clock() + ttl if ttl is not None else old_exp
                self._kv[key] = (json.dumps(new), exp)
            return result

    def set_nx(self, key, ttl):
        with self._lock:
            if self._live(key) is not None:
                return False
            self._kv[key] = ("1", self._clock() + ttl)
            return True

    def set_add(self, key, member, ttl=None):
        with self._lock:
            self._sets.setdefault(key, set()).add(member)

    def set_contains(self, key, member):
        with self._lock:
            return member in self._sets.get(key, ())

    def set_members(self, key):
        with self._lock:
            return set(self._sets.get(key, ()))

    def window_add(self, key, now, window):
        with self._lock:
            w = [t for t in self._windows.get(key, []) if now - t < window]
            w.append(now)
            self._windows[key] = w
            return len(w)


class RedisBackend:
    """redis-py backed implementation. Pass a `redis.Redis` (or compatible) client."""

    def __init__(self, client, prefix: str = "agw:"):
        import redis  # local import keeps redis an optional dependency

        self._r = client
        self._p = prefix
        self._watch_error = redis.WatchError

    def _k(self, key: str) -> str:
        return self._p + key

    def get(self, key):
        raw = self._r.get(self._k(key))
        return json.loads(raw) if raw else None

    def atomic_update(self, key, fn, ttl=None):
        k = self._k(key)
        with self._r.pipeline() as pipe:
            for _ in range(100):  # CAS retry loop under contention
                try:
                    pipe.watch(k)
                    raw = pipe.get(k)
                    cur = json.loads(raw) if raw else None
                    new, result = fn(cur)  # may raise -> nothing written, watch released
                    if new is UNCHANGED:
                        pipe.unwatch()
                        return result
                    pipe.multi()
                    if new is None:
                        pipe.delete(k)
                    elif ttl is not None:
                        pipe.set(k, json.dumps(new), ex=max(1, int(ttl)))
                    else:
                        pipe.set(k, json.dumps(new), keepttl=True)
                    pipe.execute()
                    return result
                except self._watch_error:
                    continue
        raise RuntimeError("state update contention: gave up after 100 retries")

    def set_nx(self, key, ttl):
        return bool(self._r.set(self._k(key), "1", nx=True, ex=max(1, int(ttl))))

    def set_add(self, key, member, ttl=None):
        k = self._k(key)
        self._r.sadd(k, member)
        if ttl:
            self._r.expire(k, int(ttl))

    def set_contains(self, key, member):
        return bool(self._r.sismember(self._k(key), member))

    def set_members(self, key):
        return {m.decode() if isinstance(m, bytes) else m for m in self._r.smembers(self._k(key))}

    def window_add(self, key, now, window):
        k = self._k(key)
        with self._r.pipeline(transaction=True) as pipe:
            pipe.zremrangebyscore(k, 0, now - window)
            pipe.zadd(k, {f"{now}:{uuid.uuid4().hex}": now})
            pipe.zcard(k)
            pipe.expire(k, int(window) + 5)
            return int(pipe.execute()[2])
