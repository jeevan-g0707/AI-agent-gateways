"""Canonicalization and decoding layers shared by DLP and injection scanning.

Attackers hide payloads behind Unicode tricks and encodings (zero-width characters,
lookalike letters, URL/HTML escapes, base64, hex, ROT13). Scanners therefore look at
*views* of the text, not just the raw string.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
from urllib.parse import unquote

# zero-width, bidi controls, soft hyphen, BOM, word joiner
_INVISIBLE = {ord(c): None for c in "​‌‍‎‏⁠⁡⁢⁣⁤﻿­"
              + "".join(chr(c) for c in range(0x202A, 0x202F)) + "".join(chr(c) for c in range(0x2066, 0x206A))}

# common Cyrillic / Greek lookalikes -> Latin
_CONFUSABLES = {ord(k): v for k, v in {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
    "к": "k", "м": "m", "т": "t", "н": "h", "в": "b", "ԁ": "d", "ɡ": "g", "ӏ": "l",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "ο": "o", "α": "a", "ε": "e", "ν": "v", "ι": "i", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "Ο": "O", "Α": "A", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ρ": "P", "Τ": "T", "Χ": "X", "Ζ": "Z",
}.items()}

_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){10,}")

MAX_VIEWS = 24
MAX_CHARS = 200_000


def basic_normalize(text: str) -> str:
    """NFKC + strip invisible/control characters (keeps newlines/tabs)."""
    t = unicodedata.normalize("NFKC", text).translate(_INVISIBLE)
    return "".join(ch for ch in t if ch in "\n\t\r" or unicodedata.category(ch) != "Cc")


def fold_confusables(text: str) -> str:
    return text.translate(_CONFUSABLES)


def squash(text: str) -> str:
    """Lowercase alphanumerics only: defeats 'i g n o r e' / 'i.g.n.o.r.e' spacing tricks."""
    return re.sub(r"[\W_]+", "", fold_confusables(text).lower())


def _printable_text(raw: bytes) -> str | None:
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(s) < 8:
        return None
    ok = sum(ch.isprintable() or ch in "\n\t\r" for ch in s)
    return s if ok / len(s) >= 0.9 else None


def _decode_b64(seg: str) -> str | None:
    seg = seg.rstrip("=")
    for alt in (None, b"-_"):
        try:
            raw = base64.b64decode(seg + "=" * (-len(seg) % 4), altchars=alt, validate=True)
        except (binascii.Error, ValueError):
            continue
        s = _printable_text(raw)
        if s:
            return s
    return None


def _decode_hex(seg: str) -> str | None:
    try:
        return _printable_text(bytes.fromhex(seg))
    except ValueError:
        return None


def expand_views(text: str, max_depth: int = 2, include_rot13: bool = False) -> list[tuple[str, str]]:
    """Returns [(view_name, text)], always starting with ('raw', text). Bounded in size and count."""
    text = text[:MAX_CHARS]
    views: list[tuple[str, str]] = [("raw", text)]
    seen = {text}

    def add(name: str, t: str | None) -> bool:
        if t and t not in seen and len(views) < MAX_VIEWS:
            seen.add(t)
            views.append((name, t))
            return True
        return False

    add("normalized", basic_normalize(text))
    frontier = [v for _, v in views]
    for depth in range(max_depth):
        nxt: list[str] = []
        for t in frontier:
            if "%" in t and add("url", unquote(t)):
                nxt.append(unquote(t))
            if "&" in t and add("html", html.unescape(t)):
                nxt.append(html.unescape(t))
            for seg in _B64_RE.findall(t):
                dec = _decode_b64(seg)
                if add(f"base64@{depth + 1}", dec):
                    nxt.append(dec)  # type: ignore[arg-type]
            for seg in _HEX_RE.findall(t):
                dec = _decode_hex(seg)
                if add(f"hex@{depth + 1}", dec):
                    nxt.append(dec)  # type: ignore[arg-type]
        frontier = nxt
        if not frontier:
            break
    if include_rot13:
        add("rot13", codecs.decode(basic_normalize(text), "rot13"))
    return views
