"""Canonical JSON and digests.

Rules, also written up in docs/FORMATS.md:

  * UTF-8, object keys sorted by code point, no insignificant whitespace
  * strings, booleans, null, lists, objects and small integers only
  * no floats anywhere; u64 quantities travel as decimal strings
  * a document's digest is SHA-256 over those bytes with its own digest
    field removed
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

MAX_SAFE_INT = 2**53 - 1


def _check(value: Any, path: str) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise ValueError(f"{path}: integer {value} must be carried as a decimal string")
        return
    if isinstance(value, float):
        raise ValueError(f"{path}: floats are not allowed in canonical JSON")
    if isinstance(value, list):
        for n, item in enumerate(value):
            _check(item, f"{path}[{n}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path}: non-string key {key!r}")
            _check(item, f"{path}.{key}")
        return
    raise ValueError(f"{path}: unsupported type {type(value).__name__}")


def dumps(value: Any) -> bytes:
    _check(value, "$")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: Any, exclude: str | None = None) -> str:
    if exclude is not None and isinstance(value, dict) and exclude in value:
        value = {k: v for k, v in value.items() if k != exclude}
    return sha256_hex(dumps(value))


def seal(document: dict, field: str) -> dict:
    """Return the document with its digest stored under `field`."""
    out = {k: v for k, v in document.items() if k != field}
    out[field] = digest(out)
    return out


def check_seal(document: dict, field: str) -> bool:
    return isinstance(document.get(field), str) and digest(document, exclude=field) == document[field]


def write(path: str | Path, document: Any) -> None:
    """Write pretty-printed JSON. The digest is always over the canonical form."""
    _check(document, "$")
    text = json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    Path(path).write_text(text, encoding="utf-8", newline="\n")


def load(path: str | Path) -> Any:
    def no_float(text: str):
        raise ValueError(f"float literal {text} in {path}")

    return json.loads(Path(path).read_text(encoding="utf-8"), parse_float=no_float)
