"""Bridge to the Node SDK worker (sdk-worker/worker.js).

The worker is started once per process and fed one JSON document per line.
"""

from __future__ import annotations

import atexit
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

WORKER_DIR = Path(__file__).resolve().parent.parent / "sdk-worker"

_lock = threading.Lock()
_process: subprocess.Popen | None = None


class WorkerError(Exception):
    pass


def _node() -> str:
    node = os.environ.get("EXITGUARD_NODE") or shutil.which("node")
    if not node:
        raise WorkerError("node was not found on PATH; install Node 22 or later")
    return node


def _start() -> subprocess.Popen:
    if not (WORKER_DIR / "node_modules" / "@sqds" / "multisig").is_dir():
        raise WorkerError(f"SDK is not installed; run `npm ci` in {WORKER_DIR}")
    return subprocess.Popen(
        [_node(), str(WORKER_DIR / "worker.js"), "--serve"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=str(WORKER_DIR),
    )


def close() -> None:
    global _process
    with _lock:
        if _process is not None:
            try:
                _process.stdin.close()
                _process.wait(timeout=5)
            except Exception:
                _process.kill()
            _process = None


atexit.register(close)


def call(requests: list[dict]) -> list:
    """Run a batch of worker ops and return their values in order."""
    global _process
    line = (json.dumps({"requests": requests}) + "\n").encode()
    with _lock:
        if _process is None or _process.poll() is not None:
            _process = _start()
        try:
            _process.stdin.write(line)
            _process.stdin.flush()
            reply = _process.stdout.readline()
        except OSError as exc:
            _process = None
            raise WorkerError(f"lost the SDK worker: {exc}") from None
        if not reply:
            _process = None
            raise WorkerError("the SDK worker exited without answering")
    try:
        out = json.loads(reply)
    except json.JSONDecodeError:
        raise WorkerError("the SDK worker wrote invalid JSON") from None
    if "fatal" in out:
        raise WorkerError(out["fatal"])
    results = out.get("results")
    if not isinstance(results, list) or len(results) != len(requests):
        raise WorkerError("the SDK worker answered a different number of requests than it was sent")
    values = []
    for item in results:
        if not item.get("ok"):
            raise WorkerError(item.get("error", "unknown worker error"))
        values.append(item["value"])
    return values


def one(op: str, args: dict | None = None):
    return call([{"op": op, "args": args or {}}])[0]
