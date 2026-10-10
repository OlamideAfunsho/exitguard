"""Solana JSON-RPC adapter.

Reads only. Every account read ends up as a Read with one of three statuses:
present, absent (the node answered and the account is not there) or error
(the node did not give a usable answer). The last two are never merged.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from . import squads

KNOWN_CLUSTERS = {
    "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d": "mainnet-beta",
    "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG": "devnet",
    "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY": "testnet",
}
COMMITMENTS = ("processed", "confirmed", "finalized")
BATCH = 100


def redact(url: str) -> str:
    """Keep scheme and host. API keys live in paths and query strings, so those go."""
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or "unknown-host"
    if parts.port:
        host = f"{host}:{parts.port}"
    hidden = "/<redacted>" if (parts.path.strip("/") or parts.query or parts.username) else ""
    return f"{parts.scheme}://{host}{hidden}"


def account_hash(owner: str, executable: bool, data: bytes) -> str:
    """Digest binding an account's owner, executable flag and data. Lamports are left out."""
    h = hashlib.sha256()
    h.update(b"exitguard.account.v1")
    h.update(squads.decode_address(owner))
    h.update(b"\x01" if executable else b"\x00")
    h.update(data)
    return h.hexdigest()


@dataclass
class Read:
    address: str
    status: str  # present | absent | error
    slot: int | None = None
    owner: str | None = None
    lamports: int | None = None
    executable: bool = False
    data: bytes = b""
    error: str | None = None

    @property
    def sha256(self) -> str | None:
        if self.status != "present":
            return None
        return account_hash(self.owner, self.executable, self.data)

    def mark(self) -> str:
        """What goes into a state fingerprint for this address."""
        if self.status == "present":
            return self.sha256
        return "ABSENT" if self.status == "absent" else "ERROR"


class RpcFailure(Exception):
    pass


@dataclass
class RpcClient:
    url: str
    commitment: str = "finalized"
    timeout: float = 30.0
    retries: int = 3
    min_context_slot: int = 0
    use_min_context_slot: bool = True
    calls: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.commitment not in COMMITMENTS:
            raise ValueError(f"commitment must be one of {COMMITMENTS}")
        self.endpoint = redact(self.url)
        self._id = 0

    # ----------------------------------------------------------- transport

    def _post(self, method: str, params: list) -> dict:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode()
        request = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            raise RpcFailure(f"{method}: HTTP {exc.code} from {self.endpoint}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise RpcFailure(f"{method}: {type(exc).__name__} from {self.endpoint}: {self._clean(str(reason))}") from None
        except json.JSONDecodeError:
            raise RpcFailure(f"{method}: {self.endpoint} did not return JSON") from None

    def _clean(self, text: str) -> str:
        return text.replace(self.url, self.endpoint)

    def call(self, method: str, params: list, slotted: bool = False) -> object:
        """One JSON-RPC call with bounded retries. `slotted` calls carry commitment and minContextSlot."""
        attempt = 0
        while True:
            attempt += 1
            send = list(params)
            if slotted:
                config = dict(send[-1])
                config["commitment"] = self.commitment
                if self.use_min_context_slot and self.min_context_slot:
                    config["minContextSlot"] = self.min_context_slot
                send[-1] = config
            try:
                reply = self._post(method, send)
            except RpcFailure:
                if attempt >= self.retries:
                    raise
                time.sleep(0.4 * attempt)
                continue
            error = reply.get("error")
            if error is None:
                if "result" not in reply:
                    raise RpcFailure(f"{method}: reply has neither result nor error")
                return reply["result"]
            code, message = error.get("code"), self._clean(str(error.get("message", "")))
            if code == -32016 and attempt < self.retries:  # node is behind the slot we already saw
                time.sleep(0.5 * attempt)
                continue
            if slotted and self.use_min_context_slot and code == -32602 and "minContextSlot" in message:
                self.use_min_context_slot = False
                continue
            raise RpcFailure(f"{method}: RPC error {code}: {message}")

    def _note(self, method: str, slot: int | None, count: int) -> None:
        self.calls.append({"method": method, "slot": slot, "items": count})
        if slot is not None and slot > self.min_context_slot:
            self.min_context_slot = slot

    def _context_slot(self, method: str, result: object) -> int:
        try:
            slot = result["context"]["slot"]  # type: ignore[index]
        except (KeyError, TypeError):
            raise RpcFailure(f"{method}: reply carries no context slot") from None
        if not isinstance(slot, int) or slot < self.min_context_slot:
            raise RpcFailure(f"{method}: context slot {slot} is behind slot {self.min_context_slot} already observed")
        return slot

    # --------------------------------------------------------------- reads

    def genesis_hash(self) -> str:
        return str(self.call("getGenesisHash", []))

    def version(self) -> dict:
        result = self.call("getVersion", [])
        return result if isinstance(result, dict) else {}

    def slot(self) -> int:
        slot = self.call("getSlot", [{}], slotted=True)
        if not isinstance(slot, int):
            raise RpcFailure("getSlot: non-integer slot")
        self._note("getSlot", slot, 1)
        return slot

    def latest_blockhash(self) -> str:
        result = self.call("getLatestBlockhash", [{}], slotted=True)
        return result["value"]["blockhash"]  # type: ignore[index]

    def get_multiple(self, addresses: list[str]) -> dict[str, Read]:
        out: dict[str, Read] = {}
        unique = list(dict.fromkeys(addresses))
        for start in range(0, len(unique), BATCH):
            chunk = unique[start : start + BATCH]
            try:
                result = self.call("getMultipleAccounts", [chunk, {"encoding": "base64"}], slotted=True)
                slot = self._context_slot("getMultipleAccounts", result)
                values = result["value"]  # type: ignore[index]
                if not isinstance(values, list) or len(values) != len(chunk):
                    got = len(values) if isinstance(values, list) else "no"
                    raise RpcFailure(f"getMultipleAccounts: asked for {len(chunk)} accounts, got {got}")
            except RpcFailure as exc:
                self._note("getMultipleAccounts", None, len(chunk))
                for address in chunk:
                    out[address] = Read(address, "error", error=str(exc))
                continue
            self._note("getMultipleAccounts", slot, len(chunk))
            for address, value in zip(chunk, values):
                out[address] = _to_read(address, value, slot)
        return out

    def program_accounts(self, program_id: str, filters: list[dict]) -> tuple[int, list[Read]]:
        """getProgramAccounts with context. Raises RpcFailure; the caller decides what that blocks."""
        result = self.call(
            "getProgramAccounts",
            [program_id, {"encoding": "base64", "withContext": True, "filters": filters}],
            slotted=True,
        )
        slot = self._context_slot("getProgramAccounts", result)
        rows = result["value"]  # type: ignore[index]
        if not isinstance(rows, list):
            raise RpcFailure("getProgramAccounts: value is not a list")
        self._note("getProgramAccounts", slot, len(rows))
        reads = []
        for row in rows:
            read = _to_read(row["pubkey"], row["account"], slot)
            if read.status != "present":
                raise RpcFailure(f"getProgramAccounts: unusable row for {row.get('pubkey')}")
            reads.append(read)
        return slot, reads

    def summary(self) -> dict:
        slots = [c["slot"] for c in self.calls if c["slot"] is not None]
        return {
            "endpoint": self.endpoint,
            "commitment": self.commitment,
            "calls": len(self.calls),
            "failed_calls": sum(1 for c in self.calls if c["slot"] is None),
            "slot_first": slots[0] if slots else None,
            "slot_last": max(slots) if slots else None,
            "min_context_slot_used": self.use_min_context_slot,
        }


def _to_read(address: str, value: object, slot: int) -> Read:
    if value is None:
        return Read(address, "absent", slot=slot)
    try:
        data_field = value["data"]  # type: ignore[index]
        if not (isinstance(data_field, list) and len(data_field) == 2 and data_field[1] == "base64"):
            raise ValueError("data is not base64 encoded")
        data = base64.b64decode(data_field[0], validate=True)
        owner = value["owner"]  # type: ignore[index]
        squads.decode_address(owner)
        lamports = value["lamports"]  # type: ignore[index]
        if not isinstance(lamports, int) or lamports < 0:
            raise ValueError("lamports is not an unsigned integer")
        executable = bool(value.get("executable", False))  # type: ignore[union-attr]
    except (KeyError, TypeError, ValueError) as exc:
        return Read(address, "error", slot=slot, error=f"malformed account in RPC reply: {exc}")
    if lamports == 0 and not data:
        return Read(address, "absent", slot=slot)
    return Read(address, "present", slot=slot, owner=owner, lamports=lamports, executable=executable, data=data)


def identify_cluster(client: RpcClient) -> dict:
    genesis = client.genesis_hash()
    version = client.version()
    if version.get("exitguard-simulation") is True:
        name, source = "local-simulation", "LOCAL_SIMULATION"
    elif genesis in KNOWN_CLUSTERS:
        name, source = KNOWN_CLUSTERS[genesis], "LIVE_RPC"
    else:
        name, source = "unrecognised", "UNRECOGNISED_CLUSTER"
    return {
        "genesis_hash": genesis,
        "name": name,
        "evidence_source": source,
        "node_version": str(version.get("solana-core", "unknown")),
    }
