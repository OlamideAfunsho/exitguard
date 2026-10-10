"""Squads v4 account layouts, PDA derivation and decoders.

Written against the v4 program source and checked field by field against the
official SDK's generated decoders (tests/test_parity.py). An account either decodes
under the pinned layout or raises DecodeError with a blocker code. u64 fields come back as decimal strings.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Callable

from solders.pubkey import Pubkey

PROGRAM_ID = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"
DEFAULT_PUBKEY = "11111111111111111111111111111111"
SYSTEM_PROGRAM = DEFAULT_PUBKEY
BPF_UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
ALT_PROGRAM = "AddressLookupTab1e1111111111111111111111111"

PERM_INITIATE, PERM_VOTE, PERM_EXECUTE = 1, 2, 4
PERIODS = ("OneTime", "Day", "Week", "Month")
PROPOSAL_STATUSES = ("Draft", "Active", "Rejected", "Approved", "Executing", "Executed", "Cancelled")
U64_MAX = 2**64 - 1

SEED_PREFIX = b"multisig"


class DecodeError(Exception):
    def __init__(self, code: str, detail: str):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


def account_discriminator(name: str) -> bytes:
    return hashlib.sha256(f"account:{name}".encode()).digest()[:8]


def instruction_discriminator(name: str) -> bytes:
    return hashlib.sha256(f"global:{name}".encode()).digest()[:8]


ACCOUNT_TYPES = (
    "Multisig",
    "SpendingLimit",
    "Proposal",
    "ConfigTransaction",
    "VaultTransaction",
    "Batch",
    "VaultBatchTransaction",
    "ProgramConfig",
)
DISCRIMINATORS = {account_discriminator(n): n for n in ACCOUNT_TYPES}
DISC = {n: d for d, n in DISCRIMINATORS.items()}


# ---------------------------------------------------------------- addresses

def decode_address(text: str) -> bytes:
    """Base58 decode and insist on exactly 32 bytes."""
    if not isinstance(text, str) or not text:
        raise ValueError("address must be a non-empty string")
    try:
        raw = bytes(Pubkey.from_string(text))
    except Exception as exc:  # solders raises several types here
        raise ValueError(f"not a 32-byte base58 address: {text!r}") from exc
    if len(raw) != 32 or str(Pubkey.from_bytes(raw)) != text:
        raise ValueError(f"not a canonical 32-byte base58 address: {text!r}")
    return raw


_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        n = n * 58 + _ALPHABET.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(text) - len(text.lstrip("1"))) + body


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _ALPHABET[rem] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def _pda(seeds: list[bytes], program_id: str) -> str:
    address, _bump = Pubkey.find_program_address(seeds, Pubkey.from_string(program_id))
    return str(address)


def u64_le(value: int) -> bytes:
    if not 0 <= value <= U64_MAX:
        raise ValueError(f"u64 out of range: {value}")
    return struct.pack("<Q", value)


def multisig_pda(create_key: str, program_id: str = PROGRAM_ID) -> str:
    return _pda([SEED_PREFIX, b"multisig", decode_address(create_key)], program_id)


def vault_pda(multisig: str, index: int, program_id: str = PROGRAM_ID) -> str:
    return _pda([SEED_PREFIX, decode_address(multisig), b"vault", bytes([index])], program_id)


def transaction_pda(multisig: str, index: int, program_id: str = PROGRAM_ID) -> str:
    return _pda([SEED_PREFIX, decode_address(multisig), b"transaction", u64_le(index)], program_id)


def proposal_pda(multisig: str, index: int, program_id: str = PROGRAM_ID) -> str:
    return _pda(
        [SEED_PREFIX, decode_address(multisig), b"transaction", u64_le(index), b"proposal"], program_id
    )


def batch_transaction_pda(multisig: str, batch_index: int, child: int, program_id: str = PROGRAM_ID) -> str:
    return _pda(
        [
            SEED_PREFIX,
            decode_address(multisig),
            b"transaction",
            u64_le(batch_index),
            b"batch_transaction",
            struct.pack("<I", child),
        ],
        program_id,
    )


def spending_limit_pda(multisig: str, create_key: str, program_id: str = PROGRAM_ID) -> str:
    return _pda(
        [SEED_PREFIX, decode_address(multisig), b"spending_limit", decode_address(create_key)], program_id
    )


def program_config_pda(program_id: str = PROGRAM_ID) -> str:
    return _pda([SEED_PREFIX, b"program_config"], program_id)


def programdata_address(program_id: str = PROGRAM_ID) -> str:
    return _pda([decode_address(program_id)], BPF_UPGRADEABLE_LOADER)


# ------------------------------------------------------------------- reader

class Reader:
    def __init__(self, data: bytes, offset: int = 0):
        self.data = data
        self.pos = offset

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise DecodeError("ACCOUNT_MALFORMED", f"need {n} bytes at offset {self.pos}, have {self.remaining()}")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def i64(self) -> int:
        return struct.unpack("<q", self.take(8))[0]

    def boolean(self) -> bool:
        v = self.u8()
        if v > 1:
            raise DecodeError("ACCOUNT_MALFORMED", f"bool byte {v} at offset {self.pos - 1}")
        return v == 1

    def pubkey(self) -> str:
        return str(Pubkey.from_bytes(self.take(32)))

    def vec(self, item: Callable[[], object], min_item_size: int) -> list:
        count = self.u32()
        if count * min_item_size > self.remaining():
            raise DecodeError("ACCOUNT_MALFORMED", f"vector of {count} items overruns the buffer")
        return [item() for _ in range(count)]

    def byte_vec(self) -> bytes:
        return self.take(self.u32())

    def option(self, item: Callable[[], object]):
        tag = self.u8()
        if tag == 0:
            return None
        if tag == 1:
            return item()
        raise DecodeError("ACCOUNT_MALFORMED", f"option tag {tag} at offset {self.pos - 1}")

    def expect_end(self) -> None:
        if self.remaining():
            raise DecodeError("ACCOUNT_MALFORMED", f"{self.remaining()} unexpected trailing bytes")


# ----------------------------------------------------------------- decoders

def permission_names(mask: int) -> list[str]:
    names = []
    if mask & PERM_INITIATE:
        names.append("Initiate")
    if mask & PERM_VOTE:
        names.append("Vote")
    if mask & PERM_EXECUTE:
        names.append("Execute")
    return names


def _member(r: Reader) -> dict:
    key = r.pubkey()
    mask = r.u8()
    if mask > 7:
        raise DecodeError("ACCOUNT_UNSUPPORTED", f"permission mask {mask} has unknown bits")
    return {"key": key, "permissions": mask}


def _multisig(r: Reader) -> dict:
    out = {
        "create_key": r.pubkey(),
        "config_authority": r.pubkey(),
        "threshold": r.u16(),
        "time_lock": r.u32(),
        "transaction_index": str(r.u64()),
        "stale_transaction_index": str(r.u64()),
        "rent_collector": r.option(r.pubkey),
        "bump": r.u8(),
        "members": r.vec(lambda: _member(r), 33),
    }
    keys = [m["key"] for m in out["members"]]
    if len(set(keys)) != len(keys):
        raise DecodeError("ACCOUNT_MALFORMED", "duplicate member keys")
    if int(out["stale_transaction_index"]) > int(out["transaction_index"]):
        raise DecodeError("ACCOUNT_MALFORMED", "stale_transaction_index is past transaction_index")
    return out


def _spending_limit(r: Reader) -> dict:
    out = {
        "multisig": r.pubkey(),
        "create_key": r.pubkey(),
        "vault_index": r.u8(),
        "mint": r.pubkey(),
        "amount": str(r.u64()),
    }
    period = r.u8()
    if period >= len(PERIODS):
        raise DecodeError("ACCOUNT_UNSUPPORTED", f"spending limit period {period}")
    out["period"] = PERIODS[period]
    out["remaining_amount"] = str(r.u64())
    out["last_reset"] = str(r.i64())
    out["bump"] = r.u8()
    out["members"] = r.vec(r.pubkey, 32)
    out["destinations"] = r.vec(r.pubkey, 32)
    return out


def _proposal(r: Reader) -> dict:
    out = {"multisig": r.pubkey(), "transaction_index": str(r.u64())}
    tag = r.u8()
    if tag >= len(PROPOSAL_STATUSES):
        raise DecodeError("ACCOUNT_UNSUPPORTED", f"proposal status {tag}")
    out["status"] = PROPOSAL_STATUSES[tag]
    out["status_timestamp"] = None if out["status"] == "Executing" else str(r.i64())
    out["bump"] = r.u8()
    out["approved"] = r.vec(r.pubkey, 32)
    out["rejected"] = r.vec(r.pubkey, 32)
    out["cancelled"] = r.vec(r.pubkey, 32)
    return out


def _config_action(r: Reader) -> dict:
    tag = r.u8()
    if tag == 0:
        m = _member(r)
        return {"kind": "AddMember", "key": m["key"], "permissions": m["permissions"]}
    if tag == 1:
        return {"kind": "RemoveMember", "old_member": r.pubkey()}
    if tag == 2:
        return {"kind": "ChangeThreshold", "new_threshold": r.u16()}
    if tag == 3:
        return {"kind": "SetTimeLock", "new_time_lock": r.u32()}
    if tag == 4:
        out = {
            "kind": "AddSpendingLimit",
            "create_key": r.pubkey(),
            "vault_index": r.u8(),
            "mint": r.pubkey(),
            "amount": str(r.u64()),
        }
        period = r.u8()
        if period >= len(PERIODS):
            raise DecodeError("ACCOUNT_UNSUPPORTED", f"spending limit period {period}")
        out["period"] = PERIODS[period]
        out["members"] = r.vec(r.pubkey, 32)
        out["destinations"] = r.vec(r.pubkey, 32)
        return out
    if tag == 5:
        return {"kind": "RemoveSpendingLimit", "spending_limit": r.pubkey()}
    if tag == 6:
        return {"kind": "SetRentCollector", "new_rent_collector": r.option(r.pubkey)}
    raise DecodeError("ACCOUNT_UNSUPPORTED", f"config action tag {tag}")


def _config_transaction(r: Reader) -> dict:
    return {
        "multisig": r.pubkey(),
        "creator": r.pubkey(),
        "index": str(r.u64()),
        "bump": r.u8(),
        "actions": r.vec(lambda: _config_action(r), 1),
    }


def _message(r: Reader) -> dict:
    def instruction() -> dict:
        return {
            "program_id_index": r.u8(),
            "account_indexes": list(r.byte_vec()),
            "data": r.byte_vec().hex(),
        }

    def lookup() -> dict:
        return {
            "account_key": r.pubkey(),
            "writable_indexes": list(r.byte_vec()),
            "readonly_indexes": list(r.byte_vec()),
        }

    return {
        "num_signers": r.u8(),
        "num_writable_signers": r.u8(),
        "num_writable_non_signers": r.u8(),
        "account_keys": r.vec(r.pubkey, 32),
        "instructions": r.vec(instruction, 9),
        "address_table_lookups": r.vec(lookup, 40),
    }


def _vault_transaction(r: Reader) -> dict:
    return {
        "multisig": r.pubkey(),
        "creator": r.pubkey(),
        "index": str(r.u64()),
        "bump": r.u8(),
        "vault_index": r.u8(),
        "vault_bump": r.u8(),
        "ephemeral_signer_bumps": list(r.byte_vec()),
        "message": _message(r),
    }


def _batch(r: Reader) -> dict:
    out = {
        "multisig": r.pubkey(),
        "creator": r.pubkey(),
        "index": str(r.u64()),
        "bump": r.u8(),
        "vault_index": r.u8(),
        "vault_bump": r.u8(),
        "size": r.u32(),
        "executed_transaction_index": r.u32(),
    }
    if out["executed_transaction_index"] > out["size"]:
        raise DecodeError("ACCOUNT_MALFORMED", "batch executed index is past its size")
    return out


def _vault_batch_transaction(r: Reader) -> dict:
    return {
        "bump": r.u8(),
        "ephemeral_signer_bumps": list(r.byte_vec()),
        "message": _message(r),
    }


def _program_config(r: Reader) -> dict:
    out = {
        "authority": r.pubkey(),
        "multisig_creation_fee": str(r.u64()),
        "treasury": r.pubkey(),
    }
    r.take(64)
    return out


_DECODERS: dict[str, Callable[[Reader], dict]] = {
    "Multisig": _multisig,
    "SpendingLimit": _spending_limit,
    "Proposal": _proposal,
    "ConfigTransaction": _config_transaction,
    "VaultTransaction": _vault_transaction,
    "Batch": _batch,
    "VaultBatchTransaction": _vault_batch_transaction,
    "ProgramConfig": _program_config,
}

TRANSACTION_TYPES = ("ConfigTransaction", "VaultTransaction", "Batch")


def account_type(data: bytes) -> str:
    if len(data) < 8:
        raise DecodeError("ACCOUNT_MALFORMED", f"{len(data)} bytes is too short for a discriminator")
    name = DISCRIMINATORS.get(bytes(data[:8]))
    if name is None:
        raise DecodeError("ACCOUNT_UNSUPPORTED", f"unknown discriminator {bytes(data[:8]).hex()}")
    return name


def decode_account(data: bytes, expect: str | tuple[str, ...] | None = None) -> tuple[str, dict]:
    name = account_type(data)
    if expect is not None:
        allowed = (expect,) if isinstance(expect, str) else expect
        if name not in allowed:
            raise DecodeError("ACCOUNT_UNSUPPORTED", f"expected {' or '.join(allowed)}, found {name}")
    # Bytes past the decoded fields are not checked. The program rewrites an account in place
    # without shrinking it, so after RemoveMember the old last member's bytes are still sitting
    # in the tail of the Multisig account. The program never reads them. They are still covered
    # by the account hash, so a change there shows up as drift.
    return name, _DECODERS[name](Reader(data, 8))


def decode_lookup_table(data: bytes) -> dict:
    """Address lookup table account (owned by the ALT program, not Squads)."""
    if len(data) < 56:
        raise DecodeError("ACCOUNT_MALFORMED", "lookup table shorter than its 56-byte header")
    r = Reader(data)
    if r.u32() != 1:
        raise DecodeError("ACCOUNT_UNSUPPORTED", "lookup table is not initialised")
    deactivation_slot = r.u64()
    last_extended_slot = r.u64()
    r.u8()
    body = data[56:]
    if len(body) % 32:
        raise DecodeError("ACCOUNT_MALFORMED", "lookup table body is not a whole number of addresses")
    return {
        "deactivation_slot": str(deactivation_slot),
        "active": deactivation_slot == U64_MAX,
        "last_extended_slot": str(last_extended_slot),
        "addresses": [str(Pubkey.from_bytes(body[i : i + 32])) for i in range(0, len(body), 32)],
    }


def decode_programdata(data: bytes) -> dict:
    """Upgradeable loader ProgramData header: variant 3, slot, optional authority."""
    if len(data) < 45 or struct.unpack("<I", data[:4])[0] != 3:
        raise DecodeError("ACCOUNT_MALFORMED", "not an upgradeable ProgramData account")
    slot = struct.unpack("<Q", data[4:12])[0]
    authority = str(Pubkey.from_bytes(data[13:45])) if data[12] == 1 else None
    return {"deploy_slot": str(slot), "upgrade_authority": authority, "elf_sha256": hashlib.sha256(data[45:]).hexdigest()}


def decode_program(data: bytes) -> str:
    """Upgradeable loader Program account: variant 2 followed by its ProgramData address."""
    if len(data) != 36 or struct.unpack("<I", data[:4])[0] != 2:
        raise DecodeError("ACCOUNT_MALFORMED", "not an upgradeable Program account")
    return str(Pubkey.from_bytes(data[4:36]))
