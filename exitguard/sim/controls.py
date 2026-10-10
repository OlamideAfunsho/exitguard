"""Negative controls: situations where ExitGuard must refuse.

Each control builds a fresh world, breaks one thing, runs the real commands
and reports which blocker codes came back and whether any clean output was
published. The demo prints them; the tests assert on them.
"""

from __future__ import annotations

import base64
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .. import canon, squads, verifier
from .session import Session
from .world import SOL, World, address, lookup_table_bytes


@dataclass
class Outcome:
    codes: set[str]
    published: list[str]   # clean outputs that exist but should not


@dataclass
class Control:
    key: str
    stage: str
    title: str
    expect: str
    run: Callable[[Path], Outcome]


def _published(s: Session, *names: str) -> list[str]:
    return [n for n in names if Path(s.path(n)).exists()]


def _scan_control(mutate: Callable[[World], None]) -> Callable[[Path], Outcome]:
    def run(tmp: Path) -> Outcome:
        world = World()
        mutate(world)
        s = Session(world, tmp)
        try:
            s.scan()
            codes = s.codes("review")
            s.decide() if codes else None     # an incomplete review must not turn into an intent
            return Outcome(codes, _published(s, "intent", "packet", "record"))
        finally:
            s.close()
    return run


def _patch_first_payment_index(world: World) -> None:
    """Point the payment's destination at key index 9 of a three-key message."""
    pda = squads.transaction_pda(world.grants, 1)
    data = bytearray(world.chain.account(pda).data)
    needle = struct.pack("<I", 2) + b"\x00\x01" + struct.pack("<I", 12)
    at = bytes(data).index(needle)
    data[at + 5] = 9
    world.chain.set_account(pda, bytes(data), squads.PROGRAM_ID)


def _truncate_limit(world: World) -> None:
    pda = world.limits["dana-ops"]
    world.chain.set_account(pda, bytes(world.chain.account(pda).data)[:140], squads.PROGRAM_ID)


def _foreign_owner(world: World) -> None:
    data = bytes(world.chain.account(world.grants).data)
    world.chain.set_account(world.grants, data, address("some-other-program"))


def _short_rpc_reply(world: World) -> None:
    world.chain.faults["getMultipleAccounts"] = lambda result: {**result, "value": result["value"][:-1]}


def _policy_control(expect: str, **world_kwargs) -> Callable[[Path], Outcome]:
    def run(tmp: Path) -> Outcome:
        s = Session(World(**world_kwargs), tmp)
        try:
            s.through_plan()
            review = canon.load(s.path("review"))
            row_codes = {b["code"] for a in review["authorities"] for b in a["blockers"]}
            s.execute()
            s.certify()
            return Outcome(row_codes | s.codes("record"), _published(s, "record"))
        finally:
            s.close()
    return run


def _stale_control(mutate: Callable[[World, Session], None]) -> Callable[[Path], Outcome]:
    def run(tmp: Path) -> Outcome:
        world = World()
        s = Session(world, tmp)
        try:
            s.through_plan()
            mutate(world, s)
            s.verify()
            return Outcome(s.codes("messages"), _published(s, "messages"))
        finally:
            s.close()
    return run


def _replace_limit_state(world: World, _s: Session) -> None:
    """Same address, different contents: the allowance is raised behind the reviewer's back."""
    pda = world.limits["dana-ops"]
    data = bytearray(world.chain.account(pda).data)
    data[105:113] = struct.pack("<Q", 40 * SOL)
    world.chain.set_account(pda, bytes(data), squads.PROGRAM_ID)


def _late_proposal(world: World, _s: Session) -> None:
    """dana proposes the payment dana created earlier. The multisig account does not change at all."""
    world.propose(world.grants, 4, "dana")


def _forge_packet(world: World, s: Session) -> None:
    """Swap the member being removed inside the instruction bytes, then recompute every digest."""
    packet = canon.load(s.path("packet"))
    tx = packet["transactions"][0]
    create = tx["instructions"][0]
    data = base64.b64decode(create["data"])
    forged = data.replace(squads.decode_address(world.subject), squads.decode_address(address("bayo")))
    create["data"] = base64.b64encode(forged).decode()
    create["sha256"] = verifier.instruction_digest(create)
    tx["action_digest"] = verifier.action_digest(tx)
    canon.write(s.path("packet"), canon.seal(packet, "packet_sha256"))


def _certify_control(after: Callable[[World, Session], None] | None = None, execute: bool = True,
                     before: Callable[[World], None] | None = None, commitment: str = "finalized",
                     **decide_kwargs) -> Callable[[Path], Outcome]:
    def run(tmp: Path) -> Outcome:
        world = World()
        if before:
            before(world)
        s = Session(world, tmp)
        try:
            s.through_plan(**decide_kwargs)
            if execute:
                s.execute()
            if after:
                after(world, s)
            s.certify(commitment=commitment)
            return Outcome(s.codes("record"), _published(s, "record"))
        finally:
            s.close()
    return run


def _lower_threshold(world: World, _s: Session) -> None:
    world.config_transaction(world.operations, [{"kind": "ChangeThreshold", "newThreshold": 1}])


def _member_only_removal(world: World, _s: Session) -> None:
    for ms in (world.operations, world.grants):
        world.config_transaction(ms, [{"kind": "RemoveMember", "oldMember": world.subject}])


def _upgrade_program(world: World, _s: Session) -> None:
    pda = squads.programdata_address()
    data = bytearray(world.chain.account(pda).data)
    data[4:12] = struct.pack("<Q", struct.unpack("<Q", data[4:12])[0] + 1)
    world.chain.set_account(pda, bytes(data), squads.BPF_UPGRADEABLE_LOADER, lamports=10_240_000_000)


def _new_approved_payment(world: World, _s: Session) -> None:
    index = world.vault_transaction(world.operations, "bayo", world.payees["vendor"], SOL)
    world.propose(world.operations, index, "bayo", ("ada", "bayo"))


def _hide_simulation(world: World) -> None:
    world.chain.identifies_as_simulation = False


CONTROLS: list[Control] = [
    Control("alt-missing", "scan", "lookup table used by a live payment is gone", "ALT_MISSING",
            _scan_control(lambda w: w.chain.delete_account(w.lookup_table))),
    Control("batch-child-missing", "scan", "approved batch is missing a remaining child", "BATCH_CHILD_MISSING",
            _scan_control(lambda w: w.chain.delete_account(squads.batch_transaction_pda(w.grants, 3, 2)))),
    Control("alt-index", "scan", "lookup index points past the end of its table", "ALT_INDEX_OUT_OF_RANGE",
            _scan_control(lambda w: w.chain.set_account(w.lookup_table, lookup_table_bytes([]), squads.ALT_PROGRAM))),
    Control("key-index", "scan", "instruction uses a key index that does not exist", "MESSAGE_INDEX_OUT_OF_RANGE",
            _scan_control(_patch_first_payment_index)),
    Control("malformed", "scan", "spending limit account is truncated", "ACCOUNT_MALFORMED", _scan_control(_truncate_limit)),
    Control("foreign-owner", "scan", "declared multisig is owned by another program", "ACCOUNT_FOREIGN_OWNER",
            _scan_control(_foreign_owner)),
    Control("rpc-short", "scan", "RPC returns fewer accounts than requested", "RPC_INCOMPLETE_RESULT",
            _scan_control(_short_rpc_reply)),
    Control("shared-limit", "policy", "subject shares a spending limit with someone else", "SHARED_SPENDING_LIMIT",
            _policy_control("SHARED_SPENDING_LIMIT", shared_limit=True)),
    Control("controlled", "policy", "multisig has a non-default config authority", "CONTROLLED_MULTISIG",
            _policy_control("CONTROLLED_MULTISIG", controlled=True)),
    Control("same-pda", "verify-plan", "limit rewritten at the same address after review", "REVIEW_DRIFT",
            _stale_control(_replace_limit_state)),
    Control("late-proposal", "verify-plan", "absent proposal created, parent index unchanged", "PROPOSAL_APPEARED",
            _stale_control(_late_proposal)),
    Control("forged-packet", "verify-plan", "packet bytes altered and every digest recomputed", "PACKET_DECODE_MISMATCH",
            _stale_control(_forge_packet)),
    Control("post-drift", "certify", "threshold lowered after execution", "RETAINED_STATE_CHANGED",
            _certify_control(_lower_threshold)),
    Control("still-delegate", "certify", "only the member was removed, limit left behind", "SUBJECT_STILL_DELEGATE",
            _certify_control(_member_only_removal, execute=False)),
    Control("program-upgrade", "certify", "Squads ProgramData changed after review", "PROGRAM_DRIFT",
            _certify_control(_upgrade_program)),
    Control("new-residual", "certify", "new approved payment with no decision", "RESIDUAL_UNDECIDED",
            _certify_control(_new_approved_payment)),
    Control("not-finalized", "certify", "live-looking node read at confirmed", "NOT_FINALIZED",
            _certify_control(before=_hide_simulation, commitment="confirmed")),
    Control("expired", "certify", "decisions expired before certification", "EXPIRY_INVALID",
            _certify_control(expires_in=3)),
]
