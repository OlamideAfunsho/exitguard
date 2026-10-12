"""Independent checks on what the planner and the SDK worker produced.

Nothing here trusts the packet's own description of itself. Instruction data
is decoded from bytes with a separate Python decoder, account metas are
rebuilt from PDAs derived in Python, and compiled messages are parsed from
their wire format. verify_plan then rereads the chain and explains any drift.
"""

from __future__ import annotations

import base64
import struct

from . import canon, rules, squads
from .blockers import Blocker, sort_unique
from .collector import Collection, collect
from .rpc import RpcClient
from .squads import Reader, instruction_discriminator

PACKET_SCHEMA = "exitguard.packet.v1"
STEPS = ("create", "propose", "approve", "execute")

_DISC = {name: instruction_discriminator(name) for name in (
    "config_transaction_create", "proposal_create", "proposal_approve", "config_transaction_execute")}


def _meta(pubkey: str, signer: bool, writable: bool) -> dict:
    return {"pubkey": pubkey, "is_signer": signer, "is_writable": writable}


def _strict(data: bytes, name: str) -> Reader:
    if data[:8] != _DISC[name]:
        raise squads.DecodeError("ACCOUNT_MALFORMED", f"discriminator is not {name}")
    return Reader(data, 8)


def _option_string(r: Reader) -> str | None:
    return r.option(lambda: r.byte_vec().decode("utf-8"))


def decode_instruction(step: str, data: bytes) -> dict:
    """Decode one of the four instructions a packet may contain. Trailing bytes are an error."""
    if step == "create":
        r = _strict(data, "config_transaction_create")
        actions = r.vec(lambda: squads._config_action(r), 1)
        out = {"actions": actions, "memo": _option_string(r)}
    elif step == "propose":
        r = _strict(data, "proposal_create")
        out = {"transaction_index": str(r.u64()), "draft": r.boolean()}
    elif step == "approve":
        r = _strict(data, "proposal_approve")
        out = {"memo": _option_string(r)}
    elif step == "execute":
        r = _strict(data, "config_transaction_execute")
        out = {}
    else:
        raise squads.DecodeError("ACCOUNT_UNSUPPORTED", f"unexpected step {step}")
    r.expect_end()
    return out


def expected_accounts(tx: dict, step: str, signer: str, program_id: str) -> list[dict]:
    """Account metas the program expects, built from the plan and nothing else."""
    multisig = tx["multisig"]
    index = int(tx["transaction_index"])
    transaction = squads.transaction_pda(multisig, index, program_id)
    proposal = squads.proposal_pda(multisig, index, program_id)
    if step == "create":
        return [_meta(multisig, False, True), _meta(transaction, False, True), _meta(signer, True, False),
                _meta(signer, True, True), _meta(squads.SYSTEM_PROGRAM, False, False)]
    if step == "propose":
        return [_meta(multisig, False, False), _meta(proposal, False, True), _meta(signer, True, False),
                _meta(signer, True, True), _meta(squads.SYSTEM_PROGRAM, False, False)]
    if step == "approve":
        return [_meta(multisig, False, False), _meta(signer, True, True), _meta(proposal, False, True)]
    if step == "execute":
        return [_meta(multisig, False, True), _meta(signer, True, False), _meta(proposal, False, True),
                _meta(transaction, False, False), _meta(signer, True, True), _meta(squads.SYSTEM_PROGRAM, False, False),
                *[_meta(limit, False, True) for limit in tx["spending_limits"]]]
    raise ValueError(step)


def expected_steps(tx: dict) -> list[tuple[str, str]]:
    s = tx["signers"]
    return [("create", s["proposer"]), ("propose", s["proposer"]),
            *[("approve", voter) for voter in s["approvers"]], ("execute", s["executor"])]


def instruction_digest(ix: dict) -> str:
    return canon.digest({"program_id": ix["program_id"], "accounts": ix["accounts"], "data": ix["data"]})


def action_digest(tx: dict) -> str:
    return canon.digest({
        "multisig": tx["multisig"],
        "transaction_index": tx["transaction_index"],
        "actions": tx["actions"],
        "instructions": [[i["step"], i["signer"], instruction_digest(i)] for i in tx["instructions"]],
    })


def check_transaction(tx: dict, program_id: str, subject: str) -> list[str]:
    """Compare a planned transaction's emitted instructions with what its actions require."""
    problems: list[str] = []
    where = f"{tx['multisig']} #{tx['transaction_index']}"

    kinds = [a["kind"] for a in tx["actions"]]
    removals = [a["spending_limit"] for a in tx["actions"] if a["kind"] == "RemoveSpendingLimit"]
    if any(k not in ("RemoveSpendingLimit", "RemoveMember") for k in kinds):
        problems.append(f"{where}: plan contains an action other than RemoveSpendingLimit/RemoveMember")
    if kinds != sorted(kinds, key=lambda k: k != "RemoveSpendingLimit") or kinds.count("RemoveMember") > 1:
        problems.append(f"{where}: actions are not ordered limits first, then at most one RemoveMember")
    if any(a["kind"] == "RemoveMember" and a["old_member"] != subject for a in tx["actions"]):
        problems.append(f"{where}: RemoveMember targets a wallet other than the subject")
    if removals != tx["spending_limits"] or len(set(removals)) != len(removals):
        problems.append(f"{where}: spending limit accounts do not match the RemoveSpendingLimit actions")
    if not tx["actions"]:
        problems.append(f"{where}: transaction has no actions")

    steps = expected_steps(tx)
    if [(i["step"], i["signer"]) for i in tx["instructions"]] != steps:
        problems.append(f"{where}: instruction sequence is not create, propose, approvals, execute")
        return problems

    for ix, (step, signer) in zip(tx["instructions"], steps):
        label = f"{where} {step}"
        if ix["program_id"] != program_id:
            problems.append(f"{label}: targets program {ix['program_id']}")
        if ix["accounts"] != expected_accounts(tx, step, signer, program_id):
            problems.append(f"{label}: account keys, order or signer/writable flags differ from the program's layout")
        try:
            decoded = decode_instruction(step, base64.b64decode(ix["data"], validate=True))
        except (squads.DecodeError, ValueError, UnicodeDecodeError) as exc:
            problems.append(f"{label}: data does not decode ({exc})")
            continue
        if step == "create" and (decoded["actions"] != tx["actions"] or decoded["memo"] is not None):
            problems.append(f"{label}: encoded actions differ from the reviewed actions")
        if step == "propose" and (decoded["transaction_index"] != tx["transaction_index"] or decoded["draft"]):
            problems.append(f"{label}: wrong transaction index or draft flag")
        if step == "approve" and decoded["memo"] is not None:
            problems.append(f"{label}: unexpected memo")
        if ix.get("sha256") != instruction_digest(ix):
            problems.append(f"{label}: instruction digest does not match its bytes")
    if tx.get("action_digest") != action_digest(tx):
        problems.append(f"{where}: action_digest does not match the instructions")
    return problems


def bound_expiries(intent: dict) -> list[dict]:
    """The expiry of every decision, in the form the packet carries under its digest."""
    return [{"id": d["id"], "decision": d["decision"], "expires_at_slot": d["expires_at_slot"]}
            for d in intent["decisions"] if d["decision"] != "UNKNOWN"]


def expiry_blockers(rows: object, slot: int | None, read: str) -> list[Blocker]:
    """Decisions that no longer stand at `slot`. A decision is good strictly before its expiry slot,
    the same boundary certify uses, so nothing can be signed under a decision certify would reject."""
    if not isinstance(rows, list):
        return [Blocker("EXPIRY_INVALID", "packet", "packet carries no decision expiries; plan again with this version")]
    out = []
    for row in rows:
        expiry = row.get("expires_at_slot") if isinstance(row, dict) else None
        subject = str(row.get("id")) if isinstance(row, dict) else "packet"
        if isinstance(expiry, bool) or not isinstance(expiry, int):
            out.append(Blocker("EXPIRY_INVALID", subject, "decision has no integer expiry slot"))
        elif slot is None or expiry <= slot:
            out.append(Blocker("EXPIRY_INVALID", subject,
                               f"decision expired at slot {expiry}; {read} at slot {slot}. Review again."))
    return out


def check_packet(packet: dict) -> list[str]:
    if packet.get("schema_version") != PACKET_SCHEMA:
        return ["packet schema_version is not " + PACKET_SCHEMA]
    if not canon.check_seal(packet, "packet_sha256"):
        return ["packet does not match its packet_sha256"]
    problems: list[str] = []
    seen = set()
    for tx in packet["transactions"]:
        if tx["multisig"] in seen:
            problems.append(f"{tx['multisig']}: more than one transaction planned for one multisig")
        seen.add(tx["multisig"])
        problems += check_transaction(tx, packet["program"]["program_id"], packet["subject"])
    return problems


# ------------------------------------------------------- compiled messages

def _shortvec(data: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated length prefix")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 14:
            raise ValueError("length prefix too long")


def parse_legacy_message(raw: bytes) -> dict:
    """Parse a legacy transaction message from its wire bytes."""
    if len(raw) < 3 or raw[0] & 0x80:
        raise ValueError("not a legacy message")
    required, readonly_signed, readonly_unsigned = raw[0], raw[1], raw[2]
    count, pos = _shortvec(raw, 3)
    keys = []
    for _ in range(count):
        if pos + 32 > len(raw):
            raise ValueError("truncated account keys")
        keys.append(str(squads.Pubkey.from_bytes(raw[pos : pos + 32])))
        pos += 32
    if required > count or readonly_signed > required or readonly_unsigned > count - required:
        raise ValueError("header counts exceed the key list")
    blockhash = str(squads.Pubkey.from_bytes(raw[pos : pos + 32]))
    pos += 32
    n_ix, pos = _shortvec(raw, pos)

    def flags(i: int) -> tuple[bool, bool]:
        signer = i < required
        writable = i < required - readonly_signed if signer else i < count - readonly_unsigned
        return signer, writable

    instructions = []
    for _ in range(n_ix):
        program_index = raw[pos]
        pos += 1
        n_acc, pos = _shortvec(raw, pos)
        indexes = list(raw[pos : pos + n_acc])
        pos += n_acc
        n_data, pos = _shortvec(raw, pos)
        data = raw[pos : pos + n_data]
        pos += n_data
        if pos > len(raw) or program_index >= count or any(i >= count for i in indexes):
            raise ValueError("instruction runs past the message or uses a missing key")
        instructions.append({"program_id": keys[program_index], "indexes": indexes, "data": data})
    if pos != len(raw):
        raise ValueError(f"{len(raw) - pos} trailing bytes after the last instruction")
    return {"keys": keys, "flags": [flags(i) for i in range(count)], "blockhash": blockhash,
            "instructions": instructions, "fee_payer": keys[0] if keys else None}


def check_messages(packet: dict, messages: dict) -> list[str]:
    """Decode every unsigned message and compare it with the packet's stable instructions."""
    problems: list[str] = []
    if messages.get("packet_sha256") != packet["packet_sha256"]:
        return ["messages were built for a different packet"]
    by_tx = {(t["multisig"], t["transaction_index"]): t for t in packet["transactions"]}
    covered: dict[tuple, list[int]] = {}
    for m in messages["messages"]:
        key = (m["multisig"], m["transaction_index"])
        label = f"{m['multisig']} #{m['transaction_index']} message {m['step']}"
        tx = by_tx.get(key)
        if tx is None:
            problems.append(f"{label}: no such planned transaction")
            continue
        try:
            parsed = parse_legacy_message(base64.b64decode(m["message"], validate=True))
        except ValueError as exc:
            problems.append(f"{label}: {exc}")
            continue
        wanted = [tx["instructions"][i] for i in m["instructions"]]
        covered.setdefault(key, []).extend(m["instructions"])
        if parsed["blockhash"] != messages["blockhash"]:
            problems.append(f"{label}: blockhash differs from the one recorded")
        if parsed["fee_payer"] != m["signer"] or any(w["signer"] != m["signer"] for w in wanted):
            problems.append(f"{label}: fee payer is not the expected signer")
        if len(parsed["instructions"]) != len(wanted):
            problems.append(f"{label}: carries {len(parsed['instructions'])} instructions, expected {len(wanted)}")
            continue
        roles: dict[str, list[bool]] = {m["signer"]: [True, True]}
        for got, want in zip(parsed["instructions"], wanted):
            accounts = [parsed["keys"][i] for i in got["indexes"]]
            if (got["program_id"] != want["program_id"] or accounts != [a["pubkey"] for a in want["accounts"]]
                    or got["data"] != base64.b64decode(want["data"])):
                problems.append(f"{label}: instruction bytes or account order differ from the packet")
            roles.setdefault(want["program_id"], [False, False])
            for a in want["accounts"]:
                entry = roles.setdefault(a["pubkey"], [False, False])
                entry[0] = entry[0] or a["is_signer"]
                entry[1] = entry[1] or a["is_writable"]
        got_roles = {k: list(f) for k, f in zip(parsed["keys"], parsed["flags"])}
        if got_roles != roles:
            problems.append(f"{label}: message signer/writable flags or key set differ from the packet")
    for key, tx in by_tx.items():
        if sorted(covered.get(key, [])) != list(range(len(tx["instructions"]))):
            problems.append(f"{key[0]} #{key[1]}: messages do not cover each instruction exactly once")
    return problems


# ------------------------------------------------------------ fresh checks

def _same_except_index(before: dict, after: dict) -> bool:
    drop = ("transaction_index",)
    return {k: v for k, v in before.items() if k not in drop} == {k: v for k, v in after.items() if k not in drop}


def verify_plan(client: RpcClient, packet: dict) -> dict:
    """Reread the declared scope and decide whether the packet still describes reality."""
    reasons: list[Blocker] = [Blocker("PACKET_DECODE_MISMATCH", "packet", p) for p in check_packet(packet)]
    if reasons and not canon.check_seal(packet, "packet_sha256"):
        return {"verdict": "PLAN_INVALIDATED", "reasons": [Blocker("PACKET_TAMPERED", "packet", r.detail).to_json() for r in reasons],
                "phases": [], "read": None}

    col: Collection = collect(client, packet["scope"])
    reasons += col.blockers
    if col.cluster.get("genesis_hash") != packet["cluster"]["genesis_hash"]:
        reasons.append(Blocker("CLUSTER_MISMATCH", client.endpoint, "genesis hash differs from the reviewed cluster"))

    # The operator's decisions are only good for a while. Unchanged accounts do not extend them.
    reasons += expiry_blockers(packet.get("decision_expiries"), col.rpc.get("slot_last"), "fresh state was read")

    before = packet["preconditions"]["accounts"]
    after = col.fingerprint()
    program_id = packet["program"]["program_id"]
    explained: set[str] = set()
    phases = []

    for tx in packet["transactions"]:
        ms, index = tx["multisig"], int(tx["transaction_index"])
        state = col.multisigs.get(ms)
        phase = "UNKNOWN"
        if state is None:
            phases.append({"multisig": ms, "transaction_index": tx["transaction_index"], "phase": phase})
            continue
        current = int(state["transaction_index"])
        if after.get(ms) == before.get(ms):
            phase = "READY_TO_CREATE"
        elif current < index:
            pass   # multisig changed without advancing; reported as drift below
        else:
            slot = col.slots[ms][index - 1]
            ours = (slot.tx_type == "ConfigTransaction" and slot.tx["creator"] == tx["signers"]["proposer"]
                    and slot.tx["actions"] == tx["actions"])
            status = slot.proposal["status"] if slot.proposal else None
            if not ours or current > index:
                reasons.append(Blocker("INDEX_COLLISION", ms,
                                       f"transaction index {index} was taken or passed by another transaction; scan and plan again"))
            elif status in ("Rejected", "Cancelled"):
                reasons.append(Blocker("REVIEW_DRIFT", slot.proposal_address, f"the remediation proposal was {status.lower()}"))
            elif status == "Executed":
                phase = "EXECUTED"
                explained.update({ms, slot.transaction_address, slot.proposal_address, *tx["spending_limits"]})
            else:
                reviewed = squads.decode_account(
                    base64.b64decode(packet["preconditions"]["multisig_data"][ms]), "Multisig")[1]
                if _same_except_index(reviewed, state):
                    explained.update({ms, slot.transaction_address, slot.proposal_address})
                    phase = {None: "CREATED_NOT_PROPOSED", "Draft": "CREATED_NOT_PROPOSED", "Active": "AWAITING_APPROVAL",
                             "Approved": "READY_TO_EXECUTE"}.get(status, "UNKNOWN")
        phases.append({"multisig": ms, "transaction_index": tx["transaction_index"], "phase": phase})

    executed = any(p["phase"] == "EXECUTED" for p in phases)
    for address in sorted(set(before) | set(after)):
        if address in explained or before.get(address) == after.get(address):
            continue
        role = col.roles.get(address, "account")
        if role in ("program", "programdata"):
            reasons.append(Blocker("PROGRAM_DRIFT", address, f"{role} changed since the review"))
        elif address not in before:
            reasons.append(Blocker("NEW_DEPENDENCY", address, f"{role} was not part of the review"))
        elif before[address] == "ABSENT" and role.startswith("proposal:"):
            reasons.append(Blocker("PROPOSAL_APPEARED", address,
                                   f"proposal #{role.rsplit(':', 1)[1]} was absent at review and now exists"))
        elif address not in after:
            if executed:
                continue   # executing a config change makes older pending items stale, so their dependencies drop out
            reasons.append(Blocker("REVIEW_DRIFT", address, "account is no longer part of the dependency set"))
        else:
            reasons.append(Blocker("REVIEW_DRIFT", address, f"{role} changed since the review"))

    reasons = sort_unique(reasons)
    return {
        "verdict": "PLAN_INVALIDATED" if reasons else (
            "EXECUTED" if phases and all(p["phase"] == "EXECUTED" for p in phases) else "VALID"),
        "reasons": [r.to_json() for r in reasons],
        "phases": phases,
        "read": {**col.rpc, "passes": col.passes, "state_digest": col.state_digest()},
        "cluster": col.cluster,
    }
