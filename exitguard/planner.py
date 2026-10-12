"""Build the unsigned remediation packet.

One config transaction per multisig: every RemoveSpendingLimit first, then
RemoveMember. Instructions come from the official SDK through the worker and
are decoded back by verifier.py before the packet is sealed. Nothing is
signed or sent here.
"""

from __future__ import annotations

import base64

from . import TOOL, canon, rules, sdkworker, squads, verifier
from . import intent as intent_mod
from .blockers import Blocker, ExitGuardError
from .collector import collect
from .rpc import RpcClient

MESSAGES_SCHEMA = "exitguard.messages.v1"
PLACEHOLDER_BLOCKHASH = squads.DEFAULT_PUBKEY


def _pick(candidates: list[str], wanted: str | None, role: str, multisig: str) -> str:
    if wanted is not None:
        if wanted not in candidates:
            raise ExitGuardError(Blocker("NO_ELIGIBLE_SIGNER", multisig, f"{wanted} cannot act as {role} here"))
        return wanted
    if not candidates:
        raise ExitGuardError(Blocker("NO_ELIGIBLE_SIGNER", multisig, f"no remaining member can act as {role}"))
    return candidates[0]


def _instructions(tx: dict, program_id: str) -> list[dict]:
    base = {"multisig": tx["multisig"], "transactionIndex": tx["transaction_index"], "programId": program_id}
    signers = tx["signers"]
    actions = [
        {"kind": a["kind"], "spendingLimit": a["spending_limit"]} if a["kind"] == "RemoveSpendingLimit"
        else {"kind": a["kind"], "oldMember": a["old_member"]}
        for a in tx["actions"]
    ]
    requests = [
        {"op": "configTransactionCreate", "args": {**base, "creator": signers["proposer"],
                                                   "rentPayer": signers["proposer"], "actions": actions}},
        {"op": "proposalCreate", "args": {**base, "creator": signers["proposer"], "rentPayer": signers["proposer"]}},
        *[{"op": "proposalApprove", "args": {**base, "member": voter}} for voter in signers["approvers"]],
        {"op": "configTransactionExecute", "args": {**base, "member": signers["executor"],
                                                    "rentPayer": signers["executor"],
                                                    "spendingLimits": tx["spending_limits"]}},
    ]
    built = sdkworker.call(requests)
    out = []
    for (step, signer), ix in zip(verifier.expected_steps(tx), built):
        entry = {"step": step, "signer": signer, **ix}
        entry["sha256"] = verifier.instruction_digest(entry)
        out.append(entry)
    return out


def plan(client: RpcClient, review: dict, intent: dict, proposer: str | None = None,
         executor: str | None = None) -> dict:
    intent_mod.check_binding(review, intent)
    scope = review["scope"]
    subject = review["subject"]
    program_id = scope["squads_program_id"]
    decisions = intent_mod.by_id(intent)

    unknown = [Blocker("DECISION_UNKNOWN", d["id"], "decide KEEP, REVOKE or BLOCKED before planning")
               for d in intent["decisions"] if d["decision"] == "UNKNOWN"]
    if unknown:
        raise ExitGuardError(unknown)

    # Fresh state. The index and every precondition come from this read, not from the review file.
    col = collect(client, scope)
    problems = list(col.blockers)
    if col.cluster.get("genesis_hash") != review["cluster"]["genesis_hash"]:
        problems.append(Blocker("CLUSTER_MISMATCH", client.endpoint, "genesis hash differs from the reviewed cluster"))
    reviewed = {a: (row["sha256"] if row["status"] == "present" else row["status"].upper())
                for a, row in review["coverage"]["accounts"].items()}
    fresh = col.fingerprint()
    for address in sorted(set(reviewed) | set(fresh)):
        if reviewed.get(address) != fresh.get(address):
            role = col.roles.get(address, review["coverage"]["accounts"].get(address, {}).get("role", "account"))
            code = "PROGRAM_DRIFT" if role in ("program", "programdata") else (
                "PROPOSAL_APPEARED" if reviewed.get(address) == "ABSENT" and role.startswith("proposal:") else "REVIEW_DRIFT")
            problems.append(Blocker(code, address, f"{role} differs from the reviewed state; scan and review again"))
    expiries = verifier.bound_expiries(intent)
    problems += verifier.expiry_blockers(expiries, col.rpc.get("slot_last"), "fresh state was read")
    if problems:
        raise ExitGuardError(problems, verdict="PLAN_REFUSED")

    transactions, not_planned = [], []
    for row in review["authorities"]:
        decision = decisions[row["authority_id"]]["decision"]
        if decision != "REVOKE":
            not_planned.append({"id": row["authority_id"], "decision": decision,
                                "why": [b["code"] for b in row["blockers"]] or ["operator decision"]})
    for row in review["residuals"]:
        not_planned.append({"id": row["residual_id"], "decision": decisions[row["residual_id"]]["decision"],
                            "why": ["residual actions are resolved through normal Squads governance"]})

    for resource in review["resources"]:
        ms = resource["state_address"]
        revoke = [r for r in review["authorities"]
                  if r["multisig"] == ms and decisions[r["authority_id"]]["decision"] == "REVOKE"]
        if not revoke:
            continue
        state = col.multisigs[ms]
        limits = sorted(r["address"] for r in revoke if r["kind"] == "limit")
        remove_member = any(r["kind"] == "member" for r in revoke)
        if remove_member:
            failed = rules.removal_problems(state, subject)
            if failed:
                raise ExitGuardError([Blocker(code, ms, detail) for code, detail in failed])
        roles = rules.signing_roles(state, subject)
        if len(roles["voters"]) < state["threshold"]:
            raise ExitGuardError(Blocker("NO_ELIGIBLE_SIGNER", ms, "not enough voters besides the subject to reach threshold"))
        index = int(state["transaction_index"]) + 1
        tx = {
            "multisig": ms,
            "label": resource.get("label", ""),
            "transaction_index": str(index),
            "transaction_address": squads.transaction_pda(ms, index, program_id),
            "proposal_address": squads.proposal_pda(ms, index, program_id),
            "actions": [{"kind": "RemoveSpendingLimit", "spending_limit": a} for a in limits]
                       + ([{"kind": "RemoveMember", "old_member": subject}] if remove_member else []),
            "spending_limits": limits,
            "signers": {
                "proposer": _pick(roles["proposers"], proposer, "proposer", ms),
                "approvers": roles["voters"],
                "approvals_required": state["threshold"],
                "executor": _pick(roles["executors"], executor, "executor", ms),
                "time_lock_seconds": state["time_lock"],
            },
            "revokes": sorted(r["authority_id"] for r in revoke),
        }
        tx["instructions"] = _instructions(tx, program_id)
        tx["action_digest"] = verifier.action_digest(tx)
        transactions.append(tx)

    packet = {
        "schema_version": verifier.PACKET_SCHEMA,
        "tool": TOOL,
        "organization_id": scope["organization_id"],
        "review_id": scope["review_id"],
        "subject": subject,
        "scope": scope,
        "scope_sha256": review["scope_sha256"],
        "review_sha256": review["review_sha256"],
        "intent_sha256": intent["intent_sha256"],
        "cluster": col.cluster,
        "program": col.program,
        "sdk": sdkworker.one("versions"),
        "preconditions": {
            "state_digest": col.state_digest(),
            "read": {**col.rpc, "passes": col.passes},
            "accounts": fresh,
            "multisig_data": {ms: base64.b64encode(col.reads[ms].data).decode() for ms in sorted(col.multisigs)},
        },
        "decision_expiries": expiries,
        "expires_at_slot": min(e["expires_at_slot"] for e in expiries) if expiries else None,
        "transactions": transactions,
        "not_planned": not_planned,
        "execution": {
            "signing": "external",
            "note": "ExitGuard holds no keys. Members approve and execute these instructions with their usual "
                    "Squads tooling. Signers must keep instruction bytes and account metas exactly as reviewed.",
        },
        "executor_bypass": True,
    }
    packet = canon.seal(packet, "packet_sha256")
    mismatches = verifier.check_packet(packet)
    if mismatches:
        raise ExitGuardError([Blocker("PACKET_DECODE_MISMATCH", "packet", m) for m in mismatches], verdict="PLAN_REFUSED")
    return packet


def build_messages(packet: dict, blockhash: str = PLACEHOLDER_BLOCKHASH, source: str = "placeholder",
                   slot: int | None = None) -> dict:
    """Compile unsigned legacy messages for each signing step, then decode them back."""
    requests, entries = [], []
    for tx in packet["transactions"]:
        groups: list[tuple[str, list[int]]] = [("create", [0, 1])]
        groups += [(f"approve:{ix['signer']}", [n]) for n, ix in enumerate(tx["instructions"]) if ix["step"] == "approve"]
        groups.append(("execute", [len(tx["instructions"]) - 1]))
        for step, indexes in groups:
            chosen = [tx["instructions"][i] for i in indexes]
            requests.append({"op": "compileMessage", "args": {
                "payer": chosen[0]["signer"],
                "recentBlockhash": blockhash,
                "instructions": [{k: ix[k] for k in ("program_id", "accounts", "data")} for ix in chosen],
            }})
            entries.append({"multisig": tx["multisig"], "transaction_index": tx["transaction_index"], "step": step,
                            "signer": chosen[0]["signer"], "instructions": indexes})
    compiled = sdkworker.call(requests) if requests else []
    for entry, result in zip(entries, compiled):
        entry["message"] = result["message"]
        entry["sha256"] = canon.sha256_hex(base64.b64decode(result["message"]))
    messages = {
        "schema_version": MESSAGES_SCHEMA,
        "packet_sha256": packet["packet_sha256"],
        "blockhash": blockhash,
        "blockhash_source": source,
        "blockhash_slot": slot,
        "expires": "with the blockhash; rebuild with verify-plan --messages before signing",
        "messages": entries,
    }
    mismatches = verifier.check_messages(packet, messages)
    if mismatches:
        raise ExitGuardError([Blocker("PACKET_DECODE_MISMATCH", "messages", m) for m in mismatches], verdict="PLAN_REFUSED")
    return messages
