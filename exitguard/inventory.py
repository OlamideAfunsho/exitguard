"""Turn a collection into the review document an operator decides on."""

from __future__ import annotations

import base64
import struct

from . import TOOL, canon, rules, squads
from . import scope as scope_mod
from .blockers import Blocker, sort_unique
from .collector import Collection, Slot

SCHEMA = "exitguard.review.v1"
LAMPORTS_PER_SOL = 1_000_000_000
COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111"


def sol(lamports: int | str) -> str:
    whole, frac = divmod(int(lamports), LAMPORTS_PER_SOL)
    text = f"{frac:09d}".rstrip("0")
    return f"{whole}.{text}" if text else str(whole)


def resolve_message(message: dict, tables: dict[str, dict], where: str, blockers: list[Blocker]) -> dict:
    """Expand a stored Squads message into instructions with full keys and roles.

    Key order follows the v0 rule: static keys, then every writable lookup
    address in table order, then every readonly one. Anything that points
    outside what exists is a blocker, not a guess.
    """
    static = message["account_keys"]
    signers, w_signers, w_others = (
        message["num_signers"], message["num_writable_signers"], message["num_writable_non_signers"]
    )
    if signers > len(static) or w_signers > signers or w_others > len(static) - signers:
        blockers.append(Blocker("MESSAGE_INDEX_OUT_OF_RANGE", where, "message header counts exceed its static keys"))
        return {"resolved": False, "instructions": [], "keys": []}

    keys = [
        {
            "pubkey": key,
            "signer": i < signers,
            "writable": i < w_signers or signers <= i < signers + w_others,
            "source": "static",
        }
        for i, key in enumerate(static)
    ]
    complete = True
    for writable, field in ((True, "writable_indexes"), (False, "readonly_indexes")):
        for lookup in message["address_table_lookups"]:
            table = tables.get(lookup["account_key"])
            if table is None:
                complete = False   # the collector already raised ALT_MISSING or a decode blocker
                continue
            for index in lookup[field]:
                if index >= len(table["addresses"]):
                    blockers.append(Blocker(
                        "ALT_INDEX_OUT_OF_RANGE", where,
                        f"index {index} is past the {len(table['addresses'])} addresses in {lookup['account_key']}"))
                    complete = False
                    continue
                keys.append({"pubkey": table["addresses"][index], "signer": False, "writable": writable,
                             "source": f"lookup:{lookup['account_key']}:{index}"})

    instructions = []
    if complete:
        for n, ix in enumerate(message["instructions"]):
            wanted = [ix["program_id_index"], *ix["account_indexes"]]
            if any(i >= len(keys) for i in wanted):
                blockers.append(Blocker("MESSAGE_INDEX_OUT_OF_RANGE", where,
                                        f"instruction {n} uses key index {max(wanted)} of {len(keys)}"))
                complete = False
                continue
            program = keys[ix["program_id_index"]]["pubkey"]
            accounts = [keys[i] for i in ix["account_indexes"]]
            instructions.append({
                "program_id": program,
                "accounts": accounts,
                "data_hex": ix["data"],
                "summary": _summarise(program, accounts, bytes.fromhex(ix["data"])),
            })
    return {"resolved": complete, "instructions": instructions if complete else [], "keys": keys}


def _summarise(program: str, accounts: list[dict], data: bytes) -> str:
    if program == squads.SYSTEM_PROGRAM and len(data) == 12 and struct.unpack("<I", data[:4])[0] == 2 and len(accounts) >= 2:
        lamports = struct.unpack("<Q", data[4:])[0]
        return f"pay {sol(lamports)} SOL to {accounts[1]['pubkey'][:4]}..{accounts[1]['pubkey'][-4:]}"
    if program == COMPUTE_BUDGET:
        return "compute budget setting"
    return f"call to {program[:4]}..{program[-4:]} with {len(accounts)} accounts, {len(data)} data bytes (not interpreted)"


def _join(instructions: list[dict]) -> str:
    """One line for a payload; budget settings are dropped when there is anything else to say."""
    parts = [i["summary"] for i in instructions if i["program_id"] != COMPUTE_BUDGET]
    return "; ".join(parts or [i["summary"] for i in instructions])


def _residual(col: Collection, multisig: str, slot: Slot, subject: str, blockers: list[Blocker]) -> dict:
    reads = col.reads
    involvement = []
    restores = False
    payloads = []
    if slot.tx["creator"] == subject:
        involvement.append("created by the subject")
    if slot.proposal and subject in slot.proposal["approved"]:
        involvement.append("approved by the subject")

    entry: dict = {
        "residual_id": f"proposal:{slot.proposal_address}",
        "multisig": multisig,
        "transaction_index": str(slot.index),
        "transaction_address": slot.transaction_address,
        "proposal_address": slot.proposal_address,
        "type": slot.tx_type,
        "state": slot.state,
        "proposal_status": slot.proposal["status"] if slot.proposal else None,
        "approved_by": slot.proposal["approved"] if slot.proposal else [],
        "payload_sha256": reads[slot.transaction_address].sha256,
        "children": [],
        "lookup_tables": [
            {"address": a, "sha256": reads[a].sha256} for a in slot.lookup_tables if reads[a].status == "present"
        ],
    }

    if slot.tx_type == "ConfigTransaction":
        entry["actions"] = slot.tx["actions"]
        for action in slot.tx["actions"]:
            if (action["kind"] == "AddMember" and action["key"] == subject) or (
                action["kind"] == "AddSpendingLimit" and subject in action["members"]
            ):
                restores = True
        entry["summary"] = "Config change: " + ", ".join(a["kind"] for a in slot.tx["actions"])
    elif slot.tx_type == "VaultTransaction":
        resolved = resolve_message(slot.tx["message"], col.tables, slot.transaction_address, blockers)
        payloads.append(resolved)
        entry["instructions"] = resolved["instructions"]
        entry["payload_resolved"] = resolved["resolved"]
        entry["summary"] = _join(resolved["instructions"]) or "unresolved payload"
    else:
        entry["batch"] = {"size": slot.tx["size"], "executed": slot.tx["executed_transaction_index"]}
        parts, all_resolved = [], True
        for child in slot.children:
            item = {"index": child["index"], "address": child["address"],
                    "sha256": reads[child["address"]].sha256, "instructions": []}
            if child["message"] is None:
                all_resolved = False
            else:
                resolved = resolve_message(child["message"], col.tables, child["address"], blockers)
                payloads.append(resolved)
                item["instructions"] = resolved["instructions"]
                all_resolved = all_resolved and resolved["resolved"]
                parts.append(_join(resolved["instructions"]))
            entry["children"].append(item)
        entry["payload_resolved"] = all_resolved
        entry["summary"] = f"{len(slot.children)} of {slot.tx['size']} batch payments left: " + "; ".join(parts)

    if any(key["pubkey"] == subject for p in payloads for key in p["keys"]):
        involvement.append("subject wallet appears in the payload")
    if restores:
        involvement.append("would grant the subject authority again")
    program_id = col.scope["squads_program_id"]
    if any(i["program_id"] == program_id for p in payloads for i in p["instructions"]):
        involvement.append("payload calls the Squads program")
    entry["subject_involvement"] = involvement
    entry["restores_subject_authority"] = restores
    entry["survives_member_removal"] = slot.tx_type != "ConfigTransaction" and slot.state in (rules.APPROVED, rules.EXECUTING)
    entry["binding_sha256"] = canon.digest({
        "payload": entry["payload_sha256"],
        "children": [[c["index"], c["sha256"]] for c in entry["children"]],
        "lookup_tables": [[t["address"], t["sha256"]] for t in entry["lookup_tables"]],
    })
    return entry


def build_review(col: Collection) -> dict:
    scope = col.scope
    subject = scope["subject_wallets"][0]["address"]
    blockers = list(col.blockers)
    resources, authorities, retained, residuals, history = [], [], [], [], []

    for declared in scope["resources"]:
        address = declared["state_address"]
        label = declared.get("label", "")
        state = col.multisigs.get(address)
        if state is None:
            resources.append({"state_address": address, "label": label, "scope": declared["scope"], "status": "unreadable"})
            continue

        controlled = state["config_authority"] != squads.DEFAULT_PUBKEY
        base_blockers = []
        if declared["scope"] != "manifest_owned":
            base_blockers.append({"code": "SHARED_RESOURCE", "detail": "declared shared_or_external; inspection only"})
        if controlled:
            base_blockers.append({"code": "CONTROLLED_MULTISIG",
                                  "detail": f"config authority is {state['config_authority']}; changes do not go through proposals"})

        member = next((m for m in state["members"] if m["key"] == subject), None)
        subject_limits = {a: l for a, l in col.limits.get(address, {}).items() if subject in l["members"]}

        resources.append({
            "state_address": address,
            "label": label,
            "scope": declared["scope"],
            "status": "read",
            "account_sha256": col.reads[address].sha256,
            "vault_0": squads.vault_pda(address, 0, scope["squads_program_id"]),
            "settings": state,
            "subject_is_member": member is not None,
            "remediation": "inspection_only" if base_blockers else ("automatic" if (member or subject_limits) else "none_needed"),
        })

        if member is not None:
            row_blockers = list(base_blockers)
            if not base_blockers:
                row_blockers += [{"code": c, "detail": d} for c, d in rules.removal_problems(state, subject)]
            authorities.append({
                "authority_id": f"member:{address}:{subject}",
                "kind": "member",
                "multisig": address,
                "label": label,
                "wallet": subject,
                "permissions": squads.permission_names(member["permissions"]),
                "permissions_mask": member["permissions"],
                "account_sha256": col.reads[address].sha256,
                "classification": "blocked" if row_blockers else "plannable",
                "blockers": row_blockers,
            })
        if state["config_authority"] == subject:
            authorities.append({
                "authority_id": f"config_authority:{address}",
                "kind": "config_authority",
                "multisig": address,
                "label": label,
                "wallet": subject,
                "account_sha256": col.reads[address].sha256,
                "classification": "blocked",
                "blockers": [{"code": "SUBJECT_IS_CONFIG_AUTHORITY",
                              "detail": "the subject can change this multisig alone; rotate the config authority by hand"}],
            })

        for limit_address, limit in sorted(col.limits.get(address, {}).items()):
            common = {
                "multisig": address,
                "label": label,
                "address": limit_address,
                "account_sha256": col.reads[limit_address].sha256,
                "vault_index": limit["vault_index"],
                "mint": limit["mint"],
                "amount": limit["amount"],
                "remaining_amount": limit["remaining_amount"],
                "period": limit["period"],
                "delegates": limit["members"],
                "destinations": limit["destinations"],
            }
            if subject not in limit["members"]:
                retained.append({**common, "policy_sha256": canon.digest(rules.limit_policy(limit))})
                continue
            row_blockers = list(base_blockers)
            if len(limit["members"]) > 1:
                row_blockers.append({"code": "SHARED_SPENDING_LIMIT",
                                     "detail": f"{len(limit['members']) - 1} other delegate(s) share this limit; "
                                               "it has to be rebuilt by hand without the subject"})
            authorities.append({
                "authority_id": f"limit:{limit_address}",
                "kind": "limit",
                **common,
                "shared": len(limit["members"]) > 1,
                "classification": "blocked" if row_blockers else "plannable",
                "blockers": row_blockers,
            })

        for slot in col.slots.get(address, []):
            history.append({
                "multisig": address,
                "index": str(slot.index),
                "type": slot.tx_type,
                "proposal_status": slot.proposal["status"] if slot.proposal else None,
                "state": slot.state,
            })
            if slot.state in rules.LIVE_STATES:
                residuals.append(_residual(col, address, slot, subject, blockers))

    blockers = sort_unique(blockers)
    counts = {"present": 0, "absent": 0, "error": 0}
    accounts = {}
    for address in sorted(col.reads):
        read = col.reads[address]
        counts[read.status] += 1
        row = {"role": col.roles.get(address, "unknown"), "status": read.status, "slot": read.slot}
        if read.status == "present":
            row.update({"owner": read.owner, "sha256": read.sha256, "data_len": len(read.data)})
            if col.roles.get(address) != "programdata":
                row["data"] = base64.b64encode(read.data).decode()
        elif read.status == "error":
            row["error"] = read.error
        accounts[address] = row

    review = {
        "schema_version": SCHEMA,
        "tool": TOOL,
        "result": "INCOMPLETE" if blockers else "REVIEW_READY",
        "scope": scope,
        "scope_sha256": canon.digest(scope),
        "attestation": scope_mod.attestation(scope),
        "subject": subject,
        "cluster": col.cluster,
        "read": {**col.rpc, "passes": col.passes, "atomic": False},
        "program": col.program,
        "resources": resources,
        "authorities": authorities,
        "retained_limits": retained,
        "residuals": residuals,
        "history": history,
        "outside_scope": col.discovery,
        "coverage": {"required": len(accounts), **counts, "accounts": accounts},
        "state_digest": col.state_digest(),
        "blockers": [b.to_json() for b in blockers],
    }
    return canon.seal(review, "review_sha256")
