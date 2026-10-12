"""Certify the post-execution state and verify a record later.

certify() rereads the declared scope after the remediation has been executed
by the members and checks every postcondition. It returns a record only when
all of them hold; otherwise the caller gets blockers and no record.

A record covers the declared scope over the observed slots and nothing more.
It cannot stop a member with Execute permission from acting outside
ExitGuard, and it says nothing about what happens after its last read.
"""

from __future__ import annotations

import base64

from . import TOOL, canon, inventory, rules, squads, verifier
from . import intent as intent_mod
from . import scope as scope_mod
from .blockers import Blocker, sort_unique
from .collector import collect
from .rpc import RpcClient, account_hash

SCHEMA = "exitguard.record.v1"
BOUNDARY = [
    "Covers only the treasuries listed in the embedded scope. The operator attested that list; the chain does not.",
    "Describes state between pre.slot_first and post.slot_last. Later changes are outside it.",
    "Reads were taken call by call, not as one atomic snapshot; two passes had to agree.",
    "Any member with Execute permission can act through other tooling and can restore access later.",
    "Residual payloads are inventoried and hashed. Their downstream program behaviour is not audited.",
]


def _post_checks(packet: dict, review: dict, intent: dict, post: dict, col, extra_reads: dict) -> list[Blocker]:
    """Postconditions shared by certify() and nothing else; each failure is a named blocker."""
    out: list[Blocker] = []
    subject = packet["subject"]
    decisions = intent_mod.by_id(intent)

    for d in intent["decisions"]:
        if d["decision"] == "UNKNOWN":
            out.append(Blocker("DECISION_UNKNOWN", d["id"], "row was never decided"))
        elif d["decision"] == "BLOCKED":
            out.append(Blocker("DECISION_BLOCKED", d["id"], "row needs manual resolution and a new scan"))
        elif d["decision"] == "KEEP" and d["kind"] == "authority":
            out.append(Blocker("RETAINED_SUBJECT_AUTHORITY", d["id"], "subject authority was kept; offboarding is not complete"))

    for row in post["authorities"]:
        code = {"member": "SUBJECT_STILL_MEMBER", "limit": "SUBJECT_STILL_DELEGATE"}.get(row["kind"], "RETAINED_SUBJECT_AUTHORITY")
        out.append(Blocker(code, row["authority_id"], f"still present after execution in {row['label'] or row['multisig']}"))

    for tx in packet["transactions"]:
        ms, index = tx["multisig"], int(tx["transaction_index"])
        slots = col.slots.get(ms, [])
        slot = slots[index - 1] if len(slots) >= index else None
        executed = (slot is not None and slot.tx_type == "ConfigTransaction" and slot.tx["actions"] == tx["actions"]
                    and slot.proposal is not None and slot.proposal["status"] == "Executed")
        if not executed:
            status = slot.proposal["status"] if slot and slot.proposal else "absent"
            out.append(Blocker("PROPOSAL_NOT_EXECUTED", tx["proposal_address"], f"remediation proposal #{index} is {status}"))
        for limit in tx["spending_limits"]:
            read = extra_reads[limit]
            if read.status == "present":
                out.append(Blocker("LIMIT_NOT_CLOSED", limit, "spending limit account still exists"))
            elif read.status == "error":
                out.append(Blocker("RPC_ERROR", limit, f"could not confirm closure: {read.error}"))

    # Things the offboarding must not have disturbed.
    before_settings = {r["state_address"]: r["settings"] for r in review["resources"] if r["status"] == "read"}
    for resource in post["resources"]:
        ms = resource["state_address"]
        if resource["status"] != "read" or ms not in before_settings:
            continue
        if rules.multisig_settings(before_settings[ms], subject) != rules.multisig_settings(resource["settings"], subject):
            out.append(Blocker("RETAINED_STATE_CHANGED", ms, "threshold, time lock, authority or other members changed since the review"))
    before_limits = {r["address"]: r["policy_sha256"] for r in review["retained_limits"]}
    after_limits = {r["address"]: r["policy_sha256"] for r in post["retained_limits"]}
    for address in sorted(set(before_limits) | set(after_limits)):
        if address not in after_limits:
            out.append(Blocker("RETAINED_STATE_CHANGED", address, "a retained spending limit no longer exists"))
        elif address not in before_limits:
            out.append(Blocker("RETAINED_STATE_CHANGED", address, "a spending limit appeared after the review"))
        elif before_limits[address] != after_limits[address]:
            out.append(Blocker("RETAINED_STATE_CHANGED", address, "a retained spending limit's amount, period, delegates or destinations changed"))

    for residual in post["residuals"]:
        d = decisions.get(residual["residual_id"])
        if d is None:
            out.append(Blocker("RESIDUAL_UNDECIDED", residual["residual_id"],
                               f"{residual['type']} #{residual['transaction_index']} is {residual['state']} and has no decision"))
        elif d["decision"] == "REVOKE":
            out.append(Blocker("RESIDUAL_REVOKE_PENDING", residual["residual_id"],
                               f"marked REVOKE but still {residual['state']}; cancel or reject it in Squads, then certify again"))
        elif d["decision"] == "KEEP" and d.get("binding_sha256") != residual["binding_sha256"]:
            out.append(Blocker("RESIDUAL_UNDECIDED", residual["residual_id"], "payload changed after the KEEP decision"))
    return out


def certify(client: RpcClient, packet: dict, review: dict, intent: dict) -> tuple[dict | None, list[Blocker]]:
    blockers: list[Blocker] = []
    try:
        intent_mod.check_binding(review, intent)
    except Exception as exc:  # ExitGuardError carries blockers
        return None, list(getattr(exc, "blockers", [Blocker("INPUT_TAMPERED", "inputs", str(exc))]))
    for problem in verifier.check_packet(packet):
        blockers.append(Blocker("PACKET_DECODE_MISMATCH", "packet", problem))
    if packet.get("review_sha256") != review["review_sha256"] or packet.get("intent_sha256") != intent["intent_sha256"]:
        blockers.append(Blocker("INTENT_INVALID", "packet", "packet was not planned from this review and intent"))
    if packet.get("decision_expiries") != verifier.bound_expiries(intent):
        blockers.append(Blocker("INTENT_INVALID", "packet", "decision expiries in the packet differ from the intent"))
    if blockers:
        return None, sort_unique(blockers)

    col = collect(client, packet["scope"])
    blockers += col.blockers
    planned_limits = [limit for tx in packet["transactions"] for limit in tx["spending_limits"]]
    extra = client.get_multiple(planned_limits) if planned_limits else {}

    if col.cluster.get("genesis_hash") != packet["cluster"]["genesis_hash"]:
        blockers.append(Blocker("CLUSTER_MISMATCH", client.endpoint, "genesis hash differs from the reviewed cluster"))
    source = col.cluster.get("evidence_source")
    if source != "LOCAL_SIMULATION" and client.commitment != "finalized":
        blockers.append(Blocker("NOT_FINALIZED", client.endpoint,
                                f"reads were taken at {client.commitment}; certification of a live cluster needs finalized"))
    for key in ("program_sha256", "programdata_sha256", "deploy_slot", "programdata_address"):
        if col.program.get(key) != packet["program"].get(key):
            blockers.append(Blocker("PROGRAM_DRIFT", packet["program"]["program_id"],
                                    f"{key} differs from the program bound at review"))
            break

    post = inventory.build_review(col)
    if not blockers:
        blockers += _post_checks(packet, review, intent, post, col, extra)

    post_slot = col.rpc.get("slot_last")
    expiries = []
    for d in intent["decisions"]:
        if d["decision"] == "UNKNOWN":
            continue
        e = d.get("expires_at_slot")
        if isinstance(e, bool) or not isinstance(e, int):
            blockers.append(Blocker("EXPIRY_INVALID", d["id"], "decision has no integer expiry slot"))
        elif post_slot is None or e <= post_slot:
            blockers.append(Blocker("EXPIRY_INVALID", d["id"], f"decision expired at slot {e}; post-state was read at {post_slot}"))
        else:
            expiries.append(e)
    blockers = sort_unique(blockers)
    if blockers:
        return None, blockers

    decisions = intent_mod.by_id(intent)
    after_state = {r["residual_id"]: r["state"] for r in post["residuals"]}
    history_after = {(h["multisig"], h["index"]): h["state"] for h in post["history"]}
    removed = []
    for row in review["authorities"]:
        if decisions[row["authority_id"]]["decision"] == "REVOKE":
            removed.append({k: row[k] for k in ("authority_id", "kind", "multisig", "label") if k in row}
                           | ({"permissions": row["permissions"]} if row["kind"] == "member" else
                              {"amount": row["amount"], "period": row["period"], "mint": row["mint"]}))
    residual_decisions = []
    for r in review["residuals"]:
        d = decisions[r["residual_id"]]
        residual_decisions.append({
            "residual_id": r["residual_id"], "multisig": r["multisig"], "transaction_index": r["transaction_index"],
            "type": r["type"], "summary": r["summary"], "decision": d["decision"], "reason": d["reason"],
            "expires_at_slot": d["expires_at_slot"], "binding_sha256": r["binding_sha256"],
            "state_at_review": r["state"],
            "state_after": after_state.get(r["residual_id"], history_after.get((r["multisig"], r["transaction_index"]), "closed")),
        })

    # Raw bytes for the accounts the postconditions depend on, so a verifier can recheck them offline.
    pre_accounts = review["coverage"]["accounts"]
    keep_pre = {r["state_address"] for r in review["resources"]} | {r["address"] for r in review["retained_limits"]} \
        | {r["address"] for r in review["authorities"] if r["kind"] == "limit"}
    keep_post = {r["state_address"] for r in post["resources"]} | {r["address"] for r in post["retained_limits"]}
    for tx in packet["transactions"]:
        keep_post |= {tx["transaction_address"], tx["proposal_address"]}

    def snap(accounts: dict, wanted: set[str]) -> dict:
        return {a: {"owner": accounts[a]["owner"], "data": accounts[a]["data"], "sha256": accounts[a]["sha256"]}
                for a in sorted(wanted) if accounts.get(a, {}).get("status") == "present"}

    def slim(accounts: dict) -> dict:
        return {a: {k: v for k, v in row.items() if k != "data"} for a, row in accounts.items()}

    record = {
        "schema_version": SCHEMA,
        "tool": TOOL,
        "result": "COMPLETE",
        "evidence_source": source,
        "cluster": col.cluster,
        "organization_id": packet["organization_id"],
        "review_id": packet["review_id"],
        "subject": packet["subject"],
        "scope": packet["scope"],
        "attestation": scope_mod.attestation(packet["scope"]),
        "digests": {
            "scope_sha256": packet["scope_sha256"],
            "review_sha256": review["review_sha256"],
            "intent_sha256": intent["intent_sha256"],
            "packet_sha256": packet["packet_sha256"],
            "actions": [{"multisig": t["multisig"], "transaction_index": t["transaction_index"],
                         "action_digest": t["action_digest"]} for t in packet["transactions"]],
        },
        "program": col.program,
        "pre": {**{k: review["read"][k] for k in ("commitment", "slot_first", "slot_last", "passes")},
                "state_digest": review["state_digest"]},
        "post": {**{k: post["read"][k] for k in ("commitment", "slot_first", "slot_last", "passes")},
                 "state_digest": post["state_digest"]},
        "coverage": {
            "pre": {k: review["coverage"][k] for k in ("required", "present", "absent", "error")},
            "post": {k: post["coverage"][k] for k in ("required", "present", "absent", "error")},
            "post_accounts": slim(post["coverage"]["accounts"]),
            "closed": [{"address": a, "status": extra[a].status, "slot": extra[a].slot} for a in sorted(extra)],
        },
        "snapshots": {"pre": snap(pre_accounts, keep_pre), "post": snap(post["coverage"]["accounts"], keep_post)},
        "remediation": [{"multisig": t["multisig"], "label": t["label"], "transaction_index": t["transaction_index"],
                         "transaction_address": t["transaction_address"], "proposal_address": t["proposal_address"],
                         "actions": t["actions"]} for t in packet["transactions"]],
        "removed": removed,
        "retained_limits": [{k: r[k] for k in ("address", "multisig", "label", "delegates", "amount", "period", "policy_sha256")}
                            for r in post["retained_limits"]],
        "residual_decisions": residual_decisions,
        "blockers": [],
        "expires_at_slot": min(expiries) if expiries else None,
        "executor_bypass": True,
        "boundary": BOUNDARY,
    }
    if source == "LOCAL_SIMULATION":
        record["boundary"] = ["LOCAL_SIMULATION: produced against LiteSVM. This is not finalized live-chain evidence."] + BOUNDARY
    if record["expires_at_slot"] is None:
        return None, [Blocker("EXPIRY_INVALID", "record", "no decision carries an expiry, so the record has no validity window")]
    return canon.seal(record, "record_sha256"), []


# ------------------------------------------------------------- verification

def _recheck_snapshots(record: dict) -> list[str]:
    """Re-derive the postconditions from the raw account bytes embedded in the record."""
    problems: list[str] = []
    subject = record["subject"]
    program_id = record["program"]["program_id"]
    post_accounts = record["coverage"]["post_accounts"]
    decoded: dict[str, dict[str, tuple[str, dict]]] = {"pre": {}, "post": {}}

    for side in ("pre", "post"):
        for address, item in record["snapshots"][side].items():
            try:
                data = base64.b64decode(item["data"], validate=True)
                if account_hash(item["owner"], False, data) != item["sha256"] or item["owner"] != program_id:
                    problems.append(f"{side} snapshot of {address} does not match its recorded hash or owner")
                    continue
                decoded[side][address] = squads.decode_account(data)
            except (ValueError, squads.DecodeError) as exc:
                problems.append(f"{side} snapshot of {address} does not decode: {exc}")
    for address, item in record["snapshots"]["post"].items():
        listed = post_accounts.get(address, {})
        if listed.get("status") != "present" or listed.get("sha256") != item["sha256"]:
            problems.append(f"post snapshot of {address} is not the account listed in post coverage")

    for resource in record["scope"]["resources"]:
        ms = resource["state_address"]
        before, after = decoded["pre"].get(ms), decoded["post"].get(ms)
        if not before or not after or before[0] != "Multisig" or after[0] != "Multisig":
            problems.append(f"multisig {ms} is missing from the snapshots")
            continue
        if any(m["key"] == subject for m in after[1]["members"]) or after[1]["config_authority"] == subject:
            problems.append(f"subject still has authority in {ms} in the post snapshot")
        if rules.multisig_settings(before[1], subject) != rules.multisig_settings(after[1], subject):
            problems.append(f"unrelated settings of {ms} differ between the snapshots")

    for address, (name, fields) in decoded["post"].items():
        if name == "SpendingLimit" and subject in fields["members"]:
            problems.append(f"subject is still a delegate of {address} in the post snapshot")
    for item in record["retained_limits"]:
        before, after = decoded["pre"].get(item["address"]), decoded["post"].get(item["address"])
        if not before or not after or rules.limit_policy(before[1]) != rules.limit_policy(after[1]):
            problems.append(f"retained limit {item['address']} is missing or its policy changed")

    closed = {c["address"]: c["status"] for c in record["coverage"]["closed"]}
    for tx in record["remediation"]:
        for action in tx["actions"]:
            if action["kind"] == "RemoveSpendingLimit" and closed.get(action["spending_limit"]) != "absent":
                problems.append(f"removed limit {action['spending_limit']} is not recorded as closed")
        proposal = decoded["post"].get(tx["proposal_address"])
        transaction = decoded["post"].get(tx["transaction_address"])
        if not proposal or proposal[0] != "Proposal" or proposal[1]["status"] != "Executed":
            problems.append(f"remediation proposal {tx['proposal_address']} is not Executed in the post snapshot")
        if not transaction or transaction[0] != "ConfigTransaction" or transaction[1]["actions"] != tx["actions"]:
            problems.append(f"remediation transaction {tx['transaction_address']} does not carry the recorded actions")
    return problems


def verify_certificate(record: dict, expected_sha256: str | None, client: RpcClient | None = None) -> dict:
    """Three separate answers: is the record intact, does it show what it claims, is it still true now."""
    integrity: list[str] = []
    if record.get("schema_version") != SCHEMA:
        integrity.append("schema_version is not " + SCHEMA)
    if not canon.check_seal(record, "record_sha256"):
        integrity.append("record does not match its own record_sha256")
    if expected_sha256 is None:
        anchored = False
    else:
        anchored = record.get("record_sha256") == expected_sha256.lower()
        if not anchored:
            integrity.append("record_sha256 is not the digest you supplied")

    content: list[str] = []
    if not integrity:
        if record.get("result") != "COMPLETE" or record.get("blockers") or record.get("executor_bypass") is not True:
            content.append("record does not claim a clean, bounded completion")
        if canon.digest(record["scope"]) != record["digests"]["scope_sha256"]:
            content.append("embedded scope does not match scope_sha256")
        if record["subject"] != record["scope"]["subject_wallets"][0]["address"]:
            content.append("subject differs from the scope")
        if record["cluster"].get("evidence_source") != record["evidence_source"]:
            content.append("evidence_source is inconsistent")
        if record["evidence_source"] == "LIVE_RPC" and record["post"]["commitment"] != "finalized":
            content.append("claims live evidence without finalized reads")
        if not isinstance(record.get("expires_at_slot"), int) or record["expires_at_slot"] <= record["post"]["slot_last"]:
            content.append("expiry is missing or not after the post-state read")
        content += _recheck_snapshots(record)

    attestation = scope_mod.attestation(record["scope"]) if not integrity else None

    current = {"status": "NOT_CHECKED", "reasons": ["no RPC endpoint given; current state was not read"]}
    if client is not None and not integrity and not content:
        reasons: list[str] = []
        col = collect(client, record["scope"])
        reasons += [b.line() for b in col.blockers]
        if col.cluster.get("genesis_hash") != record["cluster"]["genesis_hash"]:
            reasons.append("endpoint is a different cluster from the one recorded")
        elif not col.blockers:
            now = inventory.build_review(col)
            slot_now = col.rpc["slot_last"]
            for row in now["authorities"]:
                reasons.append(f"subject authority exists again: {row['authority_id']}")
            # Compare what the record is about, not raw bytes: a retained limit being used, or a
            # treasury doing new business, does not undo an offboarding.
            subject = record["subject"]
            for address, item in record["snapshots"]["post"].items():
                name, was = squads.decode_account(base64.b64decode(item["data"]))
                if name == "Multisig":
                    state = col.multisigs.get(address)
                    if state is None or rules.multisig_settings(was, subject) != rules.multisig_settings(state, subject):
                        reasons.append(f"settings of multisig {address} changed after the record")
                elif name == "SpendingLimit":
                    limit = col.limits.get(was["multisig"], {}).get(address)
                    if limit is None or rules.limit_policy(was) != rules.limit_policy(limit):
                        reasons.append(f"retained spending limit {address} changed or was removed after the record")
            known = {r["address"] for r in record["retained_limits"]}
            for limits in col.limits.values():
                for address in limits:
                    if address not in known:
                        reasons.append(f"spending limit {address} was created after the record")
            for key in ("program_sha256", "programdata_sha256"):
                if col.program.get(key) != record["program"].get(key):
                    reasons.append("Squads program changed after the record")
                    break
            recorded = {r["residual_id"] for r in record["residual_decisions"] if r["decision"] == "KEEP"}
            for r in now["residuals"]:
                if r["residual_id"] not in recorded:
                    reasons.append(f"new undecided residual: {r['type']} #{r['transaction_index']} in {r['multisig']}")
            if slot_now > record["expires_at_slot"]:
                reasons.append(f"record expired at slot {record['expires_at_slot']}; chain is at {slot_now}")
                status = "EXPIRED"
            else:
                status = "CURRENT" if not reasons else "CHANGED"
            current = {"status": status if not reasons or status == "EXPIRED" else "CHANGED", "reasons": reasons,
                       "checked_at_slot": slot_now, "commitment": client.commitment}
        if reasons and current.get("status") == "NOT_CHECKED":
            current = {"status": "CHANGED", "reasons": reasons}
    return {
        "record_sha256": record.get("record_sha256"),
        "historical_integrity": "FAIL" if integrity else ("PASS" if anchored else "SELF_CONSISTENT_ONLY"),
        "integrity_problems": integrity,
        "anchored_to_trusted_digest": anchored,
        "content": "NOT_CHECKED" if integrity else ("FAIL" if content else "PASS"),
        "content_problems": content,
        "evidence_source": record.get("evidence_source"),
        "attestation": attestation,
        "current_validity": current,
    }
