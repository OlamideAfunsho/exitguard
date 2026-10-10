"""Operator decisions, bound to the exact review they were made against."""

from __future__ import annotations

from . import TOOL, canon
from .blockers import Blocker, ExitGuardError

SCHEMA = "exitguard.intent.v1"
DECISIONS_SCHEMA = "exitguard.decisions.v1"
DECISIONS = ("KEEP", "REVOKE", "BLOCKED", "UNKNOWN")


def rows(review: dict) -> list[dict]:
    """Every row that needs a decision, with the hashes a decision gets bound to."""
    out = []
    for a in review["authorities"]:
        out.append({
            "id": a["authority_id"],
            "kind": "authority",
            "classification": a["classification"],
            "account_sha256": a["account_sha256"],
        })
    for r in review["residuals"]:
        out.append({
            "id": r["residual_id"],
            "kind": "residual",
            "classification": r["state"],
            "payload_sha256": r["payload_sha256"],
            "child_sha256": [c["sha256"] for c in r["children"]],
            "binding_sha256": r["binding_sha256"],
        })
    return out


def template(review: dict) -> dict:
    """A decisions file with every row set to UNKNOWN, for the operator to fill in."""
    by_id = {a["authority_id"]: a for a in review["authorities"]}
    by_id.update({r["residual_id"]: r for r in review["residuals"]})
    decisions = []
    for row in rows(review):
        source = by_id[row["id"]]
        hint = source.get("summary") or source.get("label") or ""
        decisions.append({"id": row["id"], "decision": "UNKNOWN", "reason": "", "about": hint})
    return {
        "schema_version": DECISIONS_SCHEMA,
        "review_sha256": review["review_sha256"],
        "expires_at_slot": None,
        "decisions": decisions,
    }


def build(review: dict, decisions_doc: dict) -> dict:
    if not canon.check_seal(review, "review_sha256"):
        raise ExitGuardError(Blocker("INPUT_TAMPERED", "review", "review.json does not match its review_sha256"))
    if review["result"] != "REVIEW_READY":
        raise ExitGuardError(Blocker("INTENT_INVALID", "review", "the review is incomplete; fix its blockers and scan again"))
    if not isinstance(decisions_doc, dict) or not isinstance(decisions_doc.get("decisions"), list):
        raise ExitGuardError(Blocker("INTENT_INVALID", "decisions", "expected an object with a decisions list"))
    bound = decisions_doc.get("review_sha256")
    if bound is not None and bound != review["review_sha256"]:
        raise ExitGuardError(Blocker("INTENT_INVALID", "decisions", "these decisions were written for a different review"))

    floor = review["read"]["slot_last"]
    default_expiry = decisions_doc.get("expires_at_slot")
    wanted = {row["id"]: row for row in rows(review)}
    given: dict[str, dict] = {}
    problems: list[Blocker] = []
    for item in decisions_doc["decisions"]:
        if not isinstance(item, dict) or item.get("id") not in wanted:
            problems.append(Blocker("INTENT_INVALID", str(item.get("id") if isinstance(item, dict) else item),
                                    "decision does not match any row in the review"))
            continue
        if item["id"] in given:
            problems.append(Blocker("INTENT_INVALID", item["id"], "decided twice"))
            continue
        given[item["id"]] = item

    out = []
    for row_id, row in wanted.items():
        item = given.get(row_id, {})
        decision = item.get("decision", "UNKNOWN")
        reason = str(item.get("reason") or "").strip()
        expiry = item.get("expires_at_slot", default_expiry)
        if decision not in DECISIONS:
            problems.append(Blocker("INTENT_INVALID", row_id, f"decision must be one of {', '.join(DECISIONS)}"))
            continue
        if row["kind"] == "authority" and row["classification"] == "blocked" and decision == "REVOKE":
            problems.append(Blocker("DECISION_NOT_ALLOWED", row_id,
                                    "this row cannot be remediated automatically; mark it BLOCKED and resolve it by hand"))
            continue
        if decision == "KEEP" and not reason:
            problems.append(Blocker("KEEP_INVALID", row_id, "KEEP needs a written reason"))
            continue
        if decision != "UNKNOWN":
            if isinstance(expiry, bool) or not isinstance(expiry, int):
                problems.append(Blocker("EXPIRY_INVALID", row_id, "expires_at_slot must be an integer slot"))
                continue
            if expiry <= floor:
                problems.append(Blocker("EXPIRY_INVALID", row_id, f"expires_at_slot {expiry} is not after the review slot {floor}"))
                continue
        entry = {
            "id": row_id,
            "kind": row["kind"],
            "decision": decision,
            "reason": reason,
            "expires_at_slot": expiry if decision != "UNKNOWN" else None,
            "review_sha256": review["review_sha256"],
        }
        for key in ("account_sha256", "payload_sha256", "child_sha256", "binding_sha256"):
            if key in row:
                entry[key] = row[key]
        out.append(entry)
    if problems:
        raise ExitGuardError(problems)

    tally = {d: sum(1 for e in out if e["decision"] == d) for d in DECISIONS}
    intent = {
        "schema_version": SCHEMA,
        "tool": TOOL,
        "organization_id": review["scope"]["organization_id"],
        "review_id": review["scope"]["review_id"],
        "subject": review["subject"],
        "reviewer": review["scope"]["reviewer"]["wallet"],
        "review_sha256": review["review_sha256"],
        "scope_sha256": review["scope_sha256"],
        "state_digest": review["state_digest"],
        "decisions": out,
        "tally": tally,
    }
    return canon.seal(intent, "intent_sha256")


def check_binding(review: dict, intent: dict) -> None:
    for document, field, name in ((review, "review_sha256", "review"), (intent, "intent_sha256", "intent")):
        if not canon.check_seal(document, field):
            raise ExitGuardError(Blocker("INPUT_TAMPERED", name, f"{name}.json does not match its {field}"))
    if intent.get("schema_version") != SCHEMA or intent["review_sha256"] != review["review_sha256"]:
        raise ExitGuardError(Blocker("INTENT_INVALID", "intent", "intent was not made against this review"))
    if any(d["review_sha256"] != review["review_sha256"] for d in intent["decisions"]):
        raise ExitGuardError(Blocker("INTENT_INVALID", "intent", "a decision is bound to a different review"))


def by_id(intent: dict) -> dict[str, dict]:
    return {d["id"]: d for d in intent["decisions"]}
