"""Terminal output. Plain text, optional colour, nothing that needs a wide terminal."""

from __future__ import annotations

import os
import sys

from .inventory import sol

_COLOURS = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "cyan": "36", "dim": "2", "bold": "1"}


def colour_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("EXITGUARD_COLOR") == "1":
        return True
    return sys.stdout.isatty()


def paint(text: str, *styles: str) -> str:
    if not colour_enabled() or not styles:
        return text
    return f"\x1b[{';'.join(_COLOURS[s] for s in styles)}m{text}\x1b[0m"


def short(address: str | None, keep: int = 4) -> str:
    if not address:
        return "-"
    return address if len(address) <= 2 * keep + 2 else f"{address[:keep]}..{address[-keep:]}"


def say(text: str = "") -> None:
    print(text)


def heading(text: str) -> None:
    say()
    say(paint(text, "bold"))


def table(headers: list[str], rows: list[list[str]], indent: int = 2, styles: dict[int, dict[str, tuple]] | None = None) -> None:
    """Left-aligned columns. `styles` maps a column to {cell text: paint styles}."""
    if not rows:
        say(" " * indent + paint("(none)", "dim"))
        return
    widths = [max(len(str(r[i])) for r in [headers, *rows]) for i in range(len(headers))]
    pad = " " * indent
    say(pad + paint("  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip(), "dim"))
    for row in rows:
        cells = []
        for i, (cell, width) in enumerate(zip(row, widths)):
            text = str(cell).ljust(width)
            style = (styles or {}).get(i, {}).get(str(cell))
            cells.append(paint(text, *style) if style else text)
        say(pad + "  ".join(cells).rstrip())


VERDICT_STYLE = {
    "plannable": ("green",), "blocked": ("red",), "REVOKE": ("green",), "KEEP": ("yellow",),
    "BLOCKED": ("red",), "UNKNOWN": ("red",), "approved": ("yellow",), "pending": ("yellow",),
    "latent": ("yellow",), "executing": ("yellow",),
}


def verdict(word: str, good: bool) -> str:
    return paint(word, "bold", "green" if good else "red")


def blockers(items: list[dict], title: str = "Blockers") -> None:
    if not items:
        return
    heading(title)
    for b in items:
        say(f"  {paint(b['code'], 'red')}  {short(b['subject'], 6) if len(b['subject']) > 40 else b['subject']}")
        if b.get("detail"):
            say(f"      {b['detail']}")


def review(doc: dict) -> None:
    labels = {r["state_address"]: r.get("label") or short(r["state_address"]) for r in doc["resources"]}
    read = doc["read"]
    say(f"  organization  {doc['scope']['organization_id']}   review {doc['scope']['review_id']}")
    say(f"  subject       {doc['subject']}  ({doc['attestation']['subject_provenance_effective']})")
    say(f"  cluster       {doc['cluster']['name']}  [{doc['cluster']['evidence_source']}]  {read['commitment']}, "
        f"slots {read['slot_first']}..{read['slot_last']}, {read['passes']} passes agreed")
    c = doc["coverage"]
    say(f"  coverage      {c['required']} addresses required: {c['present']} present, {c['absent']} verified absent, {c['error']} errors")

    heading("Authority held by the subject")
    rows = []
    for a in doc["authorities"]:
        if a["kind"] == "member":
            what = "member: " + "+".join(a["permissions"])
        elif a["kind"] == "limit":
            what = f"spending limit {short(a['address'])}: {sol(a['amount'])} SOL/{a['period'].lower()}"
            if a["shared"]:
                what += f", shared with {len(a['delegates']) - 1}"
        else:
            what = "config authority"
        note = ", ".join(b["code"] for b in a["blockers"]) or "can be removed by proposal"
        rows.append([a["label"] or short(a["multisig"]), what, a["classification"], note])
    table(["treasury", "authority", "status", "note"], rows, styles={2: VERDICT_STYLE})

    heading("Spending limits that stay (subject is not a delegate)")
    table(["treasury", "limit", "allowance", "delegates"],
          [[r["label"] or short(r["multisig"]), short(r["address"]), f"{sol(r['amount'])} SOL/{r['period'].lower()}",
            ", ".join(short(d) for d in r["delegates"])] for r in doc["retained_limits"]])

    heading("Unfinished actions in these treasuries (need a decision each)")
    rows = []
    for r in doc["residuals"]:
        flags = "; ".join(r["subject_involvement"] + (["survives removal"] if r["survives_member_removal"] else [])) or "-"
        rows.append([labels.get(r["multisig"], short(r["multisig"])), f"#{r['transaction_index']}", r["type"].replace("Transaction", ""),
                     r["state"], _clip(r["summary"], 60), flags])
    table(["treasury", "index", "type", "state", "payload", "notes"], rows, styles={3: VERDICT_STYLE})
    if any(r["survives_member_removal"] for r in doc["residuals"]):
        say(paint("  survives removal: already approved, so it can still execute after the subject is removed", "dim"))

    outside = doc.get("outside_scope")
    if outside is not None:
        heading("Found outside the declared scope (best effort, not a completeness claim)")
        table(["kind", "multisig", "detail"],
              [[f["kind"], f["multisig"], _outside_detail(f)] for f in outside["findings"]])
        if outside["query_errors"]:
            say(paint(f"  {len(outside['query_errors'])} discovery queries failed; this section is partial", "yellow"))
    blockers(doc["blockers"])


def _outside_detail(f: dict) -> str:
    if f["kind"] == "multisig_membership":
        return f"{'+'.join(f['permissions'])}, threshold {f['threshold']} of {f['members']}"
    return f"{sol(f['amount'])} SOL/{f['period'].lower()}"


def _clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 2] + ".."


def intent(doc: dict, review_doc: dict) -> None:
    about = {a["authority_id"]: (a["label"] or short(a["multisig"])) + " " + a["kind"] for a in review_doc["authorities"]}
    labels = {r["state_address"]: r.get("label") or short(r["state_address"]) for r in review_doc["resources"]}
    about.update({r["residual_id"]: f"{labels.get(r['multisig'])} #{r['transaction_index']} {r['type'].replace('Transaction', '')}"
                  for r in review_doc["residuals"]})
    rows = [[about.get(d["id"], d["id"]), d["decision"], str(d["expires_at_slot"] or "-"), _clip(d["reason"] or "-", 84)]
            for d in doc["decisions"]]
    table(["row", "decision", "expires at slot", "reason"], rows, styles={1: VERDICT_STYLE})


def packet(doc: dict) -> None:
    if not doc["transactions"]:
        say("  Nothing to remove. No transaction was invented; certify will check the existing state.")
    for tx in doc["transactions"]:
        s = tx["signers"]
        say(f"  {paint(tx['label'] or short(tx['multisig']), 'bold')}  config transaction #{tx['transaction_index']}")
        for n, action in enumerate(tx["actions"], 1):
            target = action.get("spending_limit") or action.get("old_member")
            say(f"    {n}. {action['kind']:<20} {target}")
        say(f"    proposer {short(s['proposer'])}   approvals {s['approvals_required']} of {len(s['approvers'])} eligible   "
            f"executor {short(s['executor'])}   time lock {s['time_lock_seconds']}s")
        say(paint(f"    action digest {tx['action_digest']}", "dim"))
    if doc.get("expires_at_slot") is not None:
        say(f"  decisions behind this packet expire at slot {doc['expires_at_slot']}; it cannot be verified or certified from then on")
    for item in doc["not_planned"]:
        if item["decision"] in ("BLOCKED", "KEEP") and item["id"].split(":")[0] in ("member", "limit", "config_authority"):
            say(f"  {paint('not planned', 'yellow')}  {_clip(item['id'], 60)}  {item['decision']}  ({', '.join(item['why'])})")


def plan_check(result: dict, labels: dict | None = None) -> None:
    for p in result["phases"]:
        say(f"  {(labels or {}).get(p['multisig'], short(p['multisig']))} #{p['transaction_index']}  {p['phase']}")
    blockers(result["reasons"], "Why the plan no longer holds")


def certificate(result: dict) -> None:
    integrity = result["historical_integrity"]
    say(f"  historical integrity   {verdict(integrity, integrity == 'PASS')}"
        + ("" if result["anchored_to_trusted_digest"] else "   (no trusted digest supplied; a self-hash proves nothing about the author)"))
    for p in result["integrity_problems"]:
        say(f"      {p}")
    say(f"  recorded postconditions  {verdict(result['content'], result['content'] == 'PASS')}   (re-derived from the raw account bytes in the record)")
    for p in result["content_problems"]:
        say(f"      {p}")
    if result["attestation"]:
        a = result["attestation"]
        say(f"  scope attestation      {a['reviewer_attestation']}   subject provenance: {a['subject_provenance_effective']}")
    say(f"  evidence source        {result['evidence_source']}")
    current = result["current_validity"]
    say(f"  current validity       {verdict(current['status'], current['status'] == 'CURRENT')}")
    for reason in current["reasons"]:
        say(f"      {reason}")
