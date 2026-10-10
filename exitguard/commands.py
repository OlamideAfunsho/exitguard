"""The seven commands. Each returns a process exit code: 0 clean, 2 blocked."""

from __future__ import annotations

import os
from pathlib import Path

from . import TOOL, canon, collector, inventory, planner, render, verifier
from . import intent as intent_mod
from . import record as record_mod
from . import scope as scope_mod
from .blockers import Blocker, ExitGuardError
from .rpc import RpcClient, RpcFailure
from .sdkworker import WorkerError

OK, BLOCKED = 0, 2
DIAGNOSTICS_SCHEMA = "exitguard.diagnostics.v1"


def _client(rpc_url: str | None, commitment: str = "finalized") -> RpcClient:
    url = rpc_url or os.environ.get("EXITGUARD_RPC_URL")
    if not url:
        raise ExitGuardError(Blocker("RPC_ERROR", "rpc", "no RPC URL; pass --rpc or set EXITGUARD_RPC_URL"))
    return RpcClient(url, commitment=commitment)


def _load(path: str, what: str) -> dict:
    try:
        doc = canon.load(path)
    except (OSError, ValueError) as exc:
        raise ExitGuardError(Blocker("INPUT_TAMPERED", str(path), f"cannot read {what}: {exc}")) from None
    if not isinstance(doc, dict):
        raise ExitGuardError(Blocker("INPUT_TAMPERED", str(path), f"{what} is not a JSON object"))
    return doc


def _fail(command: str, verdict: str, blockers: list[Blocker], out: str | None) -> int:
    """Print blockers, write diagnostics next to where the output would have gone, publish nothing else."""
    items = [b.to_json() for b in blockers]
    render.say()
    render.say(f"{render.verdict(verdict, False)}  {command} produced no output document")
    render.blockers(items)
    if out:
        path = Path(str(out) + ".diagnostics.json")
        canon.write(path, {"schema_version": DIAGNOSTICS_SCHEMA, "tool": TOOL, "command": command,
                           "verdict": verdict, "blockers": items})
        render.say(render.paint(f"\n  diagnostics: {path}", "dim"))
    return BLOCKED


def guarded(command: str, out_arg: str = "out"):
    """Turn expected failures into a blocker report and exit code 2."""
    def wrap(fn):
        def run(**kwargs) -> int:
            out = kwargs.get(out_arg)
            try:
                return fn(**kwargs)
            except ExitGuardError as exc:
                return _fail(command, exc.verdict, exc.blockers, out)
            except RpcFailure as exc:
                return _fail(command, "BLOCKED", [Blocker("RPC_ERROR", "rpc", str(exc))], out)
            except WorkerError as exc:
                return _fail(command, "BLOCKED", [Blocker("PACKET_DECODE_MISMATCH", "sdk-worker", str(exc))], out)
            except (KeyError, TypeError, IndexError, AttributeError) as exc:
                # An input file with the right digest but the wrong shape. Refuse rather than guess.
                return _fail(command, "BLOCKED", [Blocker("INPUT_TAMPERED", "input",
                                                          f"a document is missing a field or has the wrong shape ({exc!r})")], out)
        return run
    return wrap


@guarded("scan")
def scan(scope: str, rpc: str | None, out: str, commitment: str = "finalized", discover: bool = False) -> int:
    manifest = scope_mod.load(scope)
    client = _client(rpc, commitment)
    col = collector.collect(client, manifest)
    if discover and col.cluster.get("genesis_hash"):
        col.discovery = collector.discover_outside_scope(client, col)
    review = inventory.build_review(col)
    canon.write(out, review)
    render.heading(f"Scan of {len(manifest['resources'])} declared treasuries")
    render.review(review)
    render.say()
    if review["result"] != "REVIEW_READY":
        render.say(f"{render.verdict('INCOMPLETE', False)}  the inventory has gaps; {out} is diagnostic only and cannot be reviewed")
        return BLOCKED
    render.say(f"{render.verdict('REVIEW_READY', True)}  {out}")
    render.say(render.paint(f"  review_sha256 {review['review_sha256']}", "dim"))
    return OK


@guarded("review")
def review(review: str, out: str, decisions: str | None = None, init: bool = False) -> int:
    doc = _load(review, "review")
    if init:
        canon.write(out, intent_mod.template(doc))
        render.say(f"Wrote a decisions template with {len(doc['authorities']) + len(doc['residuals'])} rows to {out}. "
                   "Set each row to KEEP, REVOKE or BLOCKED.")
        return OK
    if not decisions:
        raise ExitGuardError(Blocker("INTENT_INVALID", "decisions", "pass --decisions FILE, or --init to create a template"))
    intent = intent_mod.build(doc, _load(decisions, "decisions"))
    canon.write(out, intent)
    render.heading("Decisions bound to this review")
    render.intent(intent, doc)
    render.say()
    undecided = intent["tally"]["UNKNOWN"]
    if undecided:
        render.say(f"{render.verdict('UNDECIDED', False)}  {undecided} rows are UNKNOWN; {out} was written but cannot be planned")
        return BLOCKED
    render.say(f"{render.verdict('INTENT_BOUND', True)}  {out}")
    render.say(render.paint(f"  intent_sha256 {intent['intent_sha256']}", "dim"))
    return OK


@guarded("plan")
def plan(review: str, intent: str, rpc: str | None, out: str, scope: str | None = None,
         commitment: str = "finalized", proposer: str | None = None, executor: str | None = None) -> int:
    review_doc, intent_doc = _load(review, "review"), _load(intent, "intent")
    if scope is not None and canon.digest(scope_mod.load(scope)) != review_doc.get("scope_sha256"):
        raise ExitGuardError(Blocker("SCOPE_INVALID", str(scope), "this scope is not the one the review was made from"))
    packet = planner.plan(_client(rpc, commitment), review_doc, intent_doc, proposer, executor)
    messages = planner.build_messages(packet)
    canon.write(out, packet)
    canon.write(_messages_path(out), messages)
    render.heading("Unsigned remediation packet")
    render.packet(packet)
    render.say()
    render.say(f"{render.verdict('PACKET_READY', True)}  {out}")
    render.say(render.paint(f"  packet_sha256 {packet['packet_sha256']}", "dim"))
    render.say(render.paint(f"  instructions decoded back from bytes: {sum(len(t['instructions']) for t in packet['transactions'])} checked", "dim"))
    return OK


def _messages_path(packet_path: str) -> str:
    p = Path(packet_path)
    return str(p.with_name(p.stem + ".messages.json"))


@guarded("verify-plan", out_arg="messages")
def verify_plan(packet: str, rpc: str | None, commitment: str = "finalized", messages: str | None = None) -> int:
    doc = _load(packet, "packet")
    client = _client(rpc, commitment)
    result = verifier.verify_plan(client, doc)
    render.heading("Plan against fresh chain state")
    if result["read"]:
        render.say(f"  read at slots {result['read']['slot_first']}..{result['read']['slot_last']} ({result['read']['commitment']})")
    render.plan_check(result, {t["multisig"]: t["label"] for t in doc.get("transactions", []) if t.get("label")})
    render.say()
    if result["verdict"] == "EXECUTED":
        render.say(f"{render.verdict('EXECUTED', True)}  nothing left to sign; run certify")
        return OK
    if result["verdict"] != "VALID":
        render.say(f"{render.verdict('PLAN_INVALIDATED', False)}  do not sign; scan and review again")
        if messages:
            canon.write(str(messages) + ".diagnostics.json", {"schema_version": DIAGNOSTICS_SCHEMA, "tool": TOOL,
                        "command": "verify-plan", "verdict": "PLAN_INVALIDATED", "blockers": result["reasons"]})
        return BLOCKED
    render.say(f"{render.verdict('VALID', True)}  the packet still matches what was reviewed")
    if messages:
        fresh = planner.build_messages(doc, client.latest_blockhash(), "rpc", result["read"]["slot_last"])
        canon.write(messages, fresh)
        render.say(render.paint(f"  {len(fresh['messages'])} unsigned messages rebuilt on a fresh blockhash and decoded back: {messages}", "dim"))
    return OK


@guarded("certify")
def certify(packet: str, review: str, intent: str, rpc: str | None, out: str, commitment: str = "finalized") -> int:
    record, blockers = record_mod.certify(_client(rpc, commitment), _load(packet, "packet"),
                                          _load(review, "review"), _load(intent, "intent"))
    if record is None:
        raise ExitGuardError(blockers, verdict="NOT_COMPLETE")
    canon.write(out, record)
    labels = {r["state_address"]: r["label"] for r in record["scope"]["resources"] if r.get("label")}
    render.heading("Offboarding record")
    render.say(f"  subject        {record['subject']}")
    render.say(f"  evidence       {record['evidence_source']}   pre slots {record['pre']['slot_first']}..{record['pre']['slot_last']}   "
               f"post slots {record['post']['slot_first']}..{record['post']['slot_last']} ({record['post']['commitment']})")
    render.table(["removed", "treasury", "detail"],
                 [[r["kind"], r["label"] or render.short(r["multisig"]),
                   "+".join(r["permissions"]) if r["kind"] == "member" else f"{inventory.sol(r['amount'])} SOL/{r['period'].lower()}"]
                  for r in record["removed"]])
    render.table(["residual", "decision", "at review", "now"],
                 [[f"{labels.get(r['multisig'], render.short(r['multisig']))} #{r['transaction_index']} {r['type'].replace('Transaction', '')}",
                   r["decision"], r["state_at_review"], r["state_after"]] for r in record["residual_decisions"]])
    render.say(f"  valid until slot {record['expires_at_slot']}; executor_bypass: true")
    render.say()
    render.say(f"{render.verdict('COMPLETE', True)}  {out}")
    render.say(f"  record_sha256 {record['record_sha256']}")
    return OK


@guarded("verify-certificate", out_arg="_none")
def verify_certificate(record: str, expect_sha256: str | None = None, rpc: str | None = None,
                       commitment: str = "finalized") -> int:
    doc = _load(record, "record")
    client = _client(rpc, commitment) if (rpc or os.environ.get("EXITGUARD_RPC_URL")) else None
    result = record_mod.verify_certificate(doc, expect_sha256, client)
    render.heading("Record verification")
    render.certificate(result)
    good = (result["historical_integrity"] == "PASS" and result["content"] == "PASS"
            and result["current_validity"]["status"] in ("CURRENT", "NOT_CHECKED"))
    return OK if good else BLOCKED
