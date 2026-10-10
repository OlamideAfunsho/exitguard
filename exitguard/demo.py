"""`exitguard demo`: the whole flow on one machine.

Runs the real commands, over JSON-RPC, against LiteSVM loaded with the Squads
v4 executable captured from mainnet. Signing, which ExitGuard never does, is
played by throwaway demo keys. Everything this writes is LOCAL_SIMULATION.
"""

from __future__ import annotations

import shutil
import tempfile
import time
from pathlib import Path

from . import canon, squads
from .inventory import sol
from .render import heading, paint, say, table, verdict
from .sim.chain import FIXTURES
from .sim.controls import CONTROLS
from .sim.session import Session
from .sim.world import SOL, World, address

DEMO_PORT = 18899
ERRORS = {
    "0xbc4": "Anchor 3012 AccountNotInitialized: the spending limit account no longer exists",
    "0x1774": "Squads 6004 Unauthorized",
}


def _explain(log_line: str) -> str:
    for code, meaning in ERRORS.items():
        if log_line.endswith(code):
            return f"program error {code} ({meaning})"
    return log_line


class Stage:
    def __init__(self, pause: float):
        self.pause = pause
        self.n = 0

    def __call__(self, title: str, note: str = "") -> None:
        if self.n and self.pause:
            time.sleep(self.pause)
        self.n += 1
        say()
        say(paint(f"[{self.n}] {title}", "bold", "cyan"))
        if note:
            say(paint(f"    {note}", "dim"))


def _command(text: str) -> None:
    say()
    say(paint("$ ", "dim") + paint(text, "bold"))


def _spend(world: World, limit: str, who: str, lamports: int, to: str) -> bool:
    vault = squads.vault_pda(world.operations, 0)
    before = world.chain.balance(vault)
    ok, log = world.spend(limit, who, lamports, to)
    moved = before - world.chain.balance(vault)
    outcome = paint("succeeded", "bold", "yellow") if ok else paint("failed", "bold", "green")
    say(f"    {who} spends {sol(lamports)} SOL from the Operations vault through limit `{limit}`: {outcome}")
    say(f"      vault balance {sol(before)} -> {sol(before - moved)} SOL" + ("" if ok else f"   {_explain(log)}"))
    return ok


def run(out: str = "demo-out", pause: float = 0.0) -> int:
    started = time.time()
    stage = Stage(pause)
    out_dir = Path(out)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    capture = canon.load(FIXTURES / "CAPTURE.json")
    failures: list[str] = []

    say(paint("ExitGuard demo", "bold") + "  -  offboarding one wallet from Squads v4 treasuries")
    say(f"  chain     LiteSVM, local. Evidence from this run is labelled LOCAL_SIMULATION.")
    say(f"  program   {squads.PROGRAM_ID}, executable captured from mainnet at slot "
        f"{capture['accounts']['programdata']['read_slot']}")
    say(paint(f"            ELF sha256 {capture['elf_sha256']}", "dim"))

    # ------------------------------------------------------------------ 1
    stage("The organisation", "Two treasuries created by sending real Squads instructions to the captured program.")
    world = World()
    rows = []
    for ms, label in ((world.operations, "Operations treasury"), (world.grants, "Grants treasury")):
        state = squads.decode_account(bytes(world.chain.account(ms).data), "Multisig")[1]
        names = {address(n): n for n in ("ada", "bayo", "chidi", "dana")}
        members = ", ".join(f"{names[m['key']]} ({'+'.join(p[0] for p in squads.permission_names(m['permissions']))})"
                            for m in state["members"])
        rows.append([label, ms, f"{state['threshold']} of {len(state['members'])}", members])
    table(["treasury", "multisig", "threshold", "members (I=initiate V=vote E=execute)"], rows)
    say(f"  dana ({world.subject}) is leaving. That wallet also holds a 2 SOL/week spending limit on Operations.")

    # ------------------------------------------------------------------ 2
    stage("What happens with member removal alone",
          "A separate copy of the same organisation. The team removes dana as a member and stops there.")
    naive = World()
    naive.config_transaction(naive.operations, [{"kind": "RemoveMember", "oldMember": naive.subject}])
    state = squads.decode_account(bytes(naive.chain.account(naive.operations).data), "Multisig")[1]
    still = any(m["key"] == naive.subject for m in state["members"])
    say(f"    RemoveMember executed. dana in Operations members: {'yes' if still else 'no'}")
    if not _spend(naive, "dana-ops", "dana", SOL // 2, "dana-personal"):
        failures.append("member-only removal should have left the limit usable")
    say("    The limit is its own account with its own delegate list. Removing the member did not touch it.")

    # ------------------------------------------------------------------ 3
    stage("Scan the declared scope")
    try:
        s = Session(world, out_dir, quiet=False, port=DEMO_PORT)   # fixed port keeps the documents reproducible
    except OSError:
        s = Session(world, out_dir, quiet=False)
    rpc = s.url
    _command(f"exitguard scan --scope {s.path('scope')} --rpc {rpc} --discover --out {s.path('review')}")
    if s.scan(discover=True) != 0:
        failures.append("scan")

    # ------------------------------------------------------------------ 4
    stage("Decide each row", "The operator fills in decisions.json by hand. Here a script plays the operator.")
    _command(f"exitguard review --review {s.path('review')} --decisions {s.path('decisions')} --out {s.path('intent')}")
    if _quiet_decide(s) != 0:
        failures.append("review")

    # ------------------------------------------------------------------ 5
    stage("Plan the removal and check it against fresh state")
    _command(f"exitguard plan --review {s.path('review')} --intent {s.path('intent')} --rpc {rpc} --out {s.path('packet')}")
    if s.plan() != 0:
        failures.append("plan")
    _command(f"exitguard verify-plan --packet {s.path('packet')} --rpc {rpc} --messages {s.path('messages')}")
    if s.verify() != 0:
        failures.append("verify-plan")

    # ------------------------------------------------------------------ 6
    stage("Members approve and execute", "ExitGuard holds no keys. Demo keys stand in for the members' own Squads tooling; "
                                         "the plan is rechecked before every hand-off.")
    s.quiet = True
    for phase, who in (("create", "ada creates both config transactions and their proposals"),
                       ("approve", "ada and bayo approve"),
                       ("execute", "ada executes")):
        code = s.verify()
        packet_phases = _phases(s)
        say(f"    verify-plan: {verdict('VALID', True) if code == 0 else verdict('PLAN_INVALIDATED', False)}  ({packet_phases})")
        if code != 0:
            failures.append(f"verify before {phase}")
            break
        sent = s.sign(phase)
        say(f"    {who}: {len(sent)} transactions landed")
    s.quiet = False

    # ------------------------------------------------------------------ 7
    stage("Certify the result")
    _command(f"exitguard certify --packet {s.path('packet')} --review {s.path('review')} --intent {s.path('intent')} "
             f"--rpc {rpc} --out {s.path('record')}")
    if s.certify() != 0:
        failures.append("certify")
        say(verdict("demo stopped: certification failed", False))
        return 1
    record = canon.load(s.path("record"))
    say()
    say("  The same spends as before, now against the remediated treasury:")
    if _spend(world, "dana-ops", "dana", SOL // 2, "dana-personal"):
        failures.append("delegated spend should fail after remediation")
    if not _spend(world, "payroll-bot", "payroll-bot", SOL // 4, "payroll-sink"):
        failures.append("retained service limit should still work")

    # ------------------------------------------------------------------ 8
    stage("Verify the record", "Integrity, recorded postconditions and current validity are reported separately.")
    _command(f"exitguard verify-certificate --record {s.path('record')} --expect-sha256 {record['record_sha256'][:16]}.. --rpc {rpc}")
    if s.verify_certificate(record["record_sha256"]) != 0:
        failures.append("verify-certificate")

    say()
    say("  A record is not a lock. ada and bayo now add dana back through ordinary Squads governance:")
    world.config_transaction(world.operations, [{"kind": "AddMember", "key": world.subject, "permissions": 7}])
    _command(f"exitguard verify-certificate --record {s.path('record')} --expect-sha256 {record['record_sha256'][:16]}.. --rpc {rpc}")
    if s.verify_certificate(record["record_sha256"]) == 0:
        failures.append("record should not be current after the subject was re-added")
    s.close()

    # ------------------------------------------------------------------ 9
    stage("Negative controls", "Each one builds a fresh organisation, breaks one thing and runs the same commands.")
    rows = []
    with tempfile.TemporaryDirectory(prefix="exitguard-controls-") as tmp:
        for control in CONTROLS:
            outcome = control.run(Path(tmp) / control.key)
            ok = control.expect in outcome.codes and not outcome.published
            if not ok:
                failures.append(f"control {control.key}: got {sorted(outcome.codes)}, published {outcome.published}")
            rows.append([control.stage, control.title, control.expect, "refused" if ok else "NOT REFUSED"])
    table(["stage", "situation", "blocker raised", "result"], rows,
          styles={3: {"refused": ("green",), "NOT REFUSED": ("bold", "red")}})
    say(f"  {sum(1 for r in rows if r[3] == 'refused')} of {len(rows)} refused. None of them published a packet or a record.")

    # ---------------------------------------------------------------- end
    heading("Files written")
    for name in ("scope", "review", "decisions", "intent", "packet", "packet.messages", "messages", "record"):
        path = Path(s.path(name))
        if path.exists():
            say(f"  {str(path):<34} {path.stat().st_size:>7} bytes")
    say()
    if failures:
        say(verdict("DEMO FAILED", False))
        for f in failures:
            say(f"  {f}")
        return 1
    say(f"{verdict('DEMO PASSED', True)}  in {time.time() - started:.1f}s   record_sha256 {record['record_sha256']}")
    return 0


def _quiet_decide(s: Session) -> int:
    """Fill in the decisions quietly, then show the binding step the way the CLI prints it."""
    from . import commands
    from .sim.session import DAY_OF_SLOTS, default_decision

    review = canon.load(s.path("review"))
    s.quiet = True
    s._run(commands.review, review=s.path("review"), out=s.path("decisions"), init=True)
    s.quiet = False
    decisions = canon.load(s.path("decisions"))
    decisions["expires_at_slot"] = review["read"]["slot_last"] + DAY_OF_SLOTS
    for row in decisions["decisions"]:
        row["decision"], row["reason"] = default_decision(row, review)
    canon.write(s.path("decisions"), decisions)
    return commands.review(review=s.path("review"), decisions=s.path("decisions"), out=s.path("intent"))


def _phases(s: Session) -> str:
    for line in s.output.splitlines():
        line = line.strip()
        if line.endswith(("READY_TO_CREATE", "AWAITING_APPROVAL", "READY_TO_EXECUTE", "CREATED_NOT_PROPOSED", "EXECUTED")):
            return line.rsplit("  ", 1)[-1]
    return "?"
