"""Drive the real commands against a simulated world.

Used by the demo and the tests. Session calls the same functions the CLI
calls, with file paths in a working directory, talking JSON-RPC over HTTP to
the local chain. The only thing it adds is the part ExitGuard deliberately
does not do: signing. sign_and_send() stands in for members approving in
their normal Squads tooling, using the throwaway demo keys.
"""

from __future__ import annotations

import base64
import contextlib
import io
from pathlib import Path

from solders.message import Message
from solders.transaction import Transaction

from .. import canon, commands
from ..rpc import RpcClient
from .world import World

DAY_OF_SLOTS = 216_000


def sign_and_send(rpc_url: str, messages: dict, keys: dict, phase: str) -> list[str]:
    """Sign the unsigned messages of one phase (create, approve, execute) and submit them."""
    client = RpcClient(rpc_url)
    sent = []
    approvals: dict[tuple, int] = {}
    for m in messages["messages"]:
        step = m["step"].split(":")[0]
        if step != phase:
            continue
        key = (m["multisig"], m["transaction_index"])
        if step == "approve":
            needed = messages.get("approvals_required", {}).get(m["multisig"], 2)
            if approvals.get(key, 0) >= needed:
                continue
            approvals[key] = approvals.get(key, 0) + 1
        signer = keys[m["signer"]]
        message = Message.from_bytes(base64.b64decode(m["message"]))
        tx = Transaction.new_unsigned(message)
        tx.sign([signer], message.recent_blockhash)
        sent.append(client.call("sendTransaction", [base64.b64encode(bytes(tx)).decode(), {"encoding": "base64"}]))
    return sent


def default_decision(row: dict, review: dict) -> tuple[str, str]:
    """How the demo operator decides. Real operators edit the decisions file by hand."""
    authority = next((a for a in review["authorities"] if a["authority_id"] == row["id"]), None)
    if authority is not None:
        if authority["classification"] == "blocked":
            return "BLOCKED", "needs manual work: " + ", ".join(b["code"] for b in authority["blockers"])
        return "REVOKE", "dana left the company on 2026-10-09"
    residual = next(r for r in review["residuals"] if r["residual_id"] == row["id"])
    if "created by the subject" in residual["subject_involvement"] and residual["state"] == "latent":
        return "REVOKE", "dana created this payment to dana's own wallet; it must not be proposed"
    if residual["state"] == "pending":
        return "KEEP", "still collecting votes; finance re-proposes it if it goes stale"
    return "KEEP", "approved before the departure; the approval stands as the organisation's decision"


class Session:
    def __init__(self, world: World, out_dir: str | Path, quiet: bool = True, port: int = 0):
        self.world = world
        self.dir = Path(out_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.quiet = quiet
        self.server = world.chain.serve(port)
        self.url = self.server.url
        self.output = ""
        self.keys = {str(k.pubkey()): k for k in world.keys.values()}
        canon.write(self.path("scope"), world.scope())

    def close(self) -> None:
        self.server.close()

    def path(self, name: str) -> str:
        return str(self.dir / f"{name}.json")

    def _run(self, fn, **kwargs) -> int:
        if not self.quiet:
            return fn(**kwargs)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = fn(**kwargs)
        self.output = buffer.getvalue()
        return code

    def codes(self, name: str) -> set[str]:
        """Blocker codes from the diagnostics written for `name`, or from the document itself."""
        diag = Path(self.path(name) + ".diagnostics.json")
        if diag.exists():
            return {b["code"] for b in canon.load(diag)["blockers"]}
        doc = canon.load(self.path(name)) if Path(self.path(name)).exists() else {}
        return {b["code"] for b in doc.get("blockers", [])}

    # ----------------------------------------------------------- commands

    def scan(self, discover: bool = False, commitment: str = "finalized") -> int:
        return self._run(commands.scan, scope=self.path("scope"), rpc=self.url, out=self.path("review"),
                         commitment=commitment, discover=discover)

    def decide(self, expires_in: int = DAY_OF_SLOTS, overrides: dict | None = None) -> int:
        review = canon.load(self.path("review"))
        self._run(commands.review, review=self.path("review"), out=self.path("decisions"), init=True)
        decisions = canon.load(self.path("decisions"))
        decisions["expires_at_slot"] = (review["read"]["slot_last"] or 0) + expires_in
        for row in decisions["decisions"]:
            row["decision"], row["reason"] = default_decision(row, review)
            for prefix, (decision, reason) in (overrides or {}).items():
                if row["id"].startswith(prefix):
                    row["decision"], row["reason"] = decision, reason
        canon.write(self.path("decisions"), decisions)
        return self._run(commands.review, review=self.path("review"), decisions=self.path("decisions"),
                         out=self.path("intent"))

    def plan(self) -> int:
        return self._run(commands.plan, review=self.path("review"), intent=self.path("intent"), rpc=self.url,
                         out=self.path("packet"), scope=self.path("scope"))

    def verify(self, messages: bool = True) -> int:
        return self._run(commands.verify_plan, packet=self.path("packet"), rpc=self.url,
                         messages=self.path("messages") if messages else None)

    def sign(self, phase: str) -> list[str]:
        messages = canon.load(self.path("messages"))
        packet = canon.load(self.path("packet"))
        messages["approvals_required"] = {t["multisig"]: t["signers"]["approvals_required"] for t in packet["transactions"]}
        return sign_and_send(self.url, messages, self.keys, phase)

    def execute(self) -> None:
        """Members create, approve and execute, rechecking the plan before each hand-off."""
        for phase in ("create", "approve", "execute"):
            if self.verify() != 0:
                raise RuntimeError(f"plan no longer valid before {phase}: {self.output}")
            self.sign(phase)

    def certify(self, commitment: str = "finalized") -> int:
        return self._run(commands.certify, packet=self.path("packet"), review=self.path("review"),
                         intent=self.path("intent"), rpc=self.url, out=self.path("record"), commitment=commitment)

    def verify_certificate(self, expect: str | None = None, with_rpc: bool = True) -> int:
        return self._run(commands.verify_certificate, record=self.path("record"), expect_sha256=expect,
                         rpc=self.url if with_rpc else None)

    def through_plan(self, **decide_kwargs) -> None:
        for step, code in (("scan", self.scan()), ("review", self.decide(**decide_kwargs)), ("plan", self.plan())):
            if code != 0:
                raise RuntimeError(f"{step} failed: {self.output}")


def serve_forever(port: int, scope_out: str) -> int:
    """`exitguard localnet`: the demo organisation on a local port, for running the commands by hand."""
    import time

    world = World()
    server = world.chain.serve(port)
    canon.write(scope_out, world.scope())
    print(f"local simulated chain at {server.url}  (LiteSVM, captured Squads v4 program)")
    print(f"demo scope written to {scope_out}; subject wallet is {world.subject}")
    print("Ctrl+C to stop. State is lost when this process exits.", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.close()
    return 0


def local_sign(packet_path: str, messages_path: str, phase: str, rpc_url: str) -> int:
    """`exitguard local-sign`: stand-in for members approving in Squads. Refuses anything but the simulator."""
    from .world import ACTORS, keypair

    if RpcClient(rpc_url).version().get("exitguard-simulation") is not True:
        print("local-sign only talks to the local simulator. On a real cluster, members sign in their own Squads tooling.")
        return 2
    packet, messages = canon.load(packet_path), canon.load(messages_path)
    messages["approvals_required"] = {t["multisig"]: t["signers"]["approvals_required"] for t in packet["transactions"]}
    keys = {str(keypair(n).pubkey()): keypair(n) for n in ACTORS}
    sent = sign_and_send(rpc_url, messages, keys, phase)
    print(f"{phase}: {len(sent)} transactions signed with demo keys and landed")
    return 0
