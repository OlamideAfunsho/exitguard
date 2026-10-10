"""Command line entry point: python -m exitguard <command>."""

from __future__ import annotations

import argparse
import sys

from . import __version__, commands

RPC_HELP = "RPC URL (or set EXITGUARD_RPC_URL so the key stays out of shell history)"


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="exitguard",
        description="Offboard one wallet from declared Squads v4 treasuries: members, spending limits and a verifiable record.",
    )
    p.add_argument("--version", action="version", version=f"exitguard {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="command")

    def rpc_args(s: argparse.ArgumentParser) -> None:
        s.add_argument("--rpc", help=RPC_HELP)
        s.add_argument("--commitment", default="finalized", choices=("processed", "confirmed", "finalized"))

    s = sub.add_parser("scan", help="read the declared scope and write review.json")
    s.add_argument("--scope", required=True)
    s.add_argument("--out", default="review.json")
    s.add_argument("--discover", action="store_true",
                   help="also probe for subject authority outside the declared scope (best effort)")
    rpc_args(s)

    s = sub.add_parser("review", help="bind operator decisions to a review and write intent.json")
    s.add_argument("--review", required=True)
    s.add_argument("--decisions", help="decisions file filled in by the operator")
    s.add_argument("--init", action="store_true", help="write a decisions template instead of an intent")
    s.add_argument("--out", default="intent.json")

    s = sub.add_parser("plan", help="write the unsigned remediation packet")
    s.add_argument("--review", required=True)
    s.add_argument("--intent", required=True)
    s.add_argument("--scope", help="optional; checked against the scope the review was made from")
    s.add_argument("--proposer", help="member that creates the transaction (default: first eligible)")
    s.add_argument("--executor", help="member that executes it (default: first eligible)")
    s.add_argument("--out", default="packet.json")
    rpc_args(s)

    s = sub.add_parser("verify-plan", help="check a packet against fresh chain state")
    s.add_argument("--packet", required=True)
    s.add_argument("--messages", help="on VALID, write unsigned messages on a fresh blockhash to this file")
    rpc_args(s)

    s = sub.add_parser("certify", help="verify the post-execution state and write record.json")
    s.add_argument("--packet", required=True)
    s.add_argument("--review", required=True)
    s.add_argument("--intent", required=True)
    s.add_argument("--out", default="record.json")
    rpc_args(s)

    s = sub.add_parser("verify-certificate", help="check a record's integrity and, with --rpc, whether it still holds")
    s.add_argument("--record", required=True)
    s.add_argument("--expect-sha256", help="digest obtained from a channel you trust")
    rpc_args(s)

    s = sub.add_parser("demo", help="run the whole flow locally against the captured Squads program")
    s.add_argument("--out", default="demo-out")
    s.add_argument("--pause", type=float, default=0.0, help="seconds to wait between sections")

    s = sub.add_parser("localnet", help="start the local simulated chain with the demo organisation and keep it running")
    s.add_argument("--port", type=int, default=8899)
    s.add_argument("--scope-out", default="scope.json", help="where to write the demo scope manifest")

    s = sub.add_parser("local-sign", help="demo only: sign and send one phase of a packet with the throwaway demo keys")
    s.add_argument("--packet", required=True)
    s.add_argument("--messages", required=True)
    s.add_argument("--phase", required=True, choices=("create", "approve", "execute"))
    s.add_argument("--rpc", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = vars(parser().parse_args(argv))
    command = args.pop("command")
    if command == "demo":
        from . import demo
        return demo.run(args["out"], args["pause"])
    if command == "localnet":
        from .sim import session
        return session.serve_forever(args["port"], args["scope_out"])
    if command == "local-sign":
        from .sim import session
        return session.local_sign(args["packet"], args["messages"], args["phase"], args["rpc"])
    if command == "review" and args["init"] and args["out"] == "intent.json":
        args["out"] = "decisions.json"
    handler = getattr(commands, command.replace("-", "_"))
    return handler(**args)


if __name__ == "__main__":
    sys.exit(main())
