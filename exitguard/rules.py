"""Squads v4 rules ExitGuard relies on, in one place.

These mirror checks in the on-chain program: which proposals can still move,
what a stale index does to each transaction type, and what the multisig
invariant requires after a member is removed.
"""

from __future__ import annotations

from . import squads

TERMINAL = ("Executed", "Rejected", "Cancelled")

# States a transaction slot can be in, from ExitGuard's point of view.
CLOSED = "closed"                # neither account exists any more
TERMINAL_STATE = "terminal"      # executed, rejected or cancelled
INERT = "inert_stale"            # stale index, can no longer be voted on or executed
ORPHAN = "orphan_proposal"       # proposal without its transaction; cannot execute
LATENT = "latent"                # transaction exists, proposal has not been created yet
PENDING = "pending"              # draft or active, still collecting votes
APPROVED = "approved"            # threshold reached, executable
EXECUTING = "executing"          # batch part-way through its children

LIVE_STATES = (LATENT, PENDING, APPROVED, EXECUTING)


def slot_state(multisig: dict, tx_type: str | None, tx: dict | None, proposal: dict | None) -> str:
    """Classify one transaction index.

    A config change bumps stale_transaction_index. After that:
      * proposals at or below the stale index cannot be created, activated or voted on;
      * a ConfigTransaction at or below it cannot execute even if Approved;
      * an Approved VaultTransaction or Batch can still execute. Removing a member
        does not withdraw approvals that already reached threshold.
    """
    if tx is None and proposal is None:
        return CLOSED
    if tx is None:
        return ORPHAN
    status = proposal["status"] if proposal else None
    if status in TERMINAL:
        return TERMINAL_STATE
    stale = int(tx["index"]) <= int(multisig["stale_transaction_index"])
    if status in ("Approved", "Executing"):
        if tx_type == "ConfigTransaction":
            return INERT if stale else APPROVED
        if tx_type == "Batch" and (status == "Executing" or tx["executed_transaction_index"] > 0):
            return EXECUTING
        return APPROVED
    if stale:
        return INERT
    return LATENT if proposal is None else PENDING


def has(member: dict, permission: int) -> bool:
    return bool(member["permissions"] & permission)


def removal_problems(multisig: dict, subject: str) -> list[tuple[str, str]]:
    """Why the program's invariant would reject removing `subject`, as (blocker code, detail)."""
    remaining = [m for m in multisig["members"] if m["key"] != subject]
    problems: list[tuple[str, str]] = []
    if not remaining:
        return [("LAST_MEMBER", "the subject is the only member")]
    voters = sum(1 for m in remaining if has(m, squads.PERM_VOTE))
    if voters < multisig["threshold"]:
        problems.append(
            ("THRESHOLD_UNREACHABLE", f"threshold is {multisig['threshold']} but only {voters} voters would remain")
        )
    for permission, role in (
        (squads.PERM_INITIATE, "proposer"),
        (squads.PERM_VOTE, "voter"),
        (squads.PERM_EXECUTE, "executor"),
    ):
        if not any(has(m, permission) for m in remaining):
            problems.append(("ROLE_WOULD_BE_EMPTY", f"no {role} would remain"))
    return problems


def signing_roles(multisig: dict, subject: str) -> dict:
    """Members other than the subject who can create, approve and execute the remediation."""
    others = [m for m in multisig["members"] if m["key"] != subject]
    return {
        "proposers": [m["key"] for m in others if has(m, squads.PERM_INITIATE)],
        "voters": [m["key"] for m in others if has(m, squads.PERM_VOTE)],
        "executors": [m["key"] for m in others if has(m, squads.PERM_EXECUTE)],
    }


def limit_policy(limit: dict) -> dict:
    """The parts of a spending limit that define who may spend what. Usage counters are left out."""
    return {k: limit[k] for k in ("multisig", "create_key", "vault_index", "mint", "amount", "period",
                                  "members", "destinations")}


def multisig_settings(multisig: dict, without: str | None = None) -> dict:
    """Configuration that an offboarding must not disturb."""
    return {
        "create_key": multisig["create_key"],
        "config_authority": multisig["config_authority"],
        "threshold": multisig["threshold"],
        "time_lock": multisig["time_lock"],
        "rent_collector": multisig["rent_collector"],
        "members": [m for m in multisig["members"] if m["key"] != without],
    }
