"""Named blockers. Anything that stops a clean result has one of these codes."""

from __future__ import annotations

from dataclasses import dataclass

CODES: dict[str, str] = {
    # input
    "SCOPE_INVALID": "the scope manifest failed validation",
    "INTENT_INVALID": "the intent does not bind to this review",
    "INPUT_TAMPERED": "a document does not match its own digest",
    # reads
    "RPC_ERROR": "an RPC call failed",
    "RPC_INCOMPLETE_RESULT": "an RPC call returned fewer results than were asked for",
    "CLUSTER_MISMATCH": "the endpoint is a different cluster from the one reviewed",
    "STATE_UNSTABLE": "state kept changing between collection passes",
    # accounts
    "ACCOUNT_MISSING": "a required account does not exist",
    "ACCOUNT_FOREIGN_OWNER": "an account is not owned by the expected program",
    "ACCOUNT_MALFORMED": "account bytes do not decode under the pinned layout",
    "ACCOUNT_UNSUPPORTED": "account type or version is not supported",
    "ACCOUNT_BINDING_MISMATCH": "an account does not point back at its parent or index",
    "ALT_MISSING": "an address lookup table referenced by a payload is unavailable",
    "ALT_INDEX_OUT_OF_RANGE": "a lookup index is past the end of its table",
    "MESSAGE_INDEX_OUT_OF_RANGE": "an instruction references a key index that does not exist",
    "BATCH_CHILD_MISSING": "a remaining batch child transaction is missing",
    "PROGRAM_UNVERIFIED": "the Squads program or its ProgramData could not be bound",
    # policy
    "SHARED_RESOURCE": "the resource is declared shared_or_external",
    "CONTROLLED_MULTISIG": "the multisig has a non-default config authority",
    "SHARED_SPENDING_LIMIT": "the spending limit has delegates other than the subject",
    "LAST_MEMBER": "removing the subject would leave no members",
    "THRESHOLD_UNREACHABLE": "removal would need a threshold change",
    "ROLE_WOULD_BE_EMPTY": "removal would leave no proposer, voter or executor",
    "NO_ELIGIBLE_SIGNER": "no remaining member can fill a required signing role",
    "SUBJECT_IS_CONFIG_AUTHORITY": "the subject wallet is the config authority",
    # decisions
    "DECISION_UNKNOWN": "a row has no operator decision",
    "DECISION_BLOCKED": "a row is blocked and needs manual resolution",
    "DECISION_NOT_ALLOWED": "the decision is not available for this row",
    "KEEP_INVALID": "a KEEP decision lacks a reason or a usable expiry",
    "RETAINED_SUBJECT_AUTHORITY": "in-scope subject authority was kept",
    "RESIDUAL_UNDECIDED": "a residual action has no decision bound to its payload",
    "RESIDUAL_REVOKE_PENDING": "a residual marked REVOKE is still live",
    # plan
    "REVIEW_DRIFT": "state changed since the review",
    "PROPOSAL_APPEARED": "a proposal that was absent at review now exists",
    "NEW_DEPENDENCY": "an account appeared that the review never saw",
    "PROGRAM_DRIFT": "the program binding changed",
    "INDEX_COLLISION": "the planned transaction index is taken by something else",
    "PACKET_DECODE_MISMATCH": "emitted instructions do not decode to the reviewed actions",
    "PACKET_TAMPERED": "the packet does not match its digest",
    # certification
    "SUBJECT_STILL_MEMBER": "the subject is still a member",
    "SUBJECT_STILL_DELEGATE": "the subject is still a spending limit delegate",
    "LIMIT_NOT_CLOSED": "a spending limit planned for removal still exists",
    "PROPOSAL_NOT_EXECUTED": "the remediation proposal is not Executed",
    "RETAINED_STATE_CHANGED": "retained authority or unrelated configuration changed",
    "NOT_FINALIZED": "live reads were not taken at finalized commitment",
    "EXPIRY_INVALID": "an expiry is missing, malformed or already passed",
}


@dataclass(frozen=True)
class Blocker:
    code: str
    subject: str
    detail: str = ""

    def __post_init__(self) -> None:
        if self.code not in CODES:
            raise ValueError(f"unknown blocker code {self.code}")

    def to_json(self) -> dict:
        return {"code": self.code, "subject": self.subject, "detail": self.detail}

    @staticmethod
    def from_json(d: dict) -> "Blocker":
        return Blocker(d["code"], d["subject"], d.get("detail", ""))

    def line(self) -> str:
        tail = f" - {self.detail}" if self.detail else ""
        return f"{self.code}  {self.subject}{tail}"


class ExitGuardError(Exception):
    """Raised when a command must stop. Carries the blockers that caused it."""

    def __init__(self, blockers: list[Blocker] | Blocker, verdict: str = "BLOCKED"):
        if isinstance(blockers, Blocker):
            blockers = [blockers]
        self.blockers = blockers
        self.verdict = verdict
        super().__init__("; ".join(b.line() for b in blockers))


def sort_unique(blockers: list[Blocker]) -> list[Blocker]:
    return sorted(set(blockers), key=lambda b: (b.code, b.subject, b.detail))
