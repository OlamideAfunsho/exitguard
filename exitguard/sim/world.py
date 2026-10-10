"""The synthetic organisation used by the demo and the tests.

Every account here is created by sending real Squads instructions (built by
the official SDK) to the captured program inside LiteSVM. Nothing is written
into multisig state by hand. Keys are derived from fixed seeds so addresses
are the same on every run; they are throwaway keys with no value anywhere.

Two treasuries:

  Operations   ada, bayo, dana (all permissions), threshold 2
               limit `dana-ops`     2 SOL / week, delegate: dana only
               limit `payroll-bot`  5 SOL / month, delegate: a service key

  Grants       ada, bayo (all), chidi (vote, execute), dana (initiate, vote),
               threshold 2, plus four pieces of unfinished business:
               #1 vault payment, Approved (dana was one of the approvers)
               #2 vault payment through a lookup table, Active
               #3 batch of two payments, Approved
               #4 vault payment with no proposal yet

dana is the wallet being offboarded.
"""

from __future__ import annotations

import base64
import hashlib
import struct

from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer

from .. import sdkworker, squads
from .chain import SimChain, TransactionFailed

SOL = 1_000_000_000
ACTORS = ("ada", "bayo", "chidi", "dana", "payroll-bot", "ops-key", "grants-key", "escrow-key", "side-key", "funder")
PAYEES = ("vendor", "grantee-one", "grantee-two", "grantee-three", "payroll-sink", "dana-personal")

_worker_cache: dict[str, list] = {}


def keypair(name: str) -> Keypair:
    return Keypair.from_seed(hashlib.sha256(f"exitguard-demo:{name}".encode()).digest())


def address(name: str) -> str:
    return str(keypair(name).pubkey())


def to_instruction(j: dict) -> Instruction:
    return Instruction(
        Pubkey.from_string(j["program_id"]),
        base64.b64decode(j["data"]),
        [AccountMeta(Pubkey.from_string(a["pubkey"]), a["is_signer"], a["is_writable"]) for a in j["accounts"]],
    )


def instruction_json(ix: Instruction) -> dict:
    return {
        "program_id": str(ix.program_id),
        "accounts": [
            {"pubkey": str(a.pubkey), "is_signer": a.is_signer, "is_writable": a.is_writable} for a in ix.accounts
        ],
        "data": base64.b64encode(bytes(ix.data)).decode(),
    }


def build(requests: list[dict]) -> list[Instruction]:
    """SDK-built instructions, memoised because world set-up repeats across tests."""
    key = hashlib.sha256(repr(requests).encode()).hexdigest()
    if key not in _worker_cache:
        _worker_cache[key] = sdkworker.call(requests)
    return [to_instruction(j) for j in _worker_cache[key]]


def lookup_table_bytes(addresses: list[str], last_extended_slot: int = 0) -> bytes:
    header = struct.pack("<IQQB", 1, squads.U64_MAX, last_extended_slot, 0) + b"\0" * 33 + b"\0\0"
    return header + b"".join(squads.decode_address(a) for a in addresses)


class World:
    def __init__(self, shared_limit: bool = False, controlled: bool = False):
        self.chain = SimChain()
        self.keys = {name: keypair(name) for name in ACTORS}
        self.payees = {name: address(name) for name in PAYEES}
        self.subject = address("dana")
        self.limits: dict[str, str] = {}
        self.labels: dict[str, str] = {}
        self.lookup_table = address("grants-lookup-table")

        for name in ACTORS:
            self.chain.airdrop(self.keys[name].pubkey(), 20 * SOL)

        self.operations = self._create_multisig(
            "ops-key", "Operations treasury", [("ada", 7), ("bayo", 7), ("dana", 7)], threshold=2
        )
        self.grants = self._create_multisig(
            "grants-key", "Grants treasury", [("ada", 7), ("bayo", 7), ("chidi", 6), ("dana", 3)], threshold=2
        )
        # A treasury nobody put in the manifest. The scan's discovery pass should still notice it.
        self.side = self._create_multisig("side-key", "Side project", [("chidi", 7), ("dana", 7)], threshold=1)
        self.escrow = None
        for ms in (self.operations, self.grants):
            self.chain.airdrop(squads.vault_pda(ms, 0), 50 * SOL)

        self.add_limit(self.operations, "dana-ops", ["dana"], 2 * SOL, "Week", [])
        self.add_limit(self.operations, "payroll-bot", ["payroll-bot"], 5 * SOL, "Month", ["payroll-sink"])
        if shared_limit:
            self.add_limit(self.operations, "shared-travel", ["dana", "bayo"], 1 * SOL, "Month", [])
        self._grants_backlog()
        if controlled:
            self.escrow = self._create_multisig(
                "escrow-key", "Vendor escrow", [("ada", 7), ("bayo", 7), ("dana", 7)], threshold=2, authority="ada"
            )

    # ------------------------------------------------------------- set-up

    def _create_multisig(self, key_name: str, label: str, members, threshold: int, authority: str | None = None) -> str:
        create_key = self.keys[key_name]
        ms = squads.multisig_pda(str(create_key.pubkey()))
        _, config = squads.decode_account(bytes(self.chain.account(squads.program_config_pda()).data), "ProgramConfig")
        [ix] = build(
            [
                {
                    "op": "multisigCreateV2",
                    "args": {
                        "treasury": config["treasury"],
                        "creator": address("funder"),
                        "multisig": ms,
                        "configAuthority": address(authority) if authority else None,
                        "threshold": threshold,
                        "members": sorted(
                            ({"key": address(n), "permissions": p} for n, p in members), key=lambda m: m["key"]
                        ),
                        "timeLock": 0,
                        "createKey": str(create_key.pubkey()),
                        "rentCollector": None,
                    },
                }
            ]
        )
        self.chain.send([ix], self.keys["funder"], [create_key])
        self.labels[ms] = label
        return ms

    def take_index(self, ms: str) -> int:
        state = squads.decode_account(bytes(self.chain.account(ms).data), "Multisig")[1]
        return int(state["transaction_index"]) + 1

    def config_transaction(self, ms: str, actions: list[dict], spending_limits: list[str] | None = None,
                           creator: str = "ada", approvers: tuple[str, ...] = ("ada", "bayo"),
                           executor: str = "ada") -> int:
        """Create, approve and execute one config transaction the ordinary way."""
        index = self.take_index(ms)
        base = {"multisig": ms, "transactionIndex": str(index)}
        ixs = build(
            [
                {"op": "configTransactionCreate", "args": {**base, "creator": address(creator), "actions": actions}},
                {"op": "proposalCreate", "args": {**base, "creator": address(creator)}},
                *[{"op": "proposalApprove", "args": {**base, "member": address(a)}} for a in approvers],
                {
                    "op": "configTransactionExecute",
                    "args": {
                        **base,
                        "member": address(executor),
                        "rentPayer": address(executor),
                        "spendingLimits": spending_limits or [],
                    },
                },
            ]
        )
        self.chain.send(ixs[:2], self.keys[creator])
        for n, approver in enumerate(approvers):
            self.chain.send([ixs[2 + n]], self.keys[approver])
        self.chain.send([ixs[-1]], self.keys[executor])
        return index

    def add_limit(self, ms: str, name: str, delegates: list[str], lamports: int, period: str,
                  destinations: list[str]) -> str:
        create_key = address(f"limit:{name}")
        pda = squads.spending_limit_pda(ms, create_key)
        self.config_transaction(
            ms,
            [
                {
                    "kind": "AddSpendingLimit",
                    "createKey": create_key,
                    "vaultIndex": 0,
                    "mint": squads.DEFAULT_PUBKEY,
                    "amount": str(lamports),
                    "period": period,
                    "members": sorted(address(d) for d in delegates),
                    "destinations": [self.payees[d] for d in destinations],
                }
            ],
            spending_limits=[pda],
        )
        self.limits[name] = pda
        return pda

    def _payment(self, ms: str, to: str, lamports: int) -> dict:
        vault = Pubkey.from_string(squads.vault_pda(ms, 0))
        ix = transfer(TransferParams(from_pubkey=vault, to_pubkey=Pubkey.from_string(to), lamports=lamports))
        return {
            "payer": str(vault),
            "recentBlockhash": squads.DEFAULT_PUBKEY,
            "instructions": [instruction_json(ix)],
        }

    def vault_transaction(self, ms: str, creator: str, to: str, lamports: int, tables: list[dict] | None = None) -> int:
        index = self.take_index(ms)
        [ix] = build(
            [
                {
                    "op": "vaultTransactionCreate",
                    "args": {
                        "multisig": ms,
                        "transactionIndex": str(index),
                        "creator": address(creator),
                        "vaultIndex": 0,
                        "message": self._payment(ms, to, lamports),
                        "lookupTables": tables or [],
                    },
                }
            ]
        )
        self.chain.send([ix], self.keys[creator])
        return index

    def propose(self, ms: str, index: int, creator: str, approvers: tuple[str, ...] = (), draft: bool = False) -> None:
        base = {"multisig": ms, "transactionIndex": str(index)}
        ixs = build(
            [
                {"op": "proposalCreate", "args": {**base, "creator": address(creator), "isDraft": draft}},
                *[{"op": "proposalApprove", "args": {**base, "member": address(a)}} for a in approvers],
            ]
        )
        self.chain.send([ixs[0]], self.keys[creator])
        for n, approver in enumerate(approvers):
            self.chain.send([ixs[1 + n]], self.keys[approver])

    def _grants_backlog(self) -> None:
        ms = self.grants
        # #1 approved grant payment; dana's vote is one of the two approvals
        first = self.vault_transaction(ms, "ada", self.payees["grantee-one"], 3 * SOL // 2)
        self.propose(ms, first, "ada", ("ada", "dana"))

        # #2 payment whose destination is only reachable through a lookup table
        table = [self.payees["grantee-two"], self.payees["vendor"]]
        self.chain.set_account(self.lookup_table, lookup_table_bytes(table), squads.ALT_PROGRAM)
        second = self.vault_transaction(
            ms, "bayo", self.payees["grantee-two"], SOL, [{"key": self.lookup_table, "addresses": table}]
        )
        self.propose(ms, second, "bayo", ("dana",))

        # #3 approved batch with two children still to run
        batch = self.take_index(ms)
        base = {"multisig": ms, "batchIndex": str(batch), "vaultIndex": 0}
        ixs = build(
            [
                {"op": "batchCreate", "args": {**base, "creator": address("ada")}},
                {"op": "proposalCreate", "args": {"multisig": ms, "transactionIndex": str(batch),
                                                  "creator": address("ada"), "isDraft": True}},
                *[
                    {
                        "op": "batchAddTransaction",
                        "args": {**base, "member": address("ada"), "transactionIndex": n + 1,
                                 "message": self._payment(ms, self.payees[to], SOL // 4)},
                    }
                    for n, to in enumerate(("grantee-one", "grantee-three"))
                ],
                {"op": "proposalActivate", "args": {"multisig": ms, "transactionIndex": str(batch),
                                                    "member": address("ada")}},
                *[{"op": "proposalApprove", "args": {"multisig": ms, "transactionIndex": str(batch),
                                                     "member": address(a)}} for a in ("ada", "bayo")],
            ]
        )
        self.chain.send(ixs[:2], self.keys["ada"])
        for ix in ixs[2:5]:
            self.chain.send([ix], self.keys["ada"])
        self.chain.send([ixs[5]], self.keys["ada"])
        self.chain.send([ixs[6]], self.keys["bayo"])

        # #4 created by dana, never proposed
        self.vault_transaction(ms, "dana", self.payees["dana-personal"], 4 * SOL)

    # ------------------------------------------------------------ actions

    def spend(self, limit: str, delegate: str, lamports: int, destination: str) -> tuple[bool, str]:
        """Try a delegated SOL spend. Returns (succeeded, last program log line)."""
        pda = self.limits[limit]
        acct = self.chain.account(pda)
        if acct is not None:
            ms = squads.decode_account(bytes(acct.data), "SpendingLimit")[1]["multisig"]
        else:
            ms = self.operations
        [ix] = build(
            [
                {
                    "op": "spendingLimitUse",
                    "args": {
                        "multisig": ms,
                        "member": address(delegate),
                        "spendingLimit": pda,
                        "vaultIndex": 0,
                        "amount": lamports,
                        "decimals": 9,
                        "destination": self.payees[destination],
                    },
                }
            ]
        )
        try:
            self.chain.send([ix], self.keys[delegate])
            return True, "ok"
        except TransactionFailed as exc:
            reason = next((line for line in reversed(exc.logs) if "Error" in line or "failed" in line), exc.err)
            return False, reason

    def scope(self, review_id: str = "offboard-dana-2026-10") -> dict:
        resources = [
            {"state_address": self.operations, "scope": "manifest_owned", "label": self.labels[self.operations]},
            {"state_address": self.grants, "scope": "manifest_owned", "label": self.labels[self.grants]},
        ]
        if self.escrow:
            resources.append(
                {"state_address": self.escrow, "scope": "manifest_owned", "label": self.labels[self.escrow]}
            )
        return {
            "schema_version": "exitguard.review-scope.v1",
            "organization_id": "lagoon-labs",
            "review_id": review_id,
            "squads_program_id": squads.PROGRAM_ID,
            "scope_attested_complete": True,
            "resources": resources,
            "subject_wallets": [
                {"address": self.subject, "provenance": "operator_attested", "label": "dana (departing engineer)"}
            ],
            "reviewer": {"wallet": address("ada"), "attested_at": "2026-10-10T09:00:00Z"},
        }
