"""Collect everything the declared scope depends on, and prove the read was complete.

One pass walks: program binding -> declared multisigs -> their spending limits
-> every Transaction and Proposal PDA from 1 to transaction_index -> remaining
batch children -> lookup tables used by live payloads. Every address asked for
ends up with a status. A pass is repeated until two consecutive passes agree,
because the calls are not an atomic snapshot.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import canon, rules, squads
from .blockers import Blocker, sort_unique
from .rpc import Read, RpcClient, RpcFailure, identify_cluster

MAX_PASSES = 4
LIMIT_FIRST_DELEGATE_OFFSET = 135   # disc 8 + multisig 32 + create_key 32 + vault 1 + mint 32 + amount 8
                                    # + period 1 + remaining 8 + last_reset 8 + bump 1 + vec length 4
MEMBER_VEC_OFFSETS = (100, 132)     # first member key; second value is with a rent collector set


@dataclass
class Slot:
    """One transaction index of one multisig."""
    index: int
    transaction_address: str
    proposal_address: str
    tx_type: str | None = None
    tx: dict | None = None
    proposal: dict | None = None
    state: str = "unknown"
    children: list[dict] = field(default_factory=list)
    lookup_tables: list[str] = field(default_factory=list)


@dataclass
class Collection:
    scope: dict
    cluster: dict
    reads: dict[str, Read] = field(default_factory=dict)
    roles: dict[str, str] = field(default_factory=dict)
    multisigs: dict[str, dict] = field(default_factory=dict)
    limits: dict[str, dict[str, dict]] = field(default_factory=dict)
    slots: dict[str, list[Slot]] = field(default_factory=dict)
    tables: dict[str, dict] = field(default_factory=dict)
    program: dict = field(default_factory=dict)
    blockers: list[Blocker] = field(default_factory=list)
    passes: int = 0
    rpc: dict = field(default_factory=dict)
    discovery: dict | None = None

    def fingerprint(self) -> dict[str, str]:
        return {address: self.reads[address].mark() for address in sorted(self.reads)}

    def state_digest(self) -> str:
        return canon.digest(self.fingerprint())

    def block(self, code: str, subject: str, detail: str = "") -> None:
        self.blockers.append(Blocker(code, subject, detail))


def _require(col: Collection, read: Read, what: str, owner: str) -> bool:
    """Check a read is present and owned by `owner`; record the right blocker if not."""
    if read.status == "error":
        col.block("RPC_INCOMPLETE_RESULT" if "asked for" in (read.error or "") else "RPC_ERROR",
                  read.address, f"{what}: {read.error}")
        return False
    if read.status == "absent":
        col.block("ACCOUNT_MISSING", read.address, f"{what} does not exist")
        return False
    if read.owner != owner:
        col.block("ACCOUNT_FOREIGN_OWNER", read.address, f"{what} is owned by {read.owner}")
        return False
    return True


def _decode(col: Collection, read: Read, what: str, expect) -> tuple[str, dict] | None:
    try:
        return squads.decode_account(read.data, expect)
    except squads.DecodeError as exc:
        col.block(exc.code, read.address, f"{what}: {exc.detail}")
        return None


def _read_all(client: RpcClient, col: Collection, wanted: dict[str, str]) -> None:
    missing = [a for a in wanted if a not in col.reads]
    col.reads.update(client.get_multiple(missing))
    for address, role in wanted.items():
        col.roles.setdefault(address, role)


def _bind_program(client: RpcClient, col: Collection) -> None:
    program_id = col.scope["squads_program_id"]
    programdata = squads.programdata_address(program_id)
    _read_all(client, col, {program_id: "program", programdata: "programdata"})
    prog, pdata = col.reads[program_id], col.reads[programdata]
    ok = True
    for read, what in ((prog, "Squads program"), (pdata, "Squads ProgramData")):
        if read.status != "present" or read.owner != squads.BPF_UPGRADEABLE_LOADER:
            col.block("PROGRAM_UNVERIFIED", read.address,
                      f"{what}: {read.error or read.status}, owner {read.owner}")
            ok = False
    if not ok:
        return
    try:
        if not prog.executable or squads.decode_program(prog.data) != programdata:
            raise squads.DecodeError("ACCOUNT_BINDING_MISMATCH", "program does not point at its derived ProgramData")
        header = squads.decode_programdata(pdata.data)
    except squads.DecodeError as exc:
        col.block("PROGRAM_UNVERIFIED", program_id, exc.detail)
        return
    col.program = {
        "program_id": program_id,
        "program_owner": prog.owner,
        "program_sha256": prog.sha256,
        "programdata_address": programdata,
        "programdata_owner": pdata.owner,
        "programdata_sha256": pdata.sha256,
        "deploy_slot": header["deploy_slot"],
        "upgrade_authority": header["upgrade_authority"],
        "elf_sha256": header["elf_sha256"],
    }


def _discover_limits(client: RpcClient, col: Collection, multisig: str) -> None:
    program_id = col.scope["squads_program_id"]
    filters = [
        {"memcmp": {"offset": 0, "bytes": squads.b58encode(squads.DISC["SpendingLimit"])}},
        {"memcmp": {"offset": 8, "bytes": multisig}},
    ]
    try:
        _slot, reads = client.program_accounts(program_id, filters)
    except RpcFailure as exc:
        col.block("RPC_ERROR", f"spending-limits:{multisig}", f"limit discovery failed: {exc}")
        return
    found: dict[str, dict] = {}
    for read in sorted(reads, key=lambda r: r.address):
        col.reads[read.address] = read
        col.roles[read.address] = f"spending_limit:{multisig}"
        if not _require(col, read, "spending limit", program_id):
            continue
        decoded = _decode(col, read, "spending limit", "SpendingLimit")
        if decoded is None:
            continue
        limit = decoded[1]
        if limit["multisig"] != multisig or squads.spending_limit_pda(multisig, limit["create_key"], program_id) != read.address:
            col.block("ACCOUNT_BINDING_MISMATCH", read.address, "spending limit does not derive from this multisig")
            continue
        found[read.address] = limit
    col.limits[multisig] = found


def _walk_transactions(client: RpcClient, col: Collection, multisig: str) -> None:
    program_id = col.scope["squads_program_id"]
    state = col.multisigs[multisig]
    last = int(state["transaction_index"])
    slots = [
        Slot(i, squads.transaction_pda(multisig, i, program_id), squads.proposal_pda(multisig, i, program_id))
        for i in range(1, last + 1)
    ]
    wanted = {}
    for s in slots:
        wanted[s.transaction_address] = f"transaction:{multisig}:{s.index}"
        wanted[s.proposal_address] = f"proposal:{multisig}:{s.index}"
    _read_all(client, col, wanted)

    for s in slots:
        usable = True
        tx_read, prop_read = col.reads[s.transaction_address], col.reads[s.proposal_address]
        for read, what, expect in (
            (tx_read, f"transaction #{s.index}", squads.TRANSACTION_TYPES),
            (prop_read, f"proposal #{s.index}", "Proposal"),
        ):
            if read.status == "absent":
                continue
            if not _require(col, read, what, program_id):
                usable = False
                continue
            decoded = _decode(col, read, what, expect)
            if decoded is None:
                usable = False
                continue
            name, fields = decoded
            index_field = fields["transaction_index"] if name == "Proposal" else fields["index"]
            if fields["multisig"] != multisig or int(index_field) != s.index:
                col.block("ACCOUNT_BINDING_MISMATCH", read.address, f"{what} does not point back at its multisig and index")
                usable = False
                continue
            if name == "Proposal":
                s.proposal = fields
            else:
                s.tx_type, s.tx = name, fields
        s.state = rules.slot_state(state, s.tx_type, s.tx, s.proposal) if usable else "unknown"
    col.slots[multisig] = slots

    # Children of batches that can still run.
    child_wanted = {}
    for s in slots:
        if s.tx_type == "Batch" and s.state in rules.LIVE_STATES:
            for n in range(s.tx["executed_transaction_index"] + 1, s.tx["size"] + 1):
                address = squads.batch_transaction_pda(multisig, s.index, n, program_id)
                s.children.append({"index": n, "address": address, "message": None})
                child_wanted[address] = f"batch_child:{multisig}:{s.index}:{n}"
    _read_all(client, col, child_wanted)
    for s in slots:
        for child in s.children:
            read = col.reads[child["address"]]
            what = f"batch #{s.index} child {child['index']}"
            if read.status == "absent":
                col.block("BATCH_CHILD_MISSING", child["address"], f"{what} is required by the batch header but does not exist")
                continue
            if not _require(col, read, what, program_id):
                continue
            decoded = _decode(col, read, what, "VaultBatchTransaction")
            if decoded is not None:
                child["message"] = decoded[1]["message"]

    # Lookup tables used by payloads that can still run.
    table_wanted = {}
    for s in slots:
        if s.state not in rules.LIVE_STATES:
            continue
        messages = [c["message"] for c in s.children if c["message"]]
        if s.tx_type == "VaultTransaction":
            messages.append(s.tx["message"])
        for message in messages:
            for lookup in message["address_table_lookups"]:
                if lookup["account_key"] not in s.lookup_tables:
                    s.lookup_tables.append(lookup["account_key"])
                table_wanted[lookup["account_key"]] = "lookup_table"
    _read_all(client, col, table_wanted)
    for address in table_wanted:
        read = col.reads[address]
        if read.status == "absent":
            col.block("ALT_MISSING", address, "lookup table referenced by a live payload does not exist")
            continue
        if not _require(col, read, "lookup table", squads.ALT_PROGRAM):
            continue
        try:
            col.tables[address] = squads.decode_lookup_table(read.data)
        except squads.DecodeError as exc:
            col.block(exc.code, address, f"lookup table: {exc.detail}")


def _one_pass(client: RpcClient, scope: dict, cluster: dict) -> Collection:
    col = Collection(scope=scope, cluster=cluster)
    program_id = scope["squads_program_id"]
    _bind_program(client, col)

    declared = {r["state_address"]: "multisig" for r in scope["resources"]}
    _read_all(client, col, declared)
    for address in declared:
        read = col.reads[address]
        if not _require(col, read, "declared multisig", program_id):
            continue
        decoded = _decode(col, read, "declared multisig", "Multisig")
        if decoded is None:
            continue
        state = decoded[1]
        if squads.multisig_pda(state["create_key"], program_id) != address:
            col.block("ACCOUNT_BINDING_MISMATCH", address, "address is not the Multisig PDA of its create_key")
            continue
        col.multisigs[address] = state

    for address in col.multisigs:
        _discover_limits(client, col, address)
        _walk_transactions(client, col, address)
    return col


def collect(client: RpcClient, scope: dict, cluster: dict | None = None) -> Collection:
    """Collect until two passes agree. Blockers are attached, never raised from here."""
    try:
        cluster = cluster or identify_cluster(client)
    except RpcFailure as exc:
        col = Collection(scope=scope, cluster={"genesis_hash": None, "name": "unknown",
                                              "evidence_source": "UNKNOWN", "node_version": "unknown"})
        col.block("RPC_ERROR", client.endpoint, f"could not identify the cluster: {exc}")
        col.rpc = client.summary()
        return col

    previous = _one_pass(client, scope, cluster)
    passes = 1
    while True:
        current = _one_pass(client, scope, cluster)
        passes += 1
        if current.fingerprint() == previous.fingerprint():
            break
        if passes >= MAX_PASSES:
            current.block("STATE_UNSTABLE", "collection",
                          f"account state still changing after {passes} passes; scan again when the treasuries are quiet")
            break
        previous = current
    current.passes = passes
    current.blockers = sort_unique(current.blockers)
    current.rpc = client.summary()
    return current


def discover_outside_scope(client: RpcClient, col: Collection, member_slots: int = 10) -> dict:
    """Best-effort search for subject authority outside the declared scope.

    Looks for multisigs listing the subject in one of the first `member_slots`
    member positions and spending limits listing it in one of the first three
    delegate positions. This is a courtesy, not a completeness claim: public
    RPC nodes often refuse these queries, and deeper positions are not probed.
    """
    program_id = col.scope["squads_program_id"]
    subject = col.scope["subject_wallets"][0]["address"]
    in_scope = {r["state_address"] for r in col.scope["resources"]}
    findings: dict[str, dict] = {}
    errors: list[str] = []

    def query(kind: str, offset: int) -> list[Read]:
        filters = [
            {"memcmp": {"offset": 0, "bytes": squads.b58encode(squads.DISC[kind])}},
            {"memcmp": {"offset": offset, "bytes": subject}},
        ]
        try:
            return client.program_accounts(program_id, filters)[1]
        except RpcFailure as exc:
            errors.append(f"{kind} at offset {offset}: {exc}")
            return []

    for base in MEMBER_VEC_OFFSETS:
        for position in range(member_slots):
            for read in query("Multisig", base + 33 * position):
                try:
                    state = squads.decode_account(read.data, "Multisig")[1]
                except squads.DecodeError:
                    continue
                member = next((m for m in state["members"] if m["key"] == subject), None)
                if member and read.address not in in_scope:
                    findings[read.address] = {
                        "kind": "multisig_membership",
                        "address": read.address,
                        "multisig": read.address,
                        "permissions": squads.permission_names(member["permissions"]),
                        "threshold": state["threshold"],
                        "members": len(state["members"]),
                    }
    for position in range(3):
        for read in query("SpendingLimit", LIMIT_FIRST_DELEGATE_OFFSET + 32 * position):
            try:
                limit = squads.decode_account(read.data, "SpendingLimit")[1]
            except squads.DecodeError:
                continue
            if subject in limit["members"] and limit["multisig"] not in in_scope:
                findings[read.address] = {
                    "kind": "spending_limit_delegate",
                    "address": read.address,
                    "multisig": limit["multisig"],
                    "amount": limit["amount"],
                    "period": limit["period"],
                    "mint": limit["mint"],
                }
    return {
        "method": "getProgramAccounts memcmp probes",
        "member_positions_probed": member_slots,
        "delegate_positions_probed": 3,
        "complete": False,
        "query_errors": errors,
        "findings": [findings[a] for a in sorted(findings)],
    }
