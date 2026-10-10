"""The Python decoders and PDA derivations must agree with the official SDK.

Every Squads-owned account in the simulated world was written by the real
program. Each one is decoded twice, once here and once by @sqds/multisig, and
the results are compared field by field.
"""

import base64
import re

from solders.pubkey import Pubkey

from exitguard import sdkworker, squads

SNAKE = re.compile(r"(?<!^)(?=[A-Z])")


def snake(name: str) -> str:
    return SNAKE.sub("_", name).lower()


def normalise(value, key: str = ""):
    """Bring the SDK's JSON view into the shape the Python decoders produce."""
    if isinstance(value, dict):
        if set(value) == {"mask"}:
            return value["mask"]
        if "__kind" in value:
            kind = value["__kind"]
            rest = {snake(k): normalise(v, snake(k)) for k, v in value.items() if k != "__kind"}
            if key == "status":
                return {"status": kind, "status_timestamp": rest.get("timestamp")}
            if kind == "AddMember":
                return {"kind": kind, **rest["new_member"]}
            return {"kind": kind, **rest}
        return {snake(k): normalise(v, snake(k)) for k, v in value.items()}
    if isinstance(value, list):
        if key in ("data",):
            return bytes(value).hex()
        return [normalise(v) for v in value]
    if key == "period":
        return squads.PERIODS[value]
    if key in ("threshold", "time_lock", "bump", "vault_index", "vault_bump", "size", "executed_transaction_index",
               "permissions", "new_threshold", "new_time_lock") and isinstance(value, str):
        return int(value)
    if key in ("transaction_index", "stale_transaction_index", "index", "amount", "remaining_amount", "last_reset",
               "timestamp", "multisig_creation_fee") and value is not None:
        return str(value)
    return value


def flatten(decoded: dict) -> dict:
    out = {}
    for k, v in decoded.items():
        if k == "status" and isinstance(v, dict):
            out.update(v)
        else:
            out[k] = v
    out.pop("reserved", None)
    out.pop("_reserved", None)
    return out


def squads_accounts(world):
    program = Pubkey.from_string(squads.PROGRAM_ID)
    return [(str(a), bytes(acct.data)) for a, acct in world.chain.svm.get_program_accounts(program) if acct.lamports]


def test_every_account_decodes_like_the_sdk(world):
    accounts = squads_accounts(world)
    requests, mine = [], []
    for address, data in accounts:
        name, decoded = squads.decode_account(data)
        mine.append((address, name, decoded))
        requests.append({"op": "decodeAccount", "args": {"type": name, "data": base64.b64encode(data).decode()}})
    theirs = sdkworker.call(requests)

    seen = set()
    for (address, name, decoded), sdk in zip(mine, theirs):
        expected = flatten(normalise(sdk))
        if name == "VaultTransaction" or name == "VaultBatchTransaction":
            for ix in expected["message"]["instructions"]:
                ix["account_indexes"] = list(bytes.fromhex(ix["account_indexes"])) if isinstance(ix["account_indexes"], str) else ix["account_indexes"]
            for lookup in expected["message"]["address_table_lookups"]:
                for field in ("writable_indexes", "readonly_indexes"):
                    lookup[field] = list(lookup[field])
            expected["ephemeral_signer_bumps"] = list(expected["ephemeral_signer_bumps"])
        assert decoded == expected, f"{name} {address}"
        seen.add(name)
    assert seen >= {"Multisig", "SpendingLimit", "Proposal", "ConfigTransaction", "VaultTransaction", "Batch",
                    "VaultBatchTransaction", "ProgramConfig"}


def test_pdas_match_the_sdk(world):
    ms = world.grants
    key = str(Pubkey.from_bytes(bytes(range(32))))
    cases = [
        ({"kind": "multisig", "createKey": key}, squads.multisig_pda(key)),
        ({"kind": "vault", "multisig": ms, "index": 0}, squads.vault_pda(ms, 0)),
        ({"kind": "vault", "multisig": ms, "index": 255}, squads.vault_pda(ms, 255)),
        ({"kind": "transaction", "multisig": ms, "index": "1"}, squads.transaction_pda(ms, 1)),
        ({"kind": "transaction", "multisig": ms, "index": "18446744073709551615"}, squads.transaction_pda(ms, 2**64 - 1)),
        ({"kind": "proposal", "multisig": ms, "index": "9007199254740993"}, squads.proposal_pda(ms, 2**53 + 1)),
        ({"kind": "batchTransaction", "multisig": ms, "batchIndex": "3", "index": 2}, squads.batch_transaction_pda(ms, 3, 2)),
        ({"kind": "spendingLimit", "multisig": ms, "createKey": key}, squads.spending_limit_pda(ms, key)),
        ({"kind": "programConfig"}, squads.program_config_pda()),
    ]
    got = sdkworker.call([{"op": "derive", "args": args} for args, _ in cases])
    for (args, expected), result in zip(cases, got):
        assert result["address"] == expected, args


def test_discriminators_are_on_real_accounts(world):
    for _address, data in squads_accounts(world):
        assert data[:8] in squads.DISCRIMINATORS


def test_addresses_must_be_exactly_32_bytes():
    import pytest
    for bad in ("", "abc", "0OIl", "1" * 31, "1" * 33, squads.PROGRAM_ID + "1", squads.PROGRAM_ID[:-1]):
        with pytest.raises(ValueError):
            squads.decode_address(bad)
    assert len(squads.decode_address(squads.PROGRAM_ID)) == 32
