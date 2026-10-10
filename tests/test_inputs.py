"""Scope validation, canonical JSON, RPC hygiene and the stale-index rules."""

import copy

import pytest
from solders.keypair import Keypair

from exitguard import canon, rpc, rules, scope as scope_mod, squads
from exitguard.blockers import ExitGuardError
from exitguard.sim.world import address


def manifest() -> dict:
    return {
        "schema_version": "exitguard.review-scope.v1",
        "organization_id": "lagoon-labs",
        "review_id": "offboard-1",
        "squads_program_id": squads.PROGRAM_ID,
        "scope_attested_complete": True,
        "resources": [{"state_address": address("a"), "scope": "manifest_owned", "label": "A"},
                      {"state_address": address("b"), "scope": "shared_or_external"}],
        "subject_wallets": [{"address": address("subject"), "provenance": "operator_attested"}],
        "reviewer": {"wallet": address("reviewer"), "attested_at": "2026-10-10T09:00:00Z"},
    }


def problems(doc) -> str:
    with pytest.raises(ExitGuardError) as caught:
        scope_mod.validate(doc)
    assert all(b.code == "SCOPE_INVALID" for b in caught.value.blockers)
    return " | ".join(b.detail for b in caught.value.blockers)


def test_valid_scope_is_normalised_and_deduplicated():
    doc = manifest()
    doc["resources"].append(dict(doc["resources"][0]))
    scope = scope_mod.validate(doc)
    assert [r["state_address"] for r in scope["resources"]] == sorted([address("a"), address("b")])
    assert canon.digest(scope) == canon.digest(scope_mod.validate(manifest()))


def test_scope_needs_exactly_one_subject():
    doc = manifest()
    doc["subject_wallets"].append({"address": address("second"), "provenance": "imported"})
    assert "exactly one" in problems(doc)
    doc["subject_wallets"] = []
    assert "exactly one" in problems(doc)


@pytest.mark.parametrize("bad", ["", "not-base58-0OIl", "1" * 31, squads.PROGRAM_ID[:-2], 42, None])
def test_scope_rejects_bad_addresses(bad):
    doc = manifest()
    doc["resources"][0]["state_address"] = bad
    assert "resources[0].state_address" in problems(doc)


def test_scope_rejects_conflicts_and_wrong_program():
    doc = manifest()
    doc["resources"].append({"state_address": address("a"), "scope": "shared_or_external"})
    assert "declared twice" in problems(doc)
    doc = manifest()
    doc["squads_program_id"] = address("other-program")
    assert "pinned program" in problems(doc)
    doc = manifest()
    doc["extra"] = 1
    assert "unknown field" in problems(doc)


def test_reviewer_signature_is_verified_or_labelled():
    reviewer = Keypair()
    doc = manifest()
    doc["reviewer"]["wallet"] = str(reviewer.pubkey())
    scope = scope_mod.validate(doc)
    assert scope_mod.attestation(scope)["reviewer_attestation"] == "unsigned_assertion"

    doc["reviewer"]["signature"] = str(reviewer.sign_message(scope_mod.attestation_message(scope)))
    signed = scope_mod.validate(doc)
    assert scope_mod.attestation(signed)["authenticated"] is True

    doc["reviewer"]["signature"] = str(Keypair().sign_message(scope_mod.attestation_message(scope)))
    assert scope_mod.attestation(scope_mod.validate(doc))["reviewer_attestation"] == "signature_invalid"

    doc = manifest()
    doc["subject_wallets"][0]["provenance"] = "wallet_signed"
    assert scope_mod.attestation(scope_mod.validate(doc))["subject_provenance_effective"] == "unverified"


def test_canonical_json():
    assert canon.dumps({"b": 1, "a": [True, None, "é"]}) == '{"a":[true,null,"é"],"b":1}'.encode()
    assert canon.digest({"a": 1, "b": 2}) == canon.digest({"b": 2, "a": 1})
    for bad in ({"x": 1.5}, {"x": 2**53}, {"x": {1: 2}}, {"x": b"bytes"}):
        with pytest.raises(ValueError):
            canon.dumps(bad)
    sealed = canon.seal({"a": 1}, "sha")
    assert canon.check_seal(sealed, "sha")
    sealed["a"] = 2
    assert not canon.check_seal(sealed, "sha")


def test_rpc_urls_are_redacted():
    assert rpc.redact("https://mainnet.helius-rpc.com/?api-key=SECRET") == "https://mainnet.helius-rpc.com/<redacted>"
    assert rpc.redact("https://rpc.example.org/v2/SECRETKEY") == "https://rpc.example.org/<redacted>"
    assert rpc.redact("https://user:pw@rpc.example.org") == "https://rpc.example.org/<redacted>"
    assert rpc.redact("http://127.0.0.1:8899") == "http://127.0.0.1:8899"
    client = rpc.RpcClient("http://127.0.0.1:9/key/SECRET", retries=1, timeout=2)
    with pytest.raises(rpc.RpcFailure) as caught:
        client.call("getSlot", [])
    assert "SECRET" not in str(caught.value)


def test_absent_and_error_are_different(world):
    server = world.chain.serve()
    try:
        client = rpc.RpcClient(server.url)
        missing = address("nobody-home")
        assert client.get_multiple([missing])[missing].status == "absent"
        world.chain.faults["getMultipleAccounts"] = lambda r: {**r, "value": []}
        assert client.get_multiple([missing])[missing].status == "error"
        too_many = [address(f"k{i}") for i in range(230)]
        world.chain.faults.clear()
        reads = client.get_multiple(too_many)
        assert len(reads) == 230 and [c["items"] for c in client.calls[-3:]] == [100, 100, 30]
    finally:
        world.chain.faults.clear()
        server.close()


def test_stale_index_rules():
    ms = {"stale_transaction_index": "5"}
    def tx(i, **extra): return {"index": str(i), **extra}
    def prop(status): return {"status": status}
    batch = {"executed_transaction_index": 0}

    assert rules.slot_state(ms, None, None, None) == rules.CLOSED
    assert rules.slot_state(ms, "VaultTransaction", tx(6), None) == rules.LATENT
    assert rules.slot_state(ms, "VaultTransaction", tx(5), None) == rules.INERT
    assert rules.slot_state(ms, "VaultTransaction", tx(6), prop("Active")) == rules.PENDING
    assert rules.slot_state(ms, "VaultTransaction", tx(4), prop("Active")) == rules.INERT
    # approvals that reached threshold survive a later config change, except for config transactions
    assert rules.slot_state(ms, "VaultTransaction", tx(4), prop("Approved")) == rules.APPROVED
    assert rules.slot_state(ms, "Batch", tx(4, **batch), prop("Approved")) == rules.APPROVED
    assert rules.slot_state(ms, "Batch", tx(4, executed_transaction_index=1), prop("Approved")) == rules.EXECUTING
    assert rules.slot_state(ms, "ConfigTransaction", tx(4), prop("Approved")) == rules.INERT
    assert rules.slot_state(ms, "ConfigTransaction", tx(6), prop("Approved")) == rules.APPROVED
    for done in ("Executed", "Rejected", "Cancelled"):
        assert rules.slot_state(ms, "VaultTransaction", tx(6), prop(done)) == rules.TERMINAL_STATE


def test_removal_invariants():
    def ms(members, threshold): return {"members": [{"key": k, "permissions": p} for k, p in members], "threshold": threshold}
    assert rules.removal_problems(ms([("s", 7)], 1), "s")[0][0] == "LAST_MEMBER"
    assert rules.removal_problems(ms([("s", 7), ("a", 7)], 2), "s")[0][0] == "THRESHOLD_UNREACHABLE"
    codes = [c for c, _ in rules.removal_problems(ms([("s", 7), ("a", 2), ("b", 2)], 2), "s")]
    assert codes == ["ROLE_WOULD_BE_EMPTY", "ROLE_WOULD_BE_EMPTY"]
    assert rules.removal_problems(ms([("s", 7), ("a", 7), ("b", 2)], 2), "s") == []
