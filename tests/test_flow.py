"""The integrated path, through the same functions the CLI calls."""

import base64
import copy
from pathlib import Path

from exitguard import canon, planner, record as record_mod, squads, verifier
from exitguard.sim.world import SOL, World


def test_member_removal_alone_leaves_the_limit_usable():
    world = World()
    world.config_transaction(world.operations, [{"kind": "RemoveMember", "oldMember": world.subject}])
    state = squads.decode_account(bytes(world.chain.account(world.operations).data), "Multisig")[1]
    assert world.subject not in [m["key"] for m in state["members"]]

    vault = squads.vault_pda(world.operations, 0)
    before = world.chain.balance(vault)
    ok, _ = world.spend("dana-ops", "dana", SOL // 2, "dana-personal")
    assert ok
    assert world.chain.balance(vault) == before - SOL // 2


def test_full_offboarding(session):
    s, world = session, session.world
    assert s.scan(discover=True) == 0
    review = canon.load(s.path("review"))
    assert review["result"] == "REVIEW_READY"
    assert sorted(a["kind"] for a in review["authorities"]) == ["limit", "member", "member"]
    assert [r["state"] for r in review["residuals"]] == ["approved", "pending", "approved", "latent"]
    assert [f["multisig"] for f in review["outside_scope"]["findings"]] == [world.side]
    assert review["coverage"]["error"] == 0
    # every index 1..T has both PDAs in coverage, including the proposal that does not exist
    roles = [row["role"] for row in review["coverage"]["accounts"].values()]
    for i in range(1, 5):
        assert f"transaction:{world.grants}:{i}" in roles and f"proposal:{world.grants}:{i}" in roles
    absent = [a for a, row in review["coverage"]["accounts"].items() if row["status"] == "absent"]
    assert absent == [squads.proposal_pda(world.grants, 4)]

    assert s.decide() == 0
    assert s.plan() == 0
    packet = canon.load(s.path("packet"))
    ops = next(t for t in packet["transactions"] if t["multisig"] == world.operations)
    assert [a["kind"] for a in ops["actions"]] == ["RemoveSpendingLimit", "RemoveMember"]
    assert ops["transaction_index"] == "3"
    assert verifier.check_packet(packet) == []
    assert verifier.check_messages(packet, canon.load(s.path("packet.messages"))) == []

    s.execute()
    assert s.certify() == 0
    record = canon.load(s.path("record"))
    assert record["result"] == "COMPLETE" and record["evidence_source"] == "LOCAL_SIMULATION"
    assert record["executor_bypass"] is True and record["blockers"] == []
    assert {r["kind"] for r in record["removed"]} == {"member", "limit"}
    states = {r["transaction_index"]: r["state_after"] for r in record["residual_decisions"]}
    assert states == {"1": "approved", "2": "inert_stale", "3": "approved", "4": "inert_stale"}

    vault = squads.vault_pda(world.operations, 0)
    before = world.chain.balance(vault)
    ok, _ = world.spend("dana-ops", "dana", SOL // 2, "dana-personal")
    assert not ok and world.chain.balance(vault) == before
    ok, _ = world.spend("payroll-bot", "payroll-bot", SOL // 4, "payroll-sink")
    assert ok and world.chain.balance(vault) == before - SOL // 4

    digest = record["record_sha256"]
    assert s.verify_certificate(digest) == 0                  # still current after the service limit was used
    assert s.verify_certificate(None, with_rpc=False) == 2    # no trusted digest: self-consistent is not enough
    assert s.verify_certificate("0" * 64) == 2

    world.config_transaction(world.operations, [{"kind": "AddMember", "key": world.subject, "permissions": 7}])
    assert s.verify_certificate(digest) == 2                  # intact, but no longer true
    result = record_mod.verify_certificate(record, digest)
    assert result["historical_integrity"] == "PASS" and result["current_validity"]["status"] == "NOT_CHECKED"


def test_nothing_to_remove_plans_no_transaction(session):
    s, world = session, session.world
    for ms, limits in ((world.operations, [world.limits["dana-ops"]]), (world.grants, [])):
        actions = [{"kind": "RemoveSpendingLimit", "spendingLimit": l} for l in limits]
        world.config_transaction(ms, actions + [{"kind": "RemoveMember", "oldMember": world.subject}], spending_limits=limits)
    s.through_plan()
    packet = canon.load(s.path("packet"))
    assert packet["transactions"] == []
    assert s.certify() == 0


def test_unknown_rows_cannot_be_planned(session):
    s = session
    assert s.scan() == 0
    assert s.decide(overrides={"limit:": ("UNKNOWN", "")}) == 2
    assert s.plan() == 2
    assert "DECISION_UNKNOWN" in s.codes("packet")
    assert not Path(s.path("packet")).exists()


def test_keeping_subject_authority_blocks_completion(session):
    s = session
    assert s.scan() == 0
    assert s.decide(overrides={"limit:": ("KEEP", "contractor hand-over until month end")}) == 0
    assert s.plan() == 0
    s.execute()
    assert s.certify() == 2
    assert {"RETAINED_SUBJECT_AUTHORITY", "SUBJECT_STILL_DELEGATE"} <= s.codes("record")
    assert not Path(s.path("record")).exists()


def test_edited_documents_are_rejected(session):
    s = session
    s.through_plan()
    packet = canon.load(s.path("packet"))

    edited = copy.deepcopy(packet)
    edited["transactions"][0]["actions"][-1]["old_member"] = edited["transactions"][0]["signers"]["proposer"]
    assert verifier.check_packet(edited) == ["packet does not match its packet_sha256"]

    review = canon.load(s.path("review"))
    review["authorities"].pop()
    canon.write(s.path("review"), review)
    assert s.plan() == 2 and "INPUT_TAMPERED" in s.codes("packet")


def test_message_checks_catch_substitution(session):
    s = session
    s.through_plan()
    packet = canon.load(s.path("packet"))
    messages = planner.build_messages(packet)
    assert verifier.check_messages(packet, messages) == []

    swapped = copy.deepcopy(messages)
    swapped["messages"][0]["message"], swapped["messages"][-1]["message"] = (
        swapped["messages"][-1]["message"], swapped["messages"][0]["message"])
    assert verifier.check_messages(packet, swapped)

    padded = copy.deepcopy(messages)
    raw = base64.b64decode(padded["messages"][0]["message"]) + b"\x00"
    padded["messages"][0]["message"] = base64.b64encode(raw).decode()
    assert any("trailing" in p for p in verifier.check_messages(packet, padded))

    dropped = copy.deepcopy(messages)
    dropped["messages"].pop()
    assert any("cover" in p for p in verifier.check_messages(packet, dropped))


def test_record_tampering(session):
    s = session
    s.through_plan()
    s.execute()
    assert s.certify() == 0
    record = canon.load(s.path("record"))
    digest = record["record_sha256"]

    edited = copy.deepcopy(record)
    edited["expires_at_slot"] += 1_000_000
    assert record_mod.verify_certificate(edited, digest)["historical_integrity"] == "FAIL"

    # Re-sealing gets past the self-hash but not past a digest held elsewhere.
    resealed = canon.seal(edited, "record_sha256")
    assert record_mod.verify_certificate(resealed, digest)["historical_integrity"] == "FAIL"
    assert record_mod.verify_certificate(resealed, None)["historical_integrity"] == "SELF_CONSISTENT_ONLY"

    # A resealed record whose snapshot was swapped for the pre-state fails the content check.
    forged = copy.deepcopy(record)
    ms = s.world.operations
    forged["snapshots"]["post"][ms] = forged["snapshots"]["pre"][ms]
    forged["coverage"]["post_accounts"][ms]["sha256"] = forged["snapshots"]["pre"][ms]["sha256"]
    forged = canon.seal(forged, "record_sha256")
    result = record_mod.verify_certificate(forged, forged["record_sha256"])
    assert result["historical_integrity"] == "PASS" and result["content"] == "FAIL"
