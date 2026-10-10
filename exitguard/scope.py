"""Scope manifest: load, validate, normalise.

The manifest is the operator's statement of which treasuries belong to the
organisation. ExitGuard checks its shape and records it; it cannot check that
the list is complete, and says so in every document that depends on it.
"""

from __future__ import annotations

import re
from datetime import datetime

from solders.pubkey import Pubkey
from solders.signature import Signature

from . import canon, squads
from .blockers import Blocker, ExitGuardError

SCHEMA = "exitguard.review-scope.v1"
RESOURCE_SCOPES = ("manifest_owned", "shared_or_external")
PROVENANCES = ("operator_attested", "wallet_signed", "imported", "unverified")
ATTESTATION_PREFIX = b"exitguard.scope-attestation.v1:"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def attestation_message(scope: dict) -> bytes:
    """Bytes a reviewer signs: prefix plus the digest of the scope without any signature."""
    reviewer = {k: v for k, v in scope.get("reviewer", {}).items() if k != "signature"}
    unsigned = {**{k: v for k, v in scope.items() if k != "scope_sha256"}, "reviewer": reviewer}
    return ATTESTATION_PREFIX + canon.digest(unsigned).encode()


def _address(value: object, where: str, problems: list[str]) -> str | None:
    try:
        squads.decode_address(value)  # type: ignore[arg-type]
        return value  # type: ignore[return-value]
    except ValueError as exc:
        problems.append(f"{where}: {exc}")
        return None


def validate(raw: object) -> dict:
    """Return the normalised scope or raise ExitGuardError(SCOPE_INVALID)."""
    problems: list[str] = []
    if not isinstance(raw, dict):
        raise ExitGuardError(Blocker("SCOPE_INVALID", "scope", "manifest is not a JSON object"))

    allowed = {
        "schema_version", "organization_id", "review_id", "squads_program_id",
        "scope_attested_complete", "resources", "subject_wallets", "reviewer",
    }
    for key in sorted(set(raw) - allowed):
        problems.append(f"unknown field {key!r}")
    for key in sorted(allowed - set(raw)):
        problems.append(f"missing field {key!r}")
    if problems:
        raise ExitGuardError([Blocker("SCOPE_INVALID", "scope", p) for p in problems])

    if raw["schema_version"] != SCHEMA:
        problems.append(f"schema_version must be {SCHEMA}")
    for key in ("organization_id", "review_id"):
        if not isinstance(raw[key], str) or not _ID.match(raw[key]):
            problems.append(f"{key} must be 1-64 characters of letters, digits and . _ : -")
    if raw["squads_program_id"] != squads.PROGRAM_ID:
        problems.append(f"squads_program_id must be the pinned program {squads.PROGRAM_ID}")
    if not isinstance(raw["scope_attested_complete"], bool):
        problems.append("scope_attested_complete must be true or false")

    resources: dict[str, dict] = {}
    if not isinstance(raw["resources"], list) or not raw["resources"]:
        problems.append("resources must be a non-empty list")
    else:
        for n, item in enumerate(raw["resources"]):
            where = f"resources[{n}]"
            if not isinstance(item, dict) or set(item) - {"state_address", "scope", "label"}:
                problems.append(f"{where}: expected state_address, scope and optional label")
                continue
            address = _address(item.get("state_address"), f"{where}.state_address", problems)
            if item.get("scope") not in RESOURCE_SCOPES:
                problems.append(f"{where}.scope must be one of {', '.join(RESOURCE_SCOPES)}")
                continue
            if "label" in item and not isinstance(item["label"], str):
                problems.append(f"{where}.label must be a string")
                continue
            if address is None:
                continue
            entry = {"state_address": address, "scope": item["scope"]}
            if item.get("label"):
                entry["label"] = item["label"]
            previous = resources.get(address)
            if previous is not None and previous["scope"] != entry["scope"]:
                problems.append(f"{where}: {address} is declared twice with different scopes")
            resources.setdefault(address, entry)

    subjects = []
    if not isinstance(raw["subject_wallets"], list) or len(raw["subject_wallets"]) != 1:
        problems.append("subject_wallets must contain exactly one wallet")
    else:
        item = raw["subject_wallets"][0]
        if not isinstance(item, dict) or set(item) - {"address", "provenance", "label", "signature"}:
            problems.append("subject_wallets[0]: expected address, provenance and optional label")
        else:
            address = _address(item.get("address"), "subject_wallets[0].address", problems)
            if item.get("provenance") not in PROVENANCES:
                problems.append(f"subject_wallets[0].provenance must be one of {', '.join(PROVENANCES)}")
            elif address is not None:
                subject = {"address": address, "provenance": item["provenance"]}
                if item.get("label"):
                    subject["label"] = str(item["label"])
                if item.get("signature"):
                    subject["signature"] = item["signature"]
                subjects.append(subject)

    reviewer: dict = {}
    r = raw["reviewer"]
    if not isinstance(r, dict) or set(r) - {"wallet", "attested_at", "signature"}:
        problems.append("reviewer: expected wallet, attested_at and optional signature")
    else:
        wallet = _address(r.get("wallet"), "reviewer.wallet", problems)
        stamp = r.get("attested_at")
        if not isinstance(stamp, str) or not _UTC.match(stamp):
            problems.append("reviewer.attested_at must look like 2026-10-10T09:00:00Z (UTC)")
        else:
            try:
                datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                problems.append("reviewer.attested_at is not a real date")
        if wallet is not None:
            reviewer = {"wallet": wallet, "attested_at": stamp}
            if r.get("signature"):
                reviewer["signature"] = r["signature"]

    if subjects and subjects[0]["address"] in resources:
        problems.append("the subject wallet is also listed as a resource")
    if problems:
        raise ExitGuardError([Blocker("SCOPE_INVALID", "scope", p) for p in problems])

    scope = {
        "schema_version": SCHEMA,
        "organization_id": raw["organization_id"],
        "review_id": raw["review_id"],
        "squads_program_id": raw["squads_program_id"],
        "scope_attested_complete": raw["scope_attested_complete"],
        "resources": [resources[a] for a in sorted(resources)],
        "subject_wallets": subjects,
        "reviewer": reviewer,
    }
    return scope


def _signed_by(wallet: str, signature: object, message: bytes) -> bool:
    try:
        return Signature.from_string(str(signature)).verify(Pubkey.from_string(wallet), message)
    except Exception:
        return False


def attestation(scope: dict) -> dict:
    """What can honestly be said about who stands behind this scope."""
    message = attestation_message(scope)
    reviewer = scope["reviewer"]
    subject = scope["subject_wallets"][0]
    reviewer_signed = "signature" in reviewer and _signed_by(reviewer["wallet"], reviewer["signature"], message)
    subject_signed = "signature" in subject and _signed_by(subject["address"], subject["signature"], message)

    provenance = subject["provenance"]
    if provenance == "wallet_signed" and not subject_signed:
        provenance = "unverified"
    if "signature" in reviewer and not reviewer_signed:
        status = "signature_invalid"
    else:
        status = "signature_verified" if reviewer_signed else "unsigned_assertion"
    return {
        "reviewer_wallet": reviewer["wallet"],
        "reviewer_attestation": status,
        "authenticated": reviewer_signed,
        "subject_provenance_declared": subject["provenance"],
        "subject_provenance_effective": provenance,
        "scope_attested_complete": scope["scope_attested_complete"],
        "note": "Scope completeness is the operator's assertion. The chain does not establish "
                "organization_id, review_id or which treasuries belong to the organization.",
    }


def load(path: str) -> dict:
    try:
        raw = canon.load(path)
    except (OSError, ValueError) as exc:
        raise ExitGuardError(Blocker("SCOPE_INVALID", str(path), f"cannot read manifest: {exc}")) from None
    return validate(raw)
