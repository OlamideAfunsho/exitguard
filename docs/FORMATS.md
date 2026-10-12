# Formats

Every document ExitGuard writes is JSON. This page says how they are hashed, how they refer to each other,
and what the blocker codes mean.

## Canonical JSON and digests

A document's digest is SHA-256 over its canonical form with its own digest field removed.

- UTF-8, no byte order mark
- object keys sorted by Unicode code point
- no whitespace between tokens (`,` and `:` separators)
- non-ASCII characters written as themselves, not as escape sequences
- strings, booleans, null, arrays, objects and integers with magnitude up to 2^53 - 1
- no floating point numbers anywhere; a file containing one is rejected on load
- u64 values (amounts, transaction indices, timestamps) are decimal strings

Files on disk are pretty-printed for reading. The digest is always computed over the canonical form, so
reformatting a file does not change its digest and changing a value does. The implementation is
`exitguard/canon.py`, about eighty lines.

## Account hash

Accounts are compared by

```
SHA-256( "exitguard.account.v1" || owner (32 bytes) || executable (1 byte) || data )
```

Lamports are left out on purpose: rent top-ups and vault balances change without any change in authority.
An address that the node reports as non-existent is recorded as `ABSENT`, one the node could not answer for
as `ERROR`. A state fingerprint is the map from every required address to one of those three, and
`state_digest` is the digest of that map.

## Documents

| File | `schema_version` | Digest field | Bound to |
| --- | --- | --- | --- |
| scope | `exitguard.review-scope.v1` | none (hashed as `scope_sha256` by its readers) | |
| review | `exitguard.review.v1` | `review_sha256` | scope, by embedding it |
| decisions | `exitguard.decisions.v1` | none; operator working file | review, optionally |
| intent | `exitguard.intent.v1` | `intent_sha256` | review digest; each row to its account or payload hash |
| packet | `exitguard.packet.v1` | `packet_sha256` | scope, review and intent digests; fresh account fingerprint |
| messages | `exitguard.messages.v1` | none; expires with its blockhash | packet digest |
| record | `exitguard.record.v1` | `record_sha256` | scope, review, intent and packet digests; action digests |
| diagnostics | `exitguard.diagnostics.v1` | none | written instead of an output when a command is blocked |

The scope schema is `schemas/review-scope.schema.json`. A complete set from one run is in `examples/demo-run/`.

### Row identifiers

- `member:<multisig>:<wallet>`: the subject is a member of that multisig
- `limit:<spending limit PDA>`: the subject is a delegate of that limit
- `config_authority:<multisig>`: the subject is the multisig's config authority (always blocked)
- `proposal:<proposal PDA>`: an unfinished action at that transaction index, whether or not the proposal
  account exists yet

### Decisions

`KEEP`, `REVOKE`, `BLOCKED` or `UNKNOWN`. A row with no entry is `UNKNOWN`. `KEEP` needs a reason. Every
decision other than `UNKNOWN` needs `expires_at_slot` after the review's last read slot, either on the row or
as the file-level default. A record's `expires_at_slot` is the earliest of them.

`KEEP` on a subject authority row is allowed and recorded, and it prevents a `COMPLETE` result. `REVOKE` on a
blocked row is refused; mark it `BLOCKED`, fix it by hand, scan again.

### What a residual decision is bound to

`binding_sha256` is the digest of the transaction account hash, the hashes of the batch children still to
run, and the hashes of the lookup tables its payload uses. If any of those change after a `KEEP`, the decision
no longer applies and `certify` reports `RESIDUAL_UNDECIDED`.

### Packet

`transactions[]` has one entry per multisig: the ordered actions, the signer roles, and `instructions[]` with
`program_id`, `accounts` (pubkey, `is_signer`, `is_writable`), base64 `data` and a digest each.
`action_digest` covers the ordered instruction digests and the actions. The instruction bytes themselves do
not expire.

The decisions behind them do. `decision_expiries[]` lists every decided row with its `expires_at_slot`, and
`expires_at_slot` at the top level is the earliest. Both are under `packet_sha256`. A decision is good while
the slot of the fresh read is strictly below its expiry; `plan` and `verify-plan` refuse with `EXPIRY_INVALID`
from the expiry slot onward, which is the same boundary `certify` applies. A packet without
`decision_expiries` is refused, and `certify` rejects a packet whose expiries differ from the intent's.

Unsigned messages are kept in a separate file because they do. `plan` writes them on a placeholder blockhash
(`blockhash_source: "placeholder"`) so their shape can be inspected; `verify-plan --messages` rebuilds them on
a live blockhash and runs the decode-back check on the rebuilt bytes.

### Record

`evidence_source` is `LOCAL_SIMULATION`, `LIVE_RPC` or `UNRECOGNISED_CLUSTER`, decided from the node's own
identification and the genesis hash, never from a flag. `snapshots.pre` and `snapshots.post` carry raw account
bytes for the multisigs, the limits and the remediation transaction and proposal. `coverage.closed` lists the
removed limits with the slot at which they were read as absent. `boundary` is the list of things the record
does not claim, written into the record itself.

## Exit codes

`0` clean. `2` blocked, invalidated or not complete. Anything else is a usage error or a bug.

## Blocker codes

| Code | Meaning |
| --- | --- |
| `SCOPE_INVALID` | The scope manifest failed validation |
| `INTENT_INVALID` | The intent does not bind to this review |
| `INPUT_TAMPERED` | A document does not match its own digest |
| `RPC_ERROR` | An RPC call failed |
| `RPC_INCOMPLETE_RESULT` | An RPC call returned fewer results than were asked for |
| `CLUSTER_MISMATCH` | The endpoint is a different cluster from the one reviewed |
| `STATE_UNSTABLE` | State kept changing between collection passes |
| `ACCOUNT_MISSING` | A required account does not exist |
| `ACCOUNT_FOREIGN_OWNER` | An account is not owned by the expected program |
| `ACCOUNT_MALFORMED` | Account bytes do not decode under the pinned layout |
| `ACCOUNT_UNSUPPORTED` | Account type or version is not supported |
| `ACCOUNT_BINDING_MISMATCH` | An account does not point back at its parent or index |
| `ALT_MISSING` | An address lookup table referenced by a payload is unavailable |
| `ALT_INDEX_OUT_OF_RANGE` | A lookup index is past the end of its table |
| `MESSAGE_INDEX_OUT_OF_RANGE` | An instruction references a key index that does not exist |
| `BATCH_CHILD_MISSING` | A remaining batch child transaction is missing |
| `PROGRAM_UNVERIFIED` | The Squads program or its ProgramData could not be bound |
| `SHARED_RESOURCE` | The resource is declared shared_or_external |
| `CONTROLLED_MULTISIG` | The multisig has a non-default config authority |
| `SHARED_SPENDING_LIMIT` | The spending limit has delegates other than the subject |
| `LAST_MEMBER` | Removing the subject would leave no members |
| `THRESHOLD_UNREACHABLE` | Removal would need a threshold change |
| `ROLE_WOULD_BE_EMPTY` | Removal would leave no proposer, voter or executor |
| `NO_ELIGIBLE_SIGNER` | No remaining member can fill a required signing role |
| `SUBJECT_IS_CONFIG_AUTHORITY` | The subject wallet is the config authority |
| `DECISION_UNKNOWN` | A row has no operator decision |
| `DECISION_BLOCKED` | A row is blocked and needs manual resolution |
| `DECISION_NOT_ALLOWED` | The decision is not available for this row |
| `KEEP_INVALID` | A KEEP decision lacks a reason or a usable expiry |
| `RETAINED_SUBJECT_AUTHORITY` | In-scope subject authority was kept |
| `RESIDUAL_UNDECIDED` | A residual action has no decision bound to its payload |
| `RESIDUAL_REVOKE_PENDING` | A residual marked REVOKE is still live |
| `REVIEW_DRIFT` | State changed since the review |
| `PROPOSAL_APPEARED` | A proposal that was absent at review now exists |
| `NEW_DEPENDENCY` | An account appeared that the review never saw |
| `PROGRAM_DRIFT` | The program binding changed |
| `INDEX_COLLISION` | The planned transaction index is taken by something else |
| `PACKET_DECODE_MISMATCH` | Emitted instructions do not decode to the reviewed actions |
| `PACKET_TAMPERED` | The packet does not match its digest |
| `SUBJECT_STILL_MEMBER` | The subject is still a member |
| `SUBJECT_STILL_DELEGATE` | The subject is still a spending limit delegate |
| `LIMIT_NOT_CLOSED` | A spending limit planned for removal still exists |
| `PROPOSAL_NOT_EXECUTED` | The remediation proposal is not Executed |
| `RETAINED_STATE_CHANGED` | Retained authority or unrelated configuration changed |
| `NOT_FINALIZED` | Live reads were not taken at finalized commitment |
| `EXPIRY_INVALID` | An expiry is missing, malformed or already passed |
