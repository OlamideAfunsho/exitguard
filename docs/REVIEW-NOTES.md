# Review notes

These are the author's own notes from going back over the code with two questions: where could it tell an
operator "done" when it is not, and where could it be made to emit something other than what was reviewed.
They are not an external audit and should not be read as one.

## Ways to get a false "complete"

**The inventory silently misses something.** Every address the walk needs is put in a coverage map with a
status. A failed call marks every address in that call as `error`, and a reply with the wrong number of
entries is treated as a failed call. An account that exists but does not decode, has the wrong owner, or does
not point back at its multisig and index is a blocker on that address, not a skipped row. Tests:
`rpc-short`, `malformed`, `foreign-owner`, `key-index`, `alt-missing`, `alt-index`, `batch-child-missing`.

**A proposal appears between review and execution.** Proposal PDAs for every index are read even when absent,
and the absent ones are part of the fingerprint. Creating one changes `ABSENT` to a hash while the multisig
account stays byte-identical. Test: `late-proposal`.

**State is swapped at the same address.** Comparison is by account hash, not by address or by the fields
ExitGuard happens to display. Test: `same-pda`.

**The limit is forgotten.** `certify` rebuilds the full inventory from post-state and fails on any row where
the subject still holds authority, regardless of what the packet said it would do. Test: `still-delegate`.

**The program changes underneath.** Program and ProgramData addresses, owners, deploy slot and hashes are
bound at review and compared at plan, verify and certify. Test: `program-upgrade`.

**Something unrelated changes during the offboarding.** Threshold, time lock, config authority, rent
collector and the other members are compared before and after with the subject left out. Retained limits are
compared on policy (amount, period, delegates, destinations, mint, vault), not on usage counters, so a service
key spending from its limit is not drift but an edit to the limit is. Test: `post-drift`.

**A local run is passed off as live.** `evidence_source` comes from the node (`getVersion`, genesis hash).
There is no flag that sets it. A node that does not identify as the simulator is held to finalized
commitment. Test: `not-finalized`.

## Ways to get a packet that is not what was reviewed

**The worker returns something else.** The Node worker is the only place SDK code runs. Its output is decoded
in Python with different code: instruction data by a strict reader that rejects trailing bytes, account metas
against PDAs derived in Python. The Python expectations matched the SDK's output without adjustment, which is
weak evidence that both follow the program's IDL; the stronger evidence is that the emitted instructions
execute on the captured program and produce the expected post-state.

**The packet file is edited after planning.** A plain edit breaks `packet_sha256`. An edit that recomputes
every digest still fails, because the decode-back compares the bytes with the actions and the actions with
the subject. Test: `forged-packet`.

**Messages are substituted.** `check_messages` parses each compiled message from wire format and requires the
same program, account order, data, fee payer and blockhash, the same signer and writable set, no trailing
bytes, and that the messages cover each instruction exactly once. Tests in `test_flow.py`.

**Inputs are mixed between reviews.** Intent rows carry the review digest; the packet carries scope, review
and intent digests; `certify` refuses a packet that was not planned from the review and intent it is given.

## Things that are true and worth knowing

- Reads are trusted to the RPC endpoint. A consistent liar defeats any single-endpoint tool. The mitigation is
  operational: a second provider for `verify-plan` and `certify`.
- The scope is an assertion. `--discover` helps but probes a bounded number of member and delegate positions
  and depends on the node answering `getProgramAccounts`.
- Removing a member does not withdraw their past approvals. An Approved vault transaction or batch below the
  stale index still executes. ExitGuard surfaces these and makes the operator decide; it does not cancel them.
- A vault transaction that calls the Squads program itself (for example to act as config authority of another
  multisig) is flagged in the review, but what it would do is not analysed.
- `KEEP` decisions are the operator's word. The record stores the reason text and the payload hash; it does
  not judge the reason.
- Time locks are reported in the packet and not waited for. Execution before the lock expires fails on chain
  and `verify-plan` keeps reporting `READY_TO_EXECUTE` until it lands.
- The reviewer's attestation is only called authenticated when an ed25519 signature over the scope digest
  verifies against the reviewer wallet. Otherwise it is recorded as an unsigned assertion.

## Not reviewed

Anything on a live cluster beyond a read-only scan. Token-2022 mints. Multisigs with thousands of members or
hundreds of thousands of transaction indices (the walk is linear in the index and has no cap). Behaviour of
RPC providers that silently truncate `getProgramAccounts`.
