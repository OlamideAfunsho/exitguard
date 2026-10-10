# ExitGuard

Offboarding one wallet from Squads v4 treasuries, including the part that member removal leaves behind.

When someone leaves a team, the obvious step is a `RemoveMember` proposal on each multisig. That removes their
vote. It does not touch any `SpendingLimit` they are a delegate of, because a spending limit is its own account
with its own delegate list, and `spending_limit_use` checks that list and nothing else. A wallet that is no
longer a member can keep drawing from the vault until someone notices.

ExitGuard is a local CLI for the treasury operator. You tell it which multisigs belong to your organisation and
which wallet is leaving. It reads everything those multisigs depend on, shows you every form of authority the
wallet holds and every unfinished proposal, builds one unsigned config transaction per multisig that removes
the limits and the membership together, checks that packet against fresh chain state, and after your members
have approved and executed it in their normal Squads tooling, rereads the chain and writes a JSON record of
what was true before and after.

It never holds a key, never signs, never broadcasts.

## Run the demo

Needs Python 3.12+ and Node 22+.

```
python -m venv .venv
.venv\Scripts\activate            # source .venv/bin/activate on Linux and macOS
pip install -e ".[dev]"
cd sdk-worker && npm ci && cd ..
exitguard demo
```

The demo takes about half a minute. It runs the real commands, over JSON-RPC, against LiteSVM loaded with the
Squads v4 executable as deployed on mainnet (captured with `tools/capture_program.py`; hashes are in
`fixtures/program/CAPTURE.json`). Accounts are created by sending SDK-built instructions to that program, not by
writing bytes. In order, it shows:

1. A two-treasury organisation with a departing member, `dana`, who also holds a 2 SOL/week spending limit.
2. A copy of that organisation where the team only removes the member. dana's delegated spend still succeeds
   and the vault balance drops.
3. `scan`, `review`, `plan`, `verify-plan` on the original, then the members approving and executing, with the
   plan rechecked before each hand-off.
4. `certify`. The same delegated spend now fails and the vault is unchanged. A service key's limit that was
   meant to stay still works.
5. `verify-certificate` passing, then failing its "current validity" check after two members add dana back
   through ordinary governance. The record stays intact as history; it stops being true.
6. Eighteen negative controls. Each builds a fresh organisation, breaks one thing, and has to be refused with
   a named blocker and no packet or record published.

Output from one run, with every file it wrote, is in `examples/demo-run/`. Runs are reproducible: the same
commit produces the same `record_sha256`.

A recording of that run is at `docs/demo/exitguard-demo.mp4` (two and a half minutes). It is generated from
the demo's own output by `tools/make_video.py`, not screen-captured and edited.

`pytest` runs the same paths as assertions (45 tests, under a minute), including a field-by-field comparison
of the Python account decoders against `@sqds/multisig` on accounts the real program wrote.

## Commands

| Command | Reads | Writes |
| --- | --- | --- |
| `scan` | `scope.json`, RPC | `review.json`: authorities, unfinished actions, read coverage, blockers |
| `review` | `review.json`, operator decisions | `intent.json`, bound to the review digest |
| `plan` | review, intent, fresh RPC | `packet.json` (stable instructions) and `packet.messages.json` |
| `verify-plan` | packet, fresh RPC | `VALID` or `PLAN_INVALIDATED` with reasons; optionally fresh unsigned messages |
| `certify` | packet, review, intent, post-execution RPC | `record.json`, or `NOT_COMPLETE` |
| `verify-certificate` | record, trusted digest, optional RPC | integrity, recorded postconditions, current validity |
| `demo` | bundled fixtures | one integrated local run and the negative controls |

Exit code 0 means clean, 2 means blocked. A blocked command writes `<output>.diagnostics.json` and does not
write the output itself.

To go through it by hand against the simulator, start it in one terminal and leave it running:

```
exitguard localnet --port 8899 --scope-out scope.json
```

Then, in another:

```
exitguard scan --scope scope.json --discover --out review.json --rpc http://127.0.0.1:8899
exitguard review --review review.json --init --out decisions.json
```

Edit `decisions.json`: set each row to `KEEP`, `REVOKE` or `BLOCKED`, give `KEEP` rows a reason, and set
`expires_at_slot` to a slot after the scan (the scan prints its slots; add 216000 for roughly a day).

```
exitguard review --review review.json --decisions decisions.json --out intent.json
exitguard plan --review review.json --intent intent.json --out packet.json --rpc http://127.0.0.1:8899

exitguard verify-plan --packet packet.json --messages messages.json --rpc http://127.0.0.1:8899
exitguard local-sign --packet packet.json --messages messages.json --phase create --rpc http://127.0.0.1:8899
exitguard verify-plan --packet packet.json --messages messages.json --rpc http://127.0.0.1:8899
exitguard local-sign --packet packet.json --messages messages.json --phase approve --rpc http://127.0.0.1:8899
exitguard verify-plan --packet packet.json --messages messages.json --rpc http://127.0.0.1:8899
exitguard local-sign --packet packet.json --messages messages.json --phase execute --rpc http://127.0.0.1:8899

exitguard certify --packet packet.json --review review.json --intent intent.json --out record.json --rpc http://127.0.0.1:8899
exitguard verify-certificate --record record.json --expect-sha256 <digest printed by certify> --rpc http://127.0.0.1:8899
```

`local-sign` exists only so the simulator has someone to play the members. It checks that the node identifies
as the simulator and refuses otherwise.

## On a real cluster

The normal path is the same commands with a real RPC URL. Put the URL in `EXITGUARD_RPC_URL` so an API key
does not end up in shell history; ExitGuard only ever prints or stores the scheme and host.

`packet.json` holds the instructions as program id, account metas and data, built by the official SDK
(`configTransactionCreate`, `proposalCreate`, `proposalApprove`, `configTransactionExecute`).
`verify-plan --messages` rebuilds unsigned legacy messages on a fresh blockhash and decodes them back before
writing them. Members import or reconstruct those in whatever they already use to approve Squads proposals.
The signer must keep the instruction bytes and account metas exactly as they are in the packet.

What has been run against mainnet: `scan` only, read-only, at finalized commitment, against a multisig with
170 transaction indices. It walked all 340 Transaction and Proposal PDAs plus spending limits with no read
errors, and reported an old Approved vault transaction below the stale index as still executable, which is
what the program's rules say. No packet has been executed on a live cluster. Everything in `examples/` is
`LOCAL_SIMULATION` and says so.

## What it checks

**Inventory.** For each declared multisig: the full member array and permission bits, config authority,
threshold, time lock, both indices; every SpendingLimit (found by program-account query, then checked against
its PDA derivation); the Transaction and Proposal PDA at every index from 1 to `transaction_index`, not just
recent ones; remaining children of any batch that can still run; every lookup table a live payload uses, with
each index resolved. Every address asked for gets a status of present, verified absent or error. A node
answering "null" and a node failing to answer are never treated as the same thing.

**Stability.** Calls are not an atomic snapshot, so the whole walk is done twice with `minContextSlot` rising,
and repeated until two passes agree. If they will not agree, the result is `STATE_UNSTABLE`.

**What can be planned.** Only multisigs declared `manifest_owned` whose config authority is the default
(zero) key, and only spending limits whose delegate list is the subject alone. A limit shared with someone
else, a multisig under a separate config authority, or a removal that would break the program's invariant
(last member, threshold out of reach, no proposer or executor left) is shown as `blocked` and left for a
human. One config transaction per multisig: all `RemoveSpendingLimit` actions first, then `RemoveMember`. If
there is nothing to remove, no transaction is invented.

**Unfinished actions.** A transaction with no proposal yet, a proposal still collecting votes, and an
Approved proposal that has not executed all get a row and need a decision. An Approved vault payment or batch
is the organisation's decision, not the departing wallet's private authority, and it stays executable after
the member is removed; ExitGuard says so rather than pretending removal cancels it. What a config change does
invalidate (pending and unproposed items at or below the new stale index, and stale config transactions) is
tracked per transaction type in `exitguard/rules.py`.

**The packet.** Instruction data is decoded from its bytes by a separate Python decoder that rejects trailing
bytes; account metas are rebuilt from PDAs derived in Python and compared key by key, flag by flag; compiled
messages are parsed from wire format and matched back to the packet. A packet whose bytes were altered and
whose digests were all recomputed still fails (`forged-packet` control).

**Freshness.** `plan` and `verify-plan` reread everything. Any account that differs from the review
invalidates the plan, with the reason named: `REVIEW_DRIFT`, `PROPOSAL_APPEARED` (a proposal PDA that was
verified absent now exists, which can happen without the multisig account changing at all), `PROGRAM_DRIFT`,
`INDEX_COLLISION`, `NEW_DEPENDENCY`. The plan's own creation and approvals are recognised as expected
transitions, so `verify-plan` can be run before each hand-off.

**The record.** Written only if every postcondition holds: subject absent from every in-scope member and
delegate array, planned limits closed, remediation proposals Executed with the reviewed actions, retained
limits and unrelated settings unchanged, every remaining unfinished action covered by an unexpired decision
bound to its payload hash, program unchanged, reads finalized if the cluster is live. It embeds the raw bytes
of the accounts those claims rest on, and `verify-certificate` re-derives the claims from the bytes.

Blocker codes and document formats are in [docs/FORMATS.md](docs/FORMATS.md).

## What a record does and does not mean

A record covers the treasuries in its scope between its first and last read. The scope is the operator's
assertion; the chain does not know which multisigs your organisation owns. `scan --discover` probes for
memberships and limits outside the declared list and prints what it finds separately, but it is best effort
and never a completeness claim.

A record is not a lock. Any member with Execute permission can act through other tooling, and the remaining
members can add the wallet back the next day. That is why every record carries `executor_bypass: true` and an
expiry slot, and why `verify-certificate` reports three separate things: whether the file matches a digest you
got from somewhere you trust, whether its recorded postconditions hold up, and whether the chain still agrees
now. A self-hash on its own shows the file was not changed by accident; it says nothing about who wrote it.

Reads go through whichever RPC endpoint you give it. A dishonest endpoint can lie consistently. If that
matters, run `verify-plan` and `certify` against a second provider.

## Not built

- SPL token spending limits are inventoried and removable like SOL ones, but only SOL limits have been
  executed in tests.
- Residual payloads are decoded to program, accounts and data, and system transfers are described in words.
  Anything else is listed, hashed and left to the reader.
- Shared limits are not rebuilt automatically, and controlled multisigs are inspection only. Both are
  deliberate.
- No proposal cancellation. A residual marked `REVOKE` has to be rejected or cancelled in Squads, then
  `certify` is run again.
- Vault addresses are not accepted in the scope. Give the multisig state address.
- No PDF export, hosted service or GRC integration.
- Tested on Windows with Python 3.13 and Node 24. No external audit.

## Something found while testing

After `RemoveMember`, the Multisig account keeps its size and the removed member's bytes are still sitting
past the end of the serialized state. The program rewrites the account in place and never reads that tail.
The first version of the decoder insisted on zero padding there and, correctly, refused to certify its own
remediation. The decoder now ignores bytes after the last field; they remain covered by the account hash, so
a change to them still counts as drift.

## Layout

```
exitguard/
  scope.py  rpc.py  collector.py  squads.py  rules.py     reading and decoding
  inventory.py  intent.py                                  review and decisions
  planner.py  sdkworker.py  verifier.py                    packet and independent checks
  record.py                                                certify and verify-certificate
  commands.py  cli.py  render.py                           the CLI
  demo.py  sim/                                            local chain, demo organisation, negative controls
sdk-worker/      Node worker around @sqds/multisig 2.1.4 and @solana/web3.js 1.95.3 (lockfile included)
fixtures/        captured Squads program accounts and their provenance
schemas/         review-scope.schema.json
examples/        one full demo run: scope, review, decisions, intent, packet, messages, record, transcript
tests/           pytest suite
docs/            formats, blocker codes, review notes, demo video
```

Licence: MIT for this code. The bundled Squads executable is AGPL-3.0 and unmodified; see
[NOTICE.md](NOTICE.md).
