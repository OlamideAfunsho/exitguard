# Third-party notices

ExitGuard's own source is MIT licensed (see LICENSE). It depends on, and in one
case redistributes, work by others.

## Redistributed

**Squads Protocol v4 program (compiled executable)**
`fixtures/program/programdata.bin`, `program.bin`, `program_config.bin`

These are raw account bytes read from Solana mainnet-beta with
`tools/capture_program.py`. `fixtures/program/CAPTURE.json` records the slot,
the cluster genesis hash and the SHA-256 of each file. The executable is the
deployed build of https://github.com/Squads-Protocol/v4, which is licensed
AGPL-3.0. It is included unmodified, only so the local demo and the tests run
the real program. The corresponding source is at that repository. Nothing in
ExitGuard links against or is derived from the program's source code.

## Used, not redistributed

Installed by `pip` and `npm ci`; see `requirements.txt` and
`sdk-worker/package-lock.json` for exact versions.

| Package | Version | Licence | Used for |
| --- | --- | --- | --- |
| solders (includes LiteSVM bindings) | 0.29.0 | MIT / Apache-2.0 | keys, PDAs, signature checks, local SVM |
| @sqds/multisig | 2.1.4 | MIT | official instruction builders |
| @solana/web3.js | 1.95.3 | MIT | message compilation in the worker |
| bn.js | 5.2.x | MIT | u64 arguments in the worker |
| pytest | 8.x | MIT | tests only |

Transitive npm dependencies and their licences are listed in
`sdk-worker/package-lock.json`.
