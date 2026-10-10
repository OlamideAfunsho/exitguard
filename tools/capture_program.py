"""Capture the deployed Squads v4 program from a mainnet RPC endpoint.

Writes three raw account files plus a provenance note under fixtures/program/.
The demo loads these bytes into LiteSVM, so the local run executes the same
executable that is deployed on mainnet at the captured slot.

    python tools/capture_program.py [rpc_url]
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

from solders.pubkey import Pubkey

PROGRAM_ID = Pubkey.from_string("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf")
LOADER = Pubkey.from_string("BPFLoaderUpgradeab1e11111111111111111111111")
OUT = Path(__file__).resolve().parent.parent / "fixtures" / "program"


def rpc(url: str, method: str, params: list) -> dict:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        out = json.load(resp)
    if "error" in out:
        raise SystemExit(f"{method}: {out['error']}")
    return out["result"]


def fetch(url: str, address: Pubkey) -> tuple[dict, bytes, int]:
    res = rpc(url, "getAccountInfo", [str(address), {"encoding": "base64", "commitment": "finalized"}])
    value = res["value"]
    if value is None:
        raise SystemExit(f"{address} not found")
    return value, base64.b64decode(value["data"][0]), res["context"]["slot"]


def main() -> None:
    url = sys.argv[1] if len(sys.argv) > 1 else "https://api.mainnet-beta.solana.com"
    OUT.mkdir(parents=True, exist_ok=True)

    programdata, _ = Pubkey.find_program_address([bytes(PROGRAM_ID)], LOADER)
    program_config, _ = Pubkey.find_program_address([b"multisig", b"program_config"], PROGRAM_ID)
    genesis = rpc(url, "getGenesisHash", [])

    note = {"cluster_genesis_hash": genesis, "commitment": "finalized", "accounts": {}}
    for name, address in (
        ("program", PROGRAM_ID),
        ("programdata", programdata),
        ("program_config", program_config),
    ):
        value, data, slot = fetch(url, address)
        (OUT / f"{name}.bin").write_bytes(data)
        note["accounts"][name] = {
            "address": str(address),
            "owner": value["owner"],
            "lamports": str(value["lamports"]),
            "executable": value["executable"],
            "data_len": len(data),
            "data_sha256": hashlib.sha256(data).hexdigest(),
            "read_slot": slot,
        }
        print(f"{name:15} {address}  {len(data)} bytes  slot {slot}")

    pd = (OUT / "programdata.bin").read_bytes()
    note["programdata_deploy_slot"] = str(int.from_bytes(pd[4:12], "little"))
    note["elf_sha256"] = hashlib.sha256(pd[45:]).hexdigest()
    (OUT / "CAPTURE.json").write_text(json.dumps(note, indent=2) + "\n")
    print("deploy slot", note["programdata_deploy_slot"], "elf sha256", note["elf_sha256"])


if __name__ == "__main__":
    main()
