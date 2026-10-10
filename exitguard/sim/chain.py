"""A local chain for the demo and the tests.

LiteSVM runs the Squads executable captured from mainnet (fixtures/program).
SimChain wraps it and speaks enough Solana JSON-RPC over HTTP for ExitGuard to
read it exactly the way it reads a real node. The node says what it is in
getVersion, and ExitGuard labels everything read from it LOCAL_SIMULATION.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from solders.account import Account
from solders.hash import Hash
from solders.instruction import Instruction
from solders.keypair import Keypair
from solders.litesvm import LiteSVM
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction, VersionedTransaction

from .. import squads

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures" / "program"
START_SLOT = 310_000_000
START_TIME = 1_791_590_400  # 2026-10-10T00:00:00Z
SIM_GENESIS = str(Pubkey.from_bytes(hashlib.sha256(b"exitguard local simulation").digest()))


class TransactionFailed(Exception):
    def __init__(self, err: str, logs: list[str]):
        self.err = err
        self.logs = logs
        super().__init__(err)


class RpcFault(Exception):
    def __init__(self, code: int, message: str, data: dict | None = None):
        self.code = code
        self.message = message
        self.data = data


class SimChain:
    def __init__(self) -> None:
        # LiteSVM's own blockhash check is off because we rotate the blockhash after every
        # transaction; send_raw() enforces a recent-blockhash window itself instead.
        self.svm = LiteSVM().with_blockhash_check(False)
        self.slot = START_SLOT
        self.recent_blockhashes: list[str] = []
        self.identifies_as_simulation = True
        # Fault hooks used by the negative controls: method name -> callable(result) -> result
        self.faults: dict = {}
        self._load_program()
        self._tick(0)

    # ------------------------------------------------------------ set-up

    def _load_program(self) -> None:
        loader = Pubkey.from_string(squads.BPF_UPGRADEABLE_LOADER)
        program_id = Pubkey.from_string(squads.PROGRAM_ID)
        programdata = (FIXTURES / "programdata.bin").read_bytes()
        self.svm.set_account(
            Pubkey.from_string(squads.programdata_address()), Account(10_240_000_000, programdata, loader, False)
        )
        self.svm.set_account(program_id, Account(1_141_440, (FIXTURES / "program.bin").read_bytes(), loader, True))
        self.svm.set_account(
            Pubkey.from_string(squads.program_config_pda()),
            Account(1_893_120, (FIXTURES / "program_config.bin").read_bytes(), program_id, False),
        )

    def _tick(self, slots: int = 1) -> None:
        self.slot += slots
        self.svm.warp_to_slot(self.slot)
        clock = self.svm.get_clock()
        clock.unix_timestamp = START_TIME + (self.slot - START_SLOT) * 2 // 5
        self.svm.set_clock(clock)
        self.svm.expire_blockhash()
        self.recent_blockhashes = [str(self.svm.latest_blockhash()), *self.recent_blockhashes][:150]

    # --------------------------------------------------------- direct use

    def airdrop(self, address: Pubkey | str, lamports: int) -> None:
        self.svm.airdrop(_pk(address), lamports)

    def balance(self, address: Pubkey | str) -> int:
        return self.svm.get_balance(_pk(address)) or 0

    def account(self, address: Pubkey | str) -> Account | None:
        acct = self.svm.get_account(_pk(address))
        if acct is None or (acct.lamports == 0 and len(acct.data) == 0):
            return None
        return acct

    def set_account(self, address: Pubkey | str, data: bytes, owner: str, lamports: int | None = None) -> None:
        if lamports is None:
            lamports = self.svm.minimum_balance_for_rent_exemption(len(data))
        self.svm.set_account(_pk(address), Account(lamports, data, Pubkey.from_string(owner), False))
        self._tick()

    def delete_account(self, address: Pubkey | str) -> None:
        self.svm.set_account(_pk(address), Account(0, b"", Pubkey.from_string(squads.SYSTEM_PROGRAM), False))
        self._tick()

    def send(self, instructions: list[Instruction], payer: Keypair, signers: list[Keypair] | None = None) -> list[str]:
        keys = {str(k.pubkey()): k for k in [payer, *(signers or [])]}
        blockhash = self.svm.latest_blockhash()
        message = Message.new_with_blockhash(instructions, payer.pubkey(), blockhash)
        tx = Transaction(list(keys.values()), message, blockhash)
        return self._process(tx)

    def send_raw(self, raw: bytes) -> str:
        tx = VersionedTransaction.from_bytes(raw)
        if str(tx.message.recent_blockhash) not in self.recent_blockhashes:
            raise TransactionFailed("BlockhashNotFound", [])
        self._process(tx)
        return str(tx.signatures[0])

    def _process(self, tx) -> list[str]:
        result = self.svm.send_transaction(tx)
        if hasattr(result, "err"):
            meta = result.meta()
            raise TransactionFailed(str(result.err()), list(meta.logs()))
        self._tick()
        return list(result.logs())

    # ------------------------------------------------------------ JSON-RPC

    def _context(self) -> dict:
        return {"apiVersion": "exitguard-sim", "slot": self.slot}

    def _check_min_slot(self, config: dict) -> None:
        wanted = config.get("minContextSlot")
        if wanted is not None and wanted > self.slot:
            raise RpcFault(-32016, "Minimum context slot has not been reached", {"contextSlot": self.slot})

    def _account_json(self, acct: Account | None) -> dict | None:
        if acct is None:
            return None
        data = bytes(acct.data)
        return {
            "data": [base64.b64encode(data).decode(), "base64"],
            "executable": acct.executable,
            "lamports": acct.lamports,
            "owner": str(acct.owner),
            "rentEpoch": 0,
            "space": len(data),
        }

    def handle(self, method: str, params: list) -> object:
        result = self._dispatch(method, params)
        hook = self.faults.get(method)
        return hook(result) if hook else result

    def _dispatch(self, method: str, params: list) -> object:
        if method == "getGenesisHash":
            return SIM_GENESIS
        if method == "getVersion":
            version: dict = {"feature-set": 0, "solana-core": "2.0.0"}
            if self.identifies_as_simulation:
                version["solana-core"] = "litesvm"
                version["exitguard-simulation"] = True
            return version
        if method == "getSlot":
            self._check_min_slot(params[0] if params else {})
            return self.slot
        if method == "getLatestBlockhash":
            return {
                "context": self._context(),
                "value": {"blockhash": str(self.svm.latest_blockhash()), "lastValidBlockHeight": self.slot + 150},
            }
        if method == "getBalance":
            return {"context": self._context(), "value": self.balance(params[0])}
        if method == "getAccountInfo":
            config = params[1] if len(params) > 1 else {}
            self._check_min_slot(config)
            return {"context": self._context(), "value": self._account_json(self.account(params[0]))}
        if method == "getMultipleAccounts":
            config = params[1] if len(params) > 1 else {}
            self._check_min_slot(config)
            if len(params[0]) > 100:
                raise RpcFault(-32602, "Too many inputs provided; max 100")
            return {"context": self._context(), "value": [self._account_json(self.account(a)) for a in params[0]]}
        if method == "getProgramAccounts":
            config = params[1] if len(params) > 1 else {}
            self._check_min_slot(config)
            rows = []
            for address, acct in self.svm.get_program_accounts(Pubkey.from_string(params[0])):
                data = bytes(acct.data)
                if acct.lamports == 0 or not _matches(data, config.get("filters", [])):
                    continue
                rows.append({"pubkey": str(address), "account": self._account_json(acct)})
            rows.sort(key=lambda r: r["pubkey"])
            return {"context": self._context(), "value": rows} if config.get("withContext") else rows
        if method == "sendTransaction":
            try:
                return self.send_raw(base64.b64decode(params[0]))
            except TransactionFailed as exc:
                raise RpcFault(-32002, f"Transaction simulation failed: {exc.err}", {"logs": exc.logs}) from exc
        raise RpcFault(-32601, f"Method not found: {method}")

    def serve(self, port: int = 0) -> "SimServer":
        return SimServer(self, port)


def _pk(address: Pubkey | str) -> Pubkey:
    return address if isinstance(address, Pubkey) else Pubkey.from_string(address)


def _matches(data: bytes, filters: list[dict]) -> bool:
    for f in filters:
        if "dataSize" in f and len(data) != f["dataSize"]:
            return False
        if "memcmp" in f:
            m = f["memcmp"]
            if m.get("encoding") == "base64":
                want = base64.b64decode(m["bytes"])
            else:
                want = squads.b58decode(m["bytes"])
            if data[m["offset"] : m["offset"] + len(want)] != want:
                return False
    return True


class SimServer:
    """HTTP front for a SimChain. One request at a time; this is a test node."""

    def __init__(self, chain: SimChain, port: int = 0):
        lock = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 (http.server naming)
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                reply = {"jsonrpc": "2.0", "id": body.get("id")}
                with lock:
                    try:
                        reply["result"] = chain.handle(body["method"], body.get("params") or [])
                    except RpcFault as fault:
                        reply["error"] = {"code": fault.code, "message": fault.message}
                        if fault.data is not None:
                            reply["error"]["data"] = fault.data
                    except Exception as exc:  # a bug in the simulator should not look like chain state
                        reply["error"] = {"code": -32603, "message": f"simulator error: {exc}"}
                payload = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args) -> None:
                pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.url = f"http://127.0.0.1:{self._httpd.server_address[1]}"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def blockhash_of(text: str) -> Hash:
    return Hash.from_string(text)
