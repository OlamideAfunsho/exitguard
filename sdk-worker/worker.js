// ExitGuard SDK worker.
//
// Reads {"requests": [{"op": ..., "args": {...}}, ...]} on stdin and writes
// {"results": [...]} on stdout. With --serve it stays up and handles one
// request document per line, which saves a Node start-up per call. Every op is a pure function of its arguments:
// the worker opens no sockets, reads no files and never sees a secret key.
// The Python side decodes whatever comes back before trusting it.

const multisig = require("@sqds/multisig");
const {
  PublicKey,
  TransactionMessage,
  TransactionInstruction,
  AddressLookupTableAccount,
  Message,
} = require("@solana/web3.js");
const BN = require("bn.js");

const { instructions: ix, accounts, generated } = multisig;

const pk = (s) => new PublicKey(s);
const optPk = (s) => (s === null || s === undefined ? undefined : pk(s));
const nullablePk = (s) => (s === null || s === undefined ? null : pk(s));
const programIdOf = (a) => (a.programId ? pk(a.programId) : multisig.PROGRAM_ID);

function u64(s) {
  if (typeof s !== "string" || !/^[0-9]+$/.test(s)) {
    throw new Error(`u64 values must be decimal strings, got ${JSON.stringify(s)}`);
  }
  const v = BigInt(s);
  if (v > 0xffffffffffffffffn) throw new Error(`u64 overflow: ${s}`);
  return v;
}

function instructionToJson(i) {
  return {
    program_id: i.programId.toBase58(),
    accounts: i.keys.map((k) => ({
      pubkey: k.pubkey.toBase58(),
      is_signer: k.isSigner,
      is_writable: k.isWritable,
    })),
    data: Buffer.from(i.data).toString("base64"),
  };
}

function instructionFromJson(j) {
  return new TransactionInstruction({
    programId: pk(j.program_id),
    keys: j.accounts.map((a) => ({
      pubkey: pk(a.pubkey),
      isSigner: a.is_signer,
      isWritable: a.is_writable,
    })),
    data: Buffer.from(j.data, "base64"),
  });
}

function configAction(a) {
  switch (a.kind) {
    case "RemoveSpendingLimit":
      return { __kind: "RemoveSpendingLimit", spendingLimit: pk(a.spendingLimit) };
    case "RemoveMember":
      return { __kind: "RemoveMember", oldMember: pk(a.oldMember) };
    case "AddMember":
      return {
        __kind: "AddMember",
        newMember: { key: pk(a.key), permissions: { mask: a.permissions } },
      };
    case "ChangeThreshold":
      return { __kind: "ChangeThreshold", newThreshold: a.newThreshold };
    case "AddSpendingLimit":
      return {
        __kind: "AddSpendingLimit",
        createKey: pk(a.createKey),
        vaultIndex: a.vaultIndex,
        mint: pk(a.mint),
        amount: new BN(u64(a.amount).toString()),
        period: generated.Period[a.period],
        members: a.members.map(pk),
        destinations: a.destinations.map(pk),
      };
    default:
      throw new Error(`unsupported config action ${a.kind}`);
  }
}

function innerMessage(m) {
  return new TransactionMessage({
    payerKey: pk(m.payer),
    recentBlockhash: m.recentBlockhash,
    instructions: m.instructions.map(instructionFromJson),
  });
}

function lookupTables(list) {
  if (!list || list.length === 0) return undefined;
  return list.map(
    (t) =>
      new AddressLookupTableAccount({
        key: pk(t.key),
        state: {
          deactivationSlot: BigInt("18446744073709551615"),
          lastExtendedSlot: 0,
          lastExtendedSlotStartIndex: 0,
          authority: undefined,
          addresses: t.addresses.map(pk),
        },
      })
  );
}

// JSON view of an SDK-decoded account, used only by the decoder parity tests.
function plain(v) {
  if (v === null || v === undefined) return null;
  if (v instanceof PublicKey) return v.toBase58();
  if (BN.isBN(v)) return v.toString(10);
  if (typeof v === "bigint") return v.toString(10);
  if (v instanceof Uint8Array || Buffer.isBuffer(v)) return Array.from(v);
  if (Array.isArray(v)) return v.map(plain);
  if (typeof v === "object") {
    const out = {};
    for (const [k, val] of Object.entries(v)) out[k] = plain(val);
    return out;
  }
  return v;
}

const ops = {
  configTransactionCreate(a) {
    return instructionToJson(
      ix.configTransactionCreate({
        multisigPda: pk(a.multisig),
        transactionIndex: u64(a.transactionIndex),
        creator: pk(a.creator),
        rentPayer: optPk(a.rentPayer),
        actions: a.actions.map(configAction),
        programId: programIdOf(a),
      })
    );
  },

  proposalCreate(a) {
    return instructionToJson(
      ix.proposalCreate({
        multisigPda: pk(a.multisig),
        transactionIndex: u64(a.transactionIndex),
        creator: pk(a.creator),
        rentPayer: optPk(a.rentPayer),
        isDraft: Boolean(a.isDraft),
        programId: programIdOf(a),
      })
    );
  },

  proposalActivate(a) {
    return instructionToJson(
      ix.proposalActivate({
        multisigPda: pk(a.multisig),
        transactionIndex: u64(a.transactionIndex),
        member: pk(a.member),
        programId: programIdOf(a),
      })
    );
  },

  proposalApprove(a) {
    return instructionToJson(
      ix.proposalApprove({
        multisigPda: pk(a.multisig),
        transactionIndex: u64(a.transactionIndex),
        member: pk(a.member),
        programId: programIdOf(a),
      })
    );
  },

  configTransactionExecute(a) {
    return instructionToJson(
      ix.configTransactionExecute({
        multisigPda: pk(a.multisig),
        transactionIndex: u64(a.transactionIndex),
        member: pk(a.member),
        rentPayer: optPk(a.rentPayer),
        spendingLimits: (a.spendingLimits || []).map(pk),
        programId: programIdOf(a),
      })
    );
  },

  compileMessage(a) {
    const msg = new TransactionMessage({
      payerKey: pk(a.payer),
      recentBlockhash: a.recentBlockhash,
      instructions: a.instructions.map(instructionFromJson),
    }).compileToLegacyMessage();
    return { message: Buffer.from(msg.serialize()).toString("base64") };
  },

  // ---- ops below are only used to build the local demo world and the tests ----

  multisigCreateV2(a) {
    return instructionToJson(
      ix.multisigCreateV2({
        treasury: pk(a.treasury),
        creator: pk(a.creator),
        multisigPda: pk(a.multisig),
        configAuthority: nullablePk(a.configAuthority),
        threshold: a.threshold,
        members: a.members.map((m) => ({ key: pk(m.key), permissions: { mask: m.permissions } })),
        timeLock: a.timeLock,
        createKey: pk(a.createKey),
        rentCollector: nullablePk(a.rentCollector),
        programId: programIdOf(a),
      })
    );
  },

  vaultTransactionCreate(a) {
    return instructionToJson(
      ix.vaultTransactionCreate({
        multisigPda: pk(a.multisig),
        transactionIndex: u64(a.transactionIndex),
        creator: pk(a.creator),
        vaultIndex: a.vaultIndex,
        ephemeralSigners: a.ephemeralSigners || 0,
        transactionMessage: innerMessage(a.message),
        addressLookupTableAccounts: lookupTables(a.lookupTables),
        programId: programIdOf(a),
      })
    );
  },

  batchCreate(a) {
    return instructionToJson(
      ix.batchCreate({
        multisigPda: pk(a.multisig),
        creator: pk(a.creator),
        batchIndex: u64(a.batchIndex),
        vaultIndex: a.vaultIndex,
        programId: programIdOf(a),
      })
    );
  },

  batchAddTransaction(a) {
    return instructionToJson(
      ix.batchAddTransaction({
        vaultIndex: a.vaultIndex,
        multisigPda: pk(a.multisig),
        member: pk(a.member),
        batchIndex: u64(a.batchIndex),
        transactionIndex: a.transactionIndex,
        ephemeralSigners: a.ephemeralSigners || 0,
        transactionMessage: innerMessage(a.message),
        addressLookupTableAccounts: lookupTables(a.lookupTables),
        programId: programIdOf(a),
      })
    );
  },

  spendingLimitUse(a) {
    return instructionToJson(
      ix.spendingLimitUse({
        multisigPda: pk(a.multisig),
        member: pk(a.member),
        spendingLimit: pk(a.spendingLimit),
        vaultIndex: a.vaultIndex,
        amount: a.amount,
        decimals: a.decimals,
        destination: pk(a.destination),
        programId: programIdOf(a),
      })
    );
  },

  derive(a) {
    const programId = programIdOf(a);
    const one = (r) => ({ address: r[0].toBase58(), bump: r[1] });
    switch (a.kind) {
      case "multisig":
        return one(multisig.getMultisigPda({ createKey: pk(a.createKey), programId }));
      case "vault":
        return one(multisig.getVaultPda({ multisigPda: pk(a.multisig), index: a.index, programId }));
      case "transaction":
        return one(multisig.getTransactionPda({ multisigPda: pk(a.multisig), index: u64(a.index), programId }));
      case "proposal":
        return one(
          multisig.getProposalPda({ multisigPda: pk(a.multisig), transactionIndex: u64(a.index), programId })
        );
      case "batchTransaction":
        return one(
          multisig.getBatchTransactionPda({
            multisigPda: pk(a.multisig),
            batchIndex: u64(a.batchIndex),
            transactionIndex: a.index,
            programId,
          })
        );
      case "spendingLimit":
        return one(
          multisig.getSpendingLimitPda({ multisigPda: pk(a.multisig), createKey: pk(a.createKey), programId })
        );
      case "programConfig":
        return one(multisig.getProgramConfigPda({ programId }));
      default:
        throw new Error(`unknown pda kind ${a.kind}`);
    }
  },

  decodeAccount(a) {
    const cls = accounts[a.type];
    if (!cls) throw new Error(`unknown account type ${a.type}`);
    const [decoded] = cls.fromAccountInfo({ data: Buffer.from(a.data, "base64") });
    return plain(decoded);
  },

  decodeMessage(a) {
    const m = Message.from(Buffer.from(a.message, "base64"));
    return {
      header: m.header,
      accountKeys: m.accountKeys.map((k) => k.toBase58()),
      recentBlockhash: m.recentBlockhash,
    };
  },

  versions() {
    return {
      node: process.version,
      "@sqds/multisig": require("@sqds/multisig/package.json").version,
      "@solana/web3.js": require("@solana/web3.js/package.json").version,
      program_id: multisig.PROGRAM_ID.toBase58(),
    };
  },
};

function handle(text) {
  let requests;
  try {
    requests = JSON.parse(text).requests;
    if (!Array.isArray(requests)) throw new Error("requests must be an array");
  } catch (e) {
    return { fatal: `bad input: ${e.message}` };
  }
  const results = requests.map((r, n) => {
    try {
      const fn = Object.prototype.hasOwnProperty.call(ops, r.op) ? ops[r.op] : null;
      if (!fn) throw new Error(`unknown op ${r.op}`);
      return { ok: true, value: fn(r.args || {}) };
    } catch (e) {
      return { ok: false, error: `request ${n} (${r.op}): ${e.message}` };
    }
  });
  return { results };
}

function main() {
  process.stdin.setEncoding("utf8");
  if (process.argv.includes("--serve")) {
    // One JSON document per line in, one per line out, until stdin closes.
    const lines = require("readline").createInterface({ input: process.stdin });
    lines.on("line", (line) => {
      if (line.trim()) process.stdout.write(JSON.stringify(handle(line)) + "\n");
    });
    return;
  }
  let input = "";
  process.stdin.on("data", (chunk) => (input += chunk));
  process.stdin.on("end", () => {
    const out = handle(input);
    if (out.fatal) process.exitCode = 2;
    process.stdout.write(JSON.stringify(out));
  });
}

main();
