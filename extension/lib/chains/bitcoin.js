/**
 * Eclipse Wallet — Bitcoin chain.
 * - Keys: BIP32 secp256k1, native SegWit path m/84'/0'/0'/0/0 (P2WPKH)
 * - Addresses: bech32 (bc1... / tb1...)
 * - Data: Blockstream public API + mempool.space fees
 * - Signing: BIP143 (SIGHASH_ALL, low-S, RFC6979 deterministic)
 */
import { sha256 } from '../../vendor/hashes/sha2.js';
import { ripemd160 } from '../../vendor/hashes/ripemd160.js';
import * as secp256k1 from '../../vendor/secp256k1.js';
import { deriveSecpPath } from '../slip10.js';
import { encode, decode, convertBits, BECH32_CONST } from '../bech32.js';
import {
  concatBytes, hexToBytes, bytesToHex, le32, le64,
  bitcoinVarInt, reverseBytes, be64ToBig,
} from '../bytes.js';

const sha256d = (bytes) => sha256(sha256(bytes));

function blockstreamBase(network) {
  return network === 'testnet'
    ? 'https://blockstream.info/testnet/api'
    : 'https://blockstream.info/api';
}

function mempoolBase(network) {
  return network === 'testnet' ? 'https://mempool.space/testnet/api' : 'https://mempool.space/api';
}

/** DER-encode an ECDSA signature (r, s are 32-byte big-endian). */
export function derEncodeSignature(r, s) {
  const trim = (v) => {
    let start = 0;
    while (start < v.length - 1 && v[start] === 0) start++;
    const out = v.slice(start);
    if (out[0] & 0x80) return concatBytes(new Uint8Array([0x00]), out);
    return out;
  };
  const rBytes = trim(r);
  const sBytes = trim(s);
  const body = concatBytes(
    new Uint8Array([0x02, rBytes.length]), rBytes,
    new Uint8Array([0x02, sBytes.length]), sBytes
  );
  return concatBytes(new Uint8Array([0x30, body.length]), body);
}

export const BITCOIN = {
  id: 'bitcoin',
  name: 'Bitcoin',
  symbol: 'BTC',
  decimals: 8,
  color: '#F7931A',
  networks: {
    mainnet: { id: 'mainnet', hrp: 'bc', label: 'Mainnet' },
    testnet: { id: 'testnet', hrp: 'tb', label: 'Testnet' },
  },
  defaultNetwork: 'mainnet',

  deriveKeys(seed) {
    const { privKey, pubKey } = deriveSecpPath(seed, "m/84'/0'/0'/0/0");
    const keyHash = ripemd160(sha256(pubKey)); // 20 bytes
    return { privKey, pubKey, keyHash };
  },

  address(keys, network) {
    // P2WPKH: 5-bit witness version 0 followed by the 20-byte key hash.
    // (The witness version is 5 bits, NOT a full byte — encoding it as a byte
    // produces an invalid, non-byte-aligned bech32 string.)
    const words = [0, ...convertBits([...keys.keyHash], 8, 5, true)];
    return encode(network.hrp, words, BECH32_CONST);
  },

  /** Decode a bech32 P2WPKH address -> {networkId: 0|1, keyHash} or throw. */
  decodeAddress(address) {
    const { hrp, data } = decode(String(address), BECH32_CONST);
    if (hrp !== 'bc' && hrp !== 'tb') throw new Error('Invalid Bitcoin address');
    if (data.length < 1) throw new Error('Invalid bech32 data');
    if (data[0] !== 0) throw new Error('Unsupported address type (need P2WPKH)');
    const keyHash = new Uint8Array(convertBits([...data.slice(1)], 5, 8, false));
    if (keyHash.length !== 20) throw new Error('Unsupported address type (need P2WPKH)');
    return { networkId: hrp === 'bc' ? 0 : 1, keyHash };
  },

  validateAddress(address) {
    try { this.decodeAddress(address); return true; } catch { return false; }
  },

  /** Fetch unspent P2WPKH outputs for an address. */
  async getUtxos(address, network = 'mainnet') {
    const base = blockstreamBase(network);
    const txs = await (await fetch(`${base}/address/${address}/txs?limit=1000`)).json();
    if (!Array.isArray(txs)) throw new Error('Blockstream: unexpected response');
    const spent = new Set();
    for (const tx of txs) {
      for (const vin of tx.vin || []) spent.add(`${vin.txid}:${vin.vout}`);
    }
    const utxos = [];
    for (const tx of txs) {
      for (let i = 0; i < (tx.vout || []).length; i++) {
        const out = tx.vout[i];
        const key = `${tx.txid}:${i}`;
        if (spent.has(key)) continue;
        const spk = out.scriptpubkey || '';
        if (spk.length !== 44 || !spk.startsWith('0014')) continue; // P2WPKH only
        utxos.push({
          txid: tx.txid,
          vout: i,
          sats: BigInt(out.value),
          keyHash: hexToBytes(spk.slice(4)),
        });
      }
    }
    return utxos;
  },

  async getBalance(address, network = 'mainnet') {
    const base = blockstreamBase(network);
    const info = await (await fetch(`${base}/address/${address}`)).json();
    const stats = info.chain_stats || info.mempool_stats || {};
    return {
      funded: BigInt(stats.funded_txo_sum || 0),
      spent: BigInt(stats.spent_txo_sum || 0),
      received: BigInt(info.chain_stats?.received || 0),
    };
  },

  async getFees(network = 'mainnet') {
    const j = await (await fetch(`${mempoolBase(network)}/fees/recommended`)).json();
    return {
      fastest: Number(j.fastestFee) || 1,
      halfHour: Number(j.halfHourFee) || 1,
      economy: Number(j.economyFee) || 1,
      minimum: Number(j.minimumFee) || 1,
    };
  },

  /**
   * Coin-select UTXOs for the target + estimated fee.
   */
  selectInputs(utxos, targetSats, feeEstimateSats) {
    const sorted = [...utxos].sort((a, b) => (b.sats > a.sats ? 1 : -1));
    const selected = [];
    let total = 0n;
    for (const u of sorted) {
      selected.push(u);
      total += u.sats;
      if (total >= targetSats + feeEstimateSats) break;
    }
    if (total < targetSats) throw new Error('Insufficient BTC balance');
    return { selected, total };
  },

  /**
   * BIP143 sighash preimage for a P2WPKH input.
   */
  sighashPreimage({ inputs, outputs, inputIndex, amountSats, locktime = 0, version = 2 }) {
    const input = inputs[inputIndex];
    // API convention: txid fields are display-order hex (explorer style).
    // Consensus serialization uses internal byte order = reversed.
    const hashPrevouts = sha256d(concatBytes(...inputs.map((i) => concatBytes(reverseBytes(hexToBytes(i.txid)), le32(i.vout)))));
    const hashSequence = sha256d(concatBytes(...inputs.map((i) => le32(i.sequence ?? 0xffffffff - 1))));
    const hashOutputs = sha256d(concatBytes(...outputs.map((o) => concatBytes(le64(o.valueSats), bitcoinVarInt(o.script.length), o.script))));
    // BIP143: for P2WPKH (and P2SH-P2WPKH) the scriptCode is the P2PKH
    // script 0x1976a914<20-byte-key-hash>88ac — NOT the 0x0014 witness spk.
    return concatBytes(
      le32(version),
      hashPrevouts,
      hashSequence,
      reverseBytes(hexToBytes(input.txid)),
      le32(input.vout),
      bitcoinVarInt(25),
      new Uint8Array([0x76, 0xa9, 0x14]),
      input.keyHash,
      new Uint8Array([0x88, 0xac]),
      le64(amountSats),
      le32(input.sequence ?? 0xffffffff - 1),
      hashOutputs,
      le32(locktime),
      le32(0x01) // SIGHASH_ALL
    );
  },

  /**
   * Sign all inputs (P2WPKH) and serialize the full raw transaction (hex).
   */
  signAndSerialize({ inputs, outputs, privKey, pubKey, locktime = 0, version = 2 }) {
    // Witness stack per input: [DER-sig + SIGHASH_ALL, 33-byte pubkey].
    const witnesses = inputs.map((input, i) => {
      const preimage = this.sighashPreimage({ inputs, outputs, inputIndex: i, amountSats: input.sats, locktime, version });
      const msg = sha256d(preimage);
      const sig = secp256k1.sign(msg, privKey); // low-S by default
      const compact = sig.toCompactRawBytes(); // 64 bytes r||s
      const der = derEncodeSignature(compact.slice(0, 32), compact.slice(32, 64));
      return [concatBytes(der, new Uint8Array([0x01])), pubKey];
    });

    // SegWit serialization: version, marker(0x00), flag(0x01), then legacy body,
    // then the witness stack (per-input item count, then length-prefixed items).
    const parts = [le32(version), new Uint8Array([0x00, 0x01])];
    parts.push(bitcoinVarInt(inputs.length));
    for (const input of inputs) {
      // Input = prevout(txid internal-order, vout) + scriptSig(varint+bytes) + sequence.
      // Native P2WPKH has an empty scriptSig; P2SH-P2WPKH pushes the redeemScript.
      const scriptSig = input.scriptSig ?? new Uint8Array(0);
      parts.push(
        reverseBytes(hexToBytes(input.txid)),
        le32(input.vout),
        bitcoinVarInt(scriptSig.length),
        scriptSig,
        le32(input.sequence ?? 0xffffffff - 1)
      );
    }
    parts.push(bitcoinVarInt(outputs.length));
    for (const out of outputs) {
      parts.push(le64(out.valueSats), bitcoinVarInt(out.script.length), out.script);
    }
    // Witness stacks (one per input), then locktime. BIP144 order:
    // version, marker, flag, inputs, outputs, witnesses, locktime LAST.
    for (const items of witnesses) {
      parts.push(bitcoinVarInt(items.length));
      for (const item of items) parts.push(bitcoinVarInt(item.length), item);
    }
    parts.push(le32(locktime));
    return bytesToHex(concatBytes(...parts));
  },

  /** Approximate virtual size (vbytes) of a P2WPKH tx.
   * non-witness = 12 + 40*nIn + 31*nOut; witness ~= 108*nIn (counted /4).
   * A small margin keeps the fee above the node min-relay threshold. */
  vbytesFor(nIn, nOut) {
    return 12 + 68 * nIn + 31 * nOut;
  },

  /** Build a standard 2-output send (recipient + change). */
  buildSend({ utxos, toKeyHash, amountSats, feeRate, changeKeyHash }) {
    const estFeeSats = BigInt(this.vbytesFor(1, 2) * feeRate);
    const { selected, total } = this.selectInputs(utxos, amountSats, estFeeSats);
    const nIn = selected.length;
    // Two passes for fee convergence.
    let feeSats = estFeeSats;
    for (let i = 0; i < 4; i++) {
      const changeSats = total - amountSats - feeSats;
      const nOut = changeSats > 546n ? 2 : 1;
      feeSats = BigInt(Math.ceil(this.vbytesFor(nIn, nOut) * feeRate));
    }
    let changeSats = total - amountSats - feeSats;
    if (changeSats < 0n) throw new Error('Insufficient BTC balance (including fee)');
    if (changeSats > 0n && changeSats < 546n) changeSats = 0n; // dust

    // P2WPKH scriptPubKey: OP_0 (0x00) PUSH20 (0x14) <20-byte key hash>.
    const toScript = concatBytes(new Uint8Array([0x00, 0x14]), toKeyHash);
    const outputs = [{ script: toScript, valueSats: amountSats }];
    if (changeSats > 0n) {
      outputs.push({ script: concatBytes(new Uint8Array([0x00, 0x14]), changeKeyHash), valueSats: changeSats });
    }
    const inputs = selected.map((u) => ({
      txid: u.txid, vout: u.vout, sats: u.sats, keyHash: u.keyHash,
      sequence: 0xffffffff - 1,
    }));
    return { inputs, outputs, feeSats, changeSats };
  },

  /**
   * Compute the txid of a raw transaction hex.
   * Handles SegWit (marker/flag) transactions: the txid is the dSHA256 of the
   * LEGACY serialization (version, inputs incl. scriptSig, outputs, locktime)
   * with the witness data excluded. Returns display-order (big-endian) hex.
   */
  txidOf(rawHex) {
    const bytes = hexToBytes(rawHex);
    let off = 0;
    const readU32 = () => {
      if (off + 4 > bytes.length) throw new Error('txidOf: truncated');
      const v = le32ToNum(bytes, off); off += 4; return v;
    };
    const readVarInt = () => {
      if (off >= bytes.length) throw new Error('txidOf: truncated');
      const first = bytes[off++];
      if (first < 0xfd) return first;
      if (first === 0xfd) { const v = le32ToNum(bytes, off) & 0xffff; off += 2; return v; }
      if (first === 0xfe) { const v = le32ToNum(bytes, off); off += 4; return v; }
      const v = Number(be64ToBig(bytes, off)); off += 8; return v;
    };
    const version = readU32();
    // SegWit marker (0x00) + flag (0x01) appear immediately after the version
    // in witness transactions. A legacy tx never has 0 inputs, so this pair is
    // unambiguous.
    const isSegwit = bytes[off] === 0x00 && bytes[off + 1] === 0x01;
    if (isSegwit) off += 2;
    const nIn = readVarInt();
    const legacyParts = [le32(version), bitcoinVarInt(nIn)];
    for (let i = 0; i < nIn; i++) {
      const txid = bytes.slice(off, off + 32); off += 32;
      const vout = readU32();
      const scriptLen = readVarInt();
      const scriptSig = bytes.slice(off, off + scriptLen); off += scriptLen;
      const sequence = readU32();
      legacyParts.push(txid, le32(vout), bitcoinVarInt(scriptLen), scriptSig, le32(sequence));
    }
    const nOut = readVarInt();
    legacyParts.push(bitcoinVarInt(nOut));
    for (let i = 0; i < nOut; i++) {
      const value = bytes.slice(off, off + 8); off += 8;
      const scriptLen = readVarInt();
      const script = bytes.slice(off, off + scriptLen); off += scriptLen;
      legacyParts.push(value, bitcoinVarInt(scriptLen), script);
    }
    // Skip the witness data (one stack per input) before the locktime.
    if (isSegwit) {
      for (let i = 0; i < nIn; i++) {
        const itemCount = readVarInt();
        for (let j = 0; j < itemCount; j++) {
          const itemLen = readVarInt();
          off += itemLen;
        }
      }
    }
    const locktime = bytes.slice(off, off + 4); off += 4;
    legacyParts.push(locktime);
    // txid = dSHA256(legacy serialization), shown in big-endian (display) order.
    return bytesToHex(reverseBytes(sha256d(concatBytes(...legacyParts))));
  },

  async broadcast(rawHex, network = 'mainnet') {

    const res = await fetch(`${blockstreamBase(network)}/tx`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/hex' },
      body: rawHex,
    });
    if (res.ok) return (await res.text()).trim();
    const text = await res.text().catch(() => '');
    throw new Error(`Bitcoin broadcast failed (${res.status}): ${text.slice(0, 300)}`);
  },
};

/** Little-endian 32-bit (Bitcoin wire format) — bytes are least significant first. */
function le32ToNum(b, o) {
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
}

export function formatBtc(sats) {
  const units = typeof sats === 'bigint' ? sats : BigInt(sats);
  const neg = units < 0n;
  const abs = neg ? -units : units;
  const whole = abs / 100000000n;
  const frac = (abs % 100000000n).toString().padStart(8, '0').replace(/0+$/, '');
  return (neg ? '-' : '') + whole.toString() + (frac ? '.' + frac : '') + ' BTC';
}
