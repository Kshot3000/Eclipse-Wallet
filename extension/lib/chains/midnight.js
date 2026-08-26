/**
 * Eclipse Wallet — Midnight chain (Cardano's privacy chain).
 * - Keys: BIP32 secp256k1, Midnight HD path m/44'/2400'/<account>'/0/0
 *   (role 0 = NightExternal, the "unshielded" key — per Midnight Wallet SDK)
 * - Public key: BIP340 x-only (32 bytes)
 * - Address: bech32m, HRP `mn_addr` (or `mn_addr_<network>`), payload = SHA256(x-only pubkey)
 * - Signing: BIP340 Schnorr over a 32-byte message (tx hash / dApp message)
 * - Transfers (v1): canonical CBOR record → BIP340 signature → submitted to
 *   the official public RPC (author_submitExtrinsic); see transfer section.
 */
import { sha256 } from '../../vendor/hashes/sha2.js';
import * as secp256k1 from '../../vendor/secp256k1.js';
import { deriveSecpPath } from '../slip10.js';
import { encodeBytes, decodeBytes, BECH32M_CONST } from '../bech32.js';
import { concatBytes, utf8ToBytes } from '../bytes.js';
import { cborEncodeCanonical, cborDecode } from '../cbor.js';

const N = secp256k1.CURVE.n;
const P = secp256k1.CURVE.p;
const Point = secp256k1.ProjectivePoint;
const G = Point.fromAffine({ x: secp256k1.CURVE.Gx, y: secp256k1.CURVE.Gy });

/** Official Midnight public RPC endpoints (verified live: `system_chain`
 *  returns "Midnight Mainnet" / "Midnight Preprod" / "Midnight Preview"). */
const RPC_URLS = {
  mainnet: 'https://rpc.mainnet.midnight.network',
  preprod: 'https://rpc.preprod.midnight.network',
  preview: 'https://rpc.preview.midnight.network',
};

const MAX_U64 = (1n << 64n) - 1n;

function mod(a, m = P) {
  const r = a % m;
  return r < 0n ? r + m : r;
}

function modPow(base, exp, m) {
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base, m);
    base = mod(base * base, m);
    exp >>= 1n;
  }
  return result;
}

/** BIP340 lift_x: recover the even-y point from a 32-byte x coordinate. */
function liftX(xBytes) {
  if (xBytes.length !== 32) throw new Error('x-only key must be 32 bytes');
  const x = secp256k1.etc.bytesToNumberBE(xBytes);
  if (x >= P) throw new Error('x coordinate out of field range');
  const ySquared = mod(x * x * x + 7n);
  let y = modPow(ySquared, (P + 1n) / 4n);
  if (mod(y * y) !== ySquared) throw new Error('No valid point for x coordinate');
  if (y % 2n !== 0n) y = P - y;
  return Point.fromAffine({ x, y });
}

function pointXBytes(pt) {
  return secp256k1.etc.numberToBytesBE(mod(pt.toAffine().x, P));
}

function taggedHash(tag, ...msgs) {
  const tagHash = sha256(utf8ToBytes(tag));
  return sha256(concatBytes(tagHash, tagHash, ...msgs));
}

export const MIDNIGHT = {
  id: 'midnight',
  name: 'Midnight',
  symbol: 'NIGHT',
  decimals: 6,
  color: '#0A0A0F',
  networks: {
    mainnet: { id: 'mainnet', networkId: null, label: 'Mainnet' },
    preprod: { id: 'preprod', networkId: 'preprod', label: 'Preprod' },
    preview: { id: 'preview', networkId: 'preview', label: 'Preview' },
  },
  defaultNetwork: 'mainnet',

  /** Derive the NightExternal (unshielded) key at m/44'/2400'/0'/0/0. */
  deriveKeys(seed, account = 0) {
    const path = `m/44'/2400'/${account}'/0/0`;
    const { privKey, pubKey } = deriveSecpPath(seed, path);
    const xOnly = pubKey.slice(1, 33); // BIP340 x-only
    if (xOnly.every((b) => b === 0)) throw new Error('Invalid Midnight key');
    return { privKey, xOnly, pubKey };
  },

  xOnlyFromPrivKey(privKey) {
    return secp256k1.getPublicKey(privKey, true).slice(1, 33);
  },

  /** Unshielded address: bech32m(mn_addr[_network], SHA256(x-only pubkey)). */
  address(xOnly, networkId = null) {
    const payload = sha256(xOnly);
    const hrp = networkId ? `mn_addr_${networkId}` : 'mn_addr';
    return encodeBytes(hrp, payload, BECH32M_CONST);
  },

  /** Decode a Midnight unshielded address -> {networkId: string|null, payload: 32B}. */
  decodeAddress(address) {
    const { hrp, bytes } = decodeBytes(String(address).trim(), BECH32M_CONST);
    if (!hrp.startsWith('mn_addr')) throw new Error('Invalid Midnight address (HRP)');
    const suffix = hrp.slice('mn_addr'.length);
    let networkId = null;
    if (suffix !== '') {
      if (!/^_[A-Za-z1-9-]+$/.test(suffix)) throw new Error('Invalid Midnight network segment');
      networkId = suffix.slice(1);
    }
    if (bytes.length !== 32) throw new Error('Invalid Midnight address payload');
    return { networkId, payload: bytes };
  },

  validateAddress(address) {
    try { this.decodeAddress(address); return true; } catch { return false; }
  },

  /* --------------------------- BIP340 Schnorr --------------------------- */

  /**
   * BIP340 Schnorr sign (bitcoin/bips bip-0340 reference algorithm).
   * `msg` may be any length (BIP340 allows arbitrary-size messages).
   * Pass `auxRand` (32 bytes) only for deterministic test-vector reproduction.
   * @returns {Uint8Array} 64-byte signature (R.x || s)
   */
  sign(msg, privKey, auxRand) {
    const d0 = secp256k1.utils.normPrivateKeyToScalar(privKey);
    if (d0 === 0n) throw new Error('Invalid private key');
    const Ppt = G.mul(d0);
    const d = mod(Ppt.toAffine().y, P) % 2n === 0n ? d0 : N - d0; // parity-folded key
    const pubX = pointXBytes(Ppt);                                  // x(P), 32 bytes
    const aux = auxRand
      ? auxRand
      : (() => { const a = new Uint8Array(32); crypto.getRandomValues(a); return a; })();
    const dBytes = secp256k1.etc.numberToBytesBE(d);
    const hAux = taggedHash('BIP0340/aux', aux);                    // 32 bytes
    const t = new Uint8Array(32);
    for (let i = 0; i < 32; i++) t[i] = dBytes[i] ^ hAux[i];        // t = d XOR H_aux(aux)
    let k0 = mod(secp256k1.etc.bytesToNumberBE(taggedHash('BIP0340/nonce', t, pubX, msg)), N);
    if (k0 === 0n) throw new Error('BIP340 nonce is zero (negligible probability)');
    const R = G.mul(k0);
    const r = pointXBytes(R);                                       // x(R), 32 bytes
    const k = mod(R.toAffine().y, P) % 2n === 0n ? k0 : N - k0;
    const e = mod(secp256k1.etc.bytesToNumberBE(taggedHash('BIP0340/challenge', r, pubX, msg)), N);
    const s = mod(k + e * d, N);
    return concatBytes(r, secp256k1.etc.numberToBytesBE(s));
  },

  /** BIP340 verify: 64-byte sig over an arbitrary-length msg with a 32-byte x-only pubkey. */
  verify(sig, msg, xOnly) {
    if (sig.length !== 64 || xOnly.length !== 32) {
      throw new Error('Invalid BIP340 inputs');
    }
    const s = secp256k1.etc.bytesToNumberBE(sig.slice(32, 64));
    if (s >= N) throw new Error('S out of range');
    const R = liftX(sig.slice(0, 32));
    const Q = liftX(xOnly);
    const e = mod(secp256k1.etc.bytesToNumberBE(
      taggedHash('BIP0340/challenge', pointXBytes(R), pointXBytes(Q), msg)
    ), N);
    // BIP340: check R == s*G - e*Q  (equivalently s*G == R + e*Q)
    return G.mul(s).equals(R.add(Q.mul(e)));
  },

  /* ------------------------ transfer records (v1) -----------------------
   * v1 NIGHT transfers are canonical, versioned transfer records:
   *   1. buildTransfer()   — deterministic CBOR record (from, to, amount,
   *                          fee, memo, network, ts) + its SHA-256 hash
   *   2. signTransfer()    — BIP340 Schnorr over the record hash with the
   *                          NightExternal (unshielded) key
   *   3. broadcastSigned() — JSON-RPC author_submitExtrinsic to the
   *                          official public RPC for the selected network
   *
   * Midnight's native ledger (ZK-proof) transaction format is built by the
   * Midnight SDK; until that integration lands, nodes will reject v1 records.
   * The wallet keeps the fully signed payload + signature sealed in the
   * receipt and reports the node's response honestly (no fake confirms).
   * ---------------------------------------------------------------------- */

  /** Official public RPC endpoint for a network (mainnet is the default). */
  rpcUrl(networkId = null) {
    return RPC_URLS[networkId] || RPC_URLS.mainnet;
  },

  /** Explorer link for a tx hash (mainnet: Midnight Subscan; testnets: polkadot.js app). */
  explorerUrl(networkId = null, txid = null) {
    const net = networkId || 'mainnet';
    if (net === 'mainnet' && txid) return `https://midnight.subscan.io/extrinsic/${txid}`;
    const rpc = encodeURIComponent(RPC_URLS[net] || RPC_URLS.mainnet);
    return `https://polkadot.js.org/apps/?rpc=${rpc}#/explorer`;
  },

  /**
   * Build the canonical transfer record (unsigned).
   * @param {object} p  {from: 32B x-only key, to: 32B address payload,
   *                     amount: bigint u64 micro-NIGHT, fee?: bigint u64 DUST,
   *                     memo?: string, network: 'mainnet'|'preprod'|'preview',
   *                     ts: unix seconds, nonce?: bigint}
   * @returns {{payload: Uint8Array, hash: Uint8Array}}
   */
  buildTransfer({ from, to, amount, fee = 0n, memo = '', network = 'mainnet', ts, nonce = 0n }) {
    if (!(from instanceof Uint8Array) || from.length !== 32) throw new Error('buildTransfer: from must be 32 bytes (x-only key)');
    if (!(to instanceof Uint8Array) || to.length !== 32) throw new Error('buildTransfer: to must be 32 bytes (address payload)');
    const amt = BigInt(amount);
    if (amt < 0n || amt > MAX_U64) throw new Error('buildTransfer: amount out of u64 range');
    const feeU = BigInt(fee);
    if (feeU < 0n || feeU > MAX_U64) throw new Error('buildTransfer: fee out of u64 range');
    const net = String(network || 'mainnet');
    if (!RPC_URLS[net]) throw new Error('buildTransfer: unknown Midnight network: ' + net);
    const t = BigInt(Math.floor(Number(ts))); // NaN/Infinity throw here
    if (t < 0n || t > MAX_U64) throw new Error('buildTransfer: bad timestamp');
    const record = {
      v: 1,
      kind: 'eclipse.transfer.v1',
      network: net,
      from,
      to,
      amount: amt,
      fee: feeU,
      memo: String(memo == null ? '' : memo).slice(0, 140),
      ts: t,
      nonce: BigInt(nonce),
    };
    const payload = cborEncodeCanonical(record);
    return { payload, hash: sha256(payload) };
  },

  /** Decode a transfer-record payload back to its field map (display/audit). */
  decodeTransfer(payload) {
    return cborDecode(payload);
  },

  /** Sign a built transfer with the NightExternal private key. Returns the 64-byte BIP340 signature over the record hash. */
  signTransfer(built, privKey, auxRand) {
    if (!built || !(built.payload instanceof Uint8Array) || !(built.hash instanceof Uint8Array)) {
      throw new Error('signTransfer: expected a built transfer');
    }
    return this.sign(built.hash, privKey, auxRand);
  },

  /** Verify a 64-byte transfer signature against the built record + 32-byte x-only key. */
  verifyTransfer(built, sig, xOnly) {
    if (!built || !(built.hash instanceof Uint8Array)) throw new Error('verifyTransfer: expected a built transfer');
    return this.verify(sig, built.hash, xOnly);
  },

  /**
   * Submit a signed transfer payload (hex) to Midnight's public RPC via
   * JSON-RPC `author_submitExtrinsic`. Honest result object:
   *   ok:true  → node accepted it (txid = its 32-byte hash)
   *   ok:false → node rejected it (error = the node's message) or the RPC
   *              was unreachable (offline:true)
   */
  async broadcastSigned(payloadHex, networkId = null) {
    const url = this.rpcUrl(networkId);
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'author_submitExtrinsic', params: [String(payloadHex)] });
    let res;
    try {
      res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
    } catch (e) {
      return { ok: false, offline: true, error: 'Midnight RPC unreachable — ' + ((e && e.message) || 'network error') };
    }
    let json = null;
    try { json = await res.json(); } catch { json = null; }
    if (json && typeof json.result === 'string' && json.result) {
      return { ok: true, txid: json.result };
    }
    if (json && json.error) {
      return { ok: false, code: json.error.code, error: json.error.message || 'node rejected the payload' };
    }
    return { ok: false, error: 'Unexpected Midnight RPC response (HTTP ' + res.status + ')' };
  },
};

export function formatXno(microXno) {
  const units = typeof microXno === 'bigint' ? microXno : BigInt(microXno);
  const neg = units < 0n;
  const abs = neg ? -units : units;
  const whole = abs / 1000000n;
  const frac = (abs % 1000000n).toString().padStart(6, '0').replace(/0+$/, '');
  return (neg ? '-' : '') + whole.toString() + (frac ? '.' + frac : '') + ' NIGHT';
}
