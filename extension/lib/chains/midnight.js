/**
 * Eclipse Wallet — Midnight chain (Cardano's privacy chain).
 * - Keys: BIP32 secp256k1, Midnight HD path m/44'/2400'/<account>'/0/0
 *   (role 0 = NightExternal, the "unshielded" key — per Midnight Wallet SDK)
 * - Public key: BIP340 x-only (32 bytes)
 * - Address: bech32m, HRP `mn_addr` (or `mn_addr_<network>`), payload = SHA256(x-only pubkey)
 * - Signing: BIP340 Schnorr over a 32-byte message (tx hash / dApp message)
 */
import { sha256 } from '../../vendor/hashes/sha2.js';
import * as secp256k1 from '../../vendor/secp256k1.js';
import { deriveSecpPath } from '../slip10.js';
import { encodeBytes, decodeBytes, BECH32M_CONST } from '../bech32.js';
import { concatBytes, utf8ToBytes } from '../bytes.js';

const N = secp256k1.CURVE.n;
const P = secp256k1.CURVE.p;
const Point = secp256k1.ProjectivePoint;
const G = Point.fromAffine({ x: secp256k1.CURVE.Gx, y: secp256k1.CURVE.Gy });

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
  symbol: 'XNO',
  decimals: 6,
  color: '#0A0A0F',
  networks: {
    mainnet: { id: 'mainnet', networkId: null, label: 'Mainnet' },
    testnet: { id: 'testnet', networkId: 'testnet', label: 'Testnet' },
    devnet: { id: 'devnet', networkId: 'devnet', label: 'Devnet' },
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
};

export function formatXno(microXno) {
  const units = typeof microXno === 'bigint' ? microXno : BigInt(microXno);
  const neg = units < 0n;
  const abs = neg ? -units : units;
  const whole = abs / 1000000n;
  const frac = (abs % 1000000n).toString().padStart(6, '0').replace(/0+$/, '');
  return (neg ? '-' : '') + whole.toString() + (frac ? '.' + frac : '') + ' XNO';
}