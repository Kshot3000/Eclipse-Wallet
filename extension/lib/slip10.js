/**
 * Eclipse Wallet — SLIP-0010 / BIP32 hierarchical key derivation.
 * - ed25519 (Cardano) — SLIP-0010
 * - secp256k1 (Bitcoin, Midnight) — BIP32 (a.k.a. SLIP-0010 for secp)
 */
import { hmac } from '../vendor/hashes/hmac.js';
import { sha256 } from '../vendor/hashes/sha2.js';
import { sha512 } from '../vendor/hashes/sha512.js';
import * as ed25519 from '../vendor/ed25519.js';
import * as secp256k1 from '../vendor/secp256k1.js';
import { be32, concatBytes, utf8ToBytes } from './bytes.js';

// noble-ed25519 requires a synchronous SHA-512 to be injected once (it ships
// without one by default). Every chain module transitively imports this file,
// so the wiring happens exactly once for the whole app.
ed25519.etc.sha512Sync = sha512;

// noble-secp256k1's deterministic RFC 6979 nonce generation needs a
// synchronous HMAC-SHA256. Expected signature: f(key, value, ...extraMsgs)
// -> HMAC(key, value || extraMsgs...). Without this, secp256k1.sign() throws
// "etc.hmacSha256Sync not set" (Bitcoin + Midnight signing).
secp256k1.etc.hmacSha256Sync = (key, ...msgs) => hmac(sha256, key, concatBytes(...msgs));

export const HARDENED = 0x80000000;

/** Parse "m/44'/1815'/0'/0'/0" or [44|H, 1815|H, 0|H, 0|H, 0] into uint32 indices. */
export function parsePath(path) {
  if (Array.isArray(path)) {
    return path.map((p) => (typeof p === 'number' ? p >>> 0 : parseSingle(p)));
  }
  const s = String(path).trim();
  if (s === 'm' || s === '') return [];
  if (!s.startsWith('m/')) throw new Error('Path must start with m/');
  const parts = s.slice(2).split('/');
  const out = [];
  for (const part of parts) {
    if (part.length === 0) throw new Error('Empty path component');
    out.push(parseSingle(part));
  }
  return out;
}

function parseSingle(part) {
  let hardened = false;
  let idxStr = part;
  if (idxStr.endsWith("'") || idxStr.endsWith('h') || idxStr.endsWith('H')) {
    hardened = true;
    idxStr = idxStr.slice(0, -1);
  }
  const n = Number(idxStr);
  if (!Number.isSafeInteger(n) || n < 0 || n >= 0xffffffff) throw new Error('Invalid path index: ' + part);
  return hardened ? (n + HARDENED) >>> 0 : n >>> 0;
}

/* ------------------------- ed25519 (SLIP-0010) ------------------------- */

export function ed25519Master(seed) {
  const I = hmac(sha512, utf8ToBytes('ed25519 seed'), seed);
  return { privKey: I.slice(0, 32), chainCode: I.slice(32, 64) };
}

export function ed25519Child(parent, index) {
  const hardened = (index & HARDENED) !== 0;
  const data = concatBytes(
    new Uint8Array([0x00]),
    hardened ? parent.privKey : ed25519.getPublicKey(parent.privKey),
    be32(index >>> 0)
  );
  const I = hmac(sha512, parent.chainCode, data);
  return { privKey: I.slice(0, 32), chainCode: I.slice(32, 64) };
}

/**
 * Derive an ed25519 key at a BIP44-style path.
 * @returns {{privKey: Uint8Array, chainCode: Uint8Array, pubKey: Uint8Array}}
 */
export function deriveEd25519Path(seed, path) {
  let node = ed25519Master(seed);
  for (const index of parsePath(path)) node = ed25519Child(node, index);
  return {
    privKey: node.privKey,
    chainCode: node.chainCode,
    pubKey: ed25519.getPublicKey(node.privKey),
  };
}

/* ------------------------ secp256k1 (BIP32) ------------------------ */

const N = secp256k1.CURVE.n;

function normPriv(bytes32) {
  const scalar = secp256k1.utils.normPrivateKeyToScalar(bytes32);
  return secp256k1.etc.numberToBytesBE(scalar);
}

export function secpMaster(seed) {
  const I = hmac(sha512, utf8ToBytes('Bitcoin seed'), seed);
  const privKey = I.slice(0, 32);
  if (privKey.every((b) => b === 0) || secp256k1.utils.normPrivateKeyToScalar(privKey) >= N) {
    throw new Error('Invalid master key');
  }
  return {
    privKey,
    chainCode: I.slice(32, 64),
    pubKey: secp256k1.getPublicKey(privKey, true),
  };
}

export function secpChild(parent, index) {
  const hardened = (index & HARDENED) !== 0;
  const data = concatBytes(
    hardened
      ? concatBytes(new Uint8Array([0x00]), parent.privKey)
      : parent.pubKey,
    be32(index >>> 0)
  );
  const I = hmac(sha512, parent.chainCode, data);
  const IL = I.slice(0, 32);
  const IR = I.slice(32, 64);
  const childScalar = (secp256k1.etc.bytesToNumberBE(IL) + secp256k1.etc.bytesToNumberBE(parent.privKey)) % N;
  if (childScalar === 0n) throw new Error('Invalid child key');
  const privKey = secp256k1.etc.numberToBytesBE(childScalar);
  return {
    privKey,
    chainCode: IR,
    pubKey: secp256k1.getPublicKey(privKey, true),
  };
}

/**
 * Derive a secp256k1 key at a BIP44-style path.
 * @returns {{privKey: Uint8Array, chainCode: Uint8Array, pubKey: Uint8Array}}
 */
export function deriveSecpPath(seed, path) {
  let node = secpMaster(seed);
  for (const index of parsePath(path)) node = secpChild(node, index);
  return {
    privKey: node.privKey,
    chainCode: node.chainCode,
    pubKey: node.pubKey,
  };
}

/** x-only (32-byte) public key, per BIP340 / Midnight spec. */
export function xOnlyPublicKey(privKey) {
  const full = secp256k1.getPublicKey(privKey, true); // 33-byte compressed
  return full.slice(1, 33);
}
