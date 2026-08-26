/**
 * Eclipse Wallet — CBOR (RFC 8949) encoder / decoder.
 * - Encoder: definite lengths only (what Cardano requires).
 * - `cborEncodeCanonical`: map keys sorted by their encoded byte form
 *   (Cardano canonical form — required for transaction hashes).
 * - Decoder: supports definite and indefinite length items.
 */
import { be64, be32, concatBytes, be64ToBig } from './bytes.js';

const MAJ_UINT = 0, MAJ_NEGINT = 1, MAJ_BYTES = 2, MAJ_TEXT = 3,
      MAJ_ARRAY = 4, MAJ_MAP = 5, MAJ_TAG = 6, MAJ_SIMPLE = 7;

function encodeHead(major, length) {
  const m = major << 5;
  // `length` may be a BigInt (integers up to 2^64-1); compare with BigInt literals
  // and only convert to Number in the small branches (bitwise ops forbid mixing).
  const n = typeof length === 'bigint' ? length : BigInt(length);
  if (n < 24n) return new Uint8Array([m | Number(n)]);
  if (n <= 0xffn) return new Uint8Array([m | 24, Number(n)]);
  if (n <= 0xffffn) {
    const b = new Uint8Array(3);
    b[0] = m | 25; b[1] = Number((n >> 8n) & 0xffn); b[2] = Number(n & 0xffn);
    return b;
  }
  if (n <= 0xffffffffn) {
    const b = new Uint8Array(5);
    b[0] = m | 26;
    b[1] = Number((n >> 24n) & 0xffn); b[2] = Number((n >> 16n) & 0xffn);
    b[3] = Number((n >> 8n) & 0xffn); b[4] = Number(n & 0xffn);
    return b;
  }
  return concatBytes(new Uint8Array([m | 27]), be64(n));
}

/** CBOR bignum tag (2 = positive, 3 = negative): tag header + big-endian byte string of the non-negative magnitude. */
function bignumTag(tag, magnitude) {
  const bytes = [];
  let m = magnitude;
  while (m > 0n) { bytes.unshift(Number(m & 0xffn)); m >>= 8n; }
  if (bytes.length === 0) bytes.push(0);
  return concatBytes(encodeHead(MAJ_TAG, BigInt(tag)), encodeHead(MAJ_BYTES, BigInt(bytes.length)), new Uint8Array(bytes));
}

/** Encode one JS value to CBOR bytes (definite lengths). */
export function cborEncode(value) {
  const parts = [];
  encodeValue(value, parts);
  return concatBytes(...parts);
}

function encodeValue(value, parts) {
  if (value === null) { parts.push(new Uint8Array([0xf6])); return; }
  if (value === undefined) { parts.push(new Uint8Array([0xf7])); return; }
  if (value === true) { parts.push(new Uint8Array([0xf5])); return; }
  if (value === false) { parts.push(new Uint8Array([0xf4])); return; }

  if (typeof value === 'bigint' || (typeof value === 'number' && Number.isInteger(value))) {
    // Integer (bigint, or an integer double such as 2^64). Use the 64-bit
    // unsigned / negative-int major types when in range, otherwise CBOR
    // bignum tags (2 = positive, 3 = negative) over a big-endian byte string.
    const n = (typeof value === 'bigint') ? value : BigInt(value);
    const MAX64 = (1n << 64n) - 1n; // 2^64 - 1  (max unsigned 64-bit)
    const MIN64 = -(1n << 64n);    // -(2^64)   (min negative-int)
    if (n >= 0n && n <= MAX64) {
      parts.push(encodeHead(MAJ_UINT, n));
    } else if (n >= MIN64 && n <= -1n) {
      parts.push(encodeHead(MAJ_NEGINT, -1n - n));
    } else if (n > MAX64) {
      parts.push(bignumTag(2, n));
    } else { // n < MIN64
      parts.push(bignumTag(3, -1n - n));
    }
    return;
  }
  if (typeof value === 'number') {
    // IEEE-754 double
    const b = new Uint8Array(9);
    b[0] = 0xfb;
    new DataView(b.buffer).setFloat64(1, value, false);
    parts.push(b);
    return;
  }
  if (typeof value === 'string') {
    const bytes = new TextEncoder().encode(value);
    parts.push(encodeHead(MAJ_TEXT, bytes.length), bytes);
    return;
  }
  if (value instanceof Uint8Array) {
    parts.push(encodeHead(MAJ_BYTES, value.length), value);
    return;
  }
  if (Array.isArray(value)) {
    parts.push(encodeHead(MAJ_ARRAY, value.length));
    for (const item of value) encodeValue(item, parts);
    return;
  }
  if (value instanceof Map) {
    const entries = [...value.entries()];
    parts.push(encodeHead(MAJ_MAP, entries.length));
    for (const [k, v] of entries) { encodeValue(k, parts); encodeValue(v, parts); }
    return;
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value).filter(([, v]) => v !== undefined);
    parts.push(encodeHead(MAJ_MAP, entries.length));
    for (const [k, v] of entries) { encodeValue(k, parts); encodeValue(v, parts); }
    return;
  }
  throw new Error('Cannot CBOR-encode value: ' + typeof value);
}

/**
 * Encode with canonical (Cardano) ordering: every map's keys are sorted
 * by their encoded byte representation, lexicographically.
 */
export function cborEncodeCanonical(value) {
  const parts = [];
  encodeCanonical(value, parts);
  return concatBytes(...parts);
}

function encodeCanonical(value, parts) {
  if (Array.isArray(value)) {
    parts.push(encodeHead(MAJ_ARRAY, value.length));
    for (const item of value) encodeCanonical(item, parts);
    return;
  }
  // Only Maps and plain objects are map structures. Leaf values — including
  // Uint8Array, which is also `typeof === 'object'` — must go through the
  // plain encoder so byte strings stay byte strings (Cardano tx bodies,
  // signees and txids depend on this).
  let entries = null;
  if (value instanceof Map) entries = [...value.entries()];
  else if (value !== null && typeof value === 'object' && !(value instanceof Uint8Array)) {
    entries = Object.entries(value).filter(([, v]) => v !== undefined);
  }
  if (entries !== null) {
    // Encode keys, sort by encoded bytes, then emit pairs.
    const pairs = entries.map(([k, v]) => {
      const keyParts = [];
      encodeCanonical(k, keyParts);
      return { keyBytes: concatBytes(...keyParts), value: v };
    });
    pairs.sort((a, b) => compareBytes(a.keyBytes, b.keyBytes));
    parts.push(encodeHead(MAJ_MAP, pairs.length));
    for (const p of pairs) {
      parts.push(p.keyBytes);
      encodeCanonical(p.value, parts);
    }
    return;
  }
  encodeValue(value, parts);
}

function compareBytes(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/* ----------------------------- decoder ----------------------------- */

export function cborDecode(bytes) {
  const cursor = { i: 0 };
  const value = decodeValue(bytes, cursor, 0);
  if (cursor.i !== bytes.length) throw new Error('Trailing bytes after CBOR item');
  return value;
}

/** True when the next item is the break code (0xff) terminating an indefinite-length sequence. */
function atBreak(bytes, cursor) {
  return cursor.i < bytes.length && bytes[cursor.i] === 0xff;
}

function readLength(bytes, cursor, additional) {
  if (additional < 24) return { length: additional, big: false };
  if (additional === 24) {
    if (cursor.i + 1 > bytes.length) throw new Error('CBOR truncated');
    return { length: bytes[cursor.i++], big: false };
  }
  if (additional === 25) {
    if (cursor.i + 2 > bytes.length) throw new Error('CBOR truncated');
    const n = (bytes[cursor.i] << 8) | bytes[cursor.i + 1];
    cursor.i += 2;
    return { length: n, big: false };
  }
  if (additional === 26) {
    if (cursor.i + 4 > bytes.length) throw new Error('CBOR truncated');
    const n = be32ToNum(bytes, cursor.i);
    cursor.i += 4;
    return { length: n, big: false };
  }
  if (additional === 27) {
    if (cursor.i + 8 > bytes.length) throw new Error('CBOR truncated');
    const length = be64ToBig(bytes, cursor.i);
    cursor.i += 8;
    return { length, big: true };
  }
  if (additional === 31) return { length: -1, big: false }; // indefinite
  throw new Error('Invalid CBOR additional info: ' + additional);
}

function be32ToNum(b, o) {
  return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
}

function decodeValue(bytes, cursor, depth) {
  if (depth > 100) throw new Error('CBOR nesting too deep');
  if (cursor.i >= bytes.length) throw new Error('CBOR truncated');
  const head = bytes[cursor.i++];
  const major = head >> 5;
  const additional = head & 0x1f;

  switch (major) {
    case MAJ_UINT: {
      const { length } = readLength(bytes, cursor, additional);
      const n = typeof length === 'bigint' ? length : BigInt(length);
      return n <= Number.MAX_SAFE_INTEGER ? Number(n) : n;
    }
    case MAJ_NEGINT: {
      const { length } = readLength(bytes, cursor, additional);
      const n = (typeof length === 'bigint' ? length : BigInt(length));
      const result = -1n - n;
      return result >= -Number.MAX_SAFE_INTEGER ? Number(result) : result;
    }
    case MAJ_BYTES: {
      const { length } = readLength(bytes, cursor, additional);
      if (length === -1) {
        const chunks = [];
        for (;;) {
          if (atBreak(bytes, cursor)) { cursor.i++; break; }
          const chunk = decodeValue(bytes, cursor, depth + 1);
          if (!(chunk instanceof Uint8Array)) throw new Error('Invalid indefinite-length byte chunk');
          chunks.push(chunk);
        }
        return concatBytes(...chunks);
      }
      if (cursor.i + length > bytes.length) throw new Error('CBOR bytes truncated');
      const out = bytes.slice(cursor.i, cursor.i + length);
      cursor.i += length;
      return out;
    }
    case MAJ_TEXT: {
      const { length } = readLength(bytes, cursor, additional);
      if (length === -1) {
        let s = '';
        for (;;) {
          if (atBreak(bytes, cursor)) { cursor.i++; break; }
          s += decodeValue(bytes, cursor, depth + 1);
        }
        return s;
      }
      if (cursor.i + length > bytes.length) throw new Error('CBOR text truncated');
      const out = new TextDecoder('utf-8').decode(bytes.slice(cursor.i, cursor.i + length));
      cursor.i += length;
      return out;
    }
    case MAJ_ARRAY: {
      const { length } = readLength(bytes, cursor, additional);
      const arr = [];
      if (length === -1) {
        for (;;) {
          if (atBreak(bytes, cursor)) { cursor.i++; break; }
          arr.push(decodeValue(bytes, cursor, depth + 1));
        }
      } else {
        const count = Number(length);
        for (let k = 0; k < count; k++) arr.push(decodeValue(bytes, cursor, depth + 1));
      }
      return arr;
    }
    case MAJ_MAP: {
      const { length } = readLength(bytes, cursor, additional);
      const map = new Map();
      if (length === -1) {
        for (;;) {
          if (atBreak(bytes, cursor)) { cursor.i++; break; }
          const key = decodeValue(bytes, cursor, depth + 1);
          map.set(key, decodeValue(bytes, cursor, depth + 1));
        }
      } else {
        const count = Number(length);
        for (let k = 0; k < count; k++) {
          const key = decodeValue(bytes, cursor, depth + 1);
          map.set(key, decodeValue(bytes, cursor, depth + 1));
        }
      }
      return map;
    }
    case MAJ_TAG: {
      const { length } = readLength(bytes, cursor, additional);
      const tagNum = typeof length === 'bigint' ? length : BigInt(length);
      const content = decodeValue(bytes, cursor, depth + 1);
      // Bignum tags: 2 = positive, 3 = negative (over a byte string).
      if ((tagNum === 2n || tagNum === 3n) && content instanceof Uint8Array) {
        let v = 0n;
        for (let i = 0; i < content.length; i++) v = (v << 8n) | BigInt(content[i]);
        return tagNum === 2n ? v : (-1n - v);
      }
      return { tag: typeof length === 'bigint' ? length : Number(length), content };
    }
    case MAJ_SIMPLE: {
      if (additional === 20) return false;
      if (additional === 21) return true;
      if (additional === 22) return null;
      if (additional === 23) return undefined; // 0xf7
      if (additional === 24) {
        if (cursor.i >= bytes.length) throw new Error('CBOR truncated');
        return bytes[cursor.i++];
      }
      if (additional === 25) {
        if (cursor.i + 2 > bytes.length) throw new Error('CBOR truncated');
        // Half-precision IEEE-754, decoded manually (DataView.getFloat16 is
        // not available in every runtime). sign(1) exp(5) mantissa(10).
        const b16 = (bytes[cursor.i] << 8) | bytes[cursor.i + 1];
        cursor.i += 2;
        const sign = (b16 >>> 15) & 1;
        const exp = (b16 >>> 10) & 0x1f;
        const mant = b16 & 0x3ff;
        let v;
        if (exp === 0) v = mant * 2 ** -24;
        else if (exp === 31) v = mant ? NaN : (sign ? -Infinity : Infinity);
        else v = (1 + mant / 1024) * 2 ** (exp - 15);
        return sign ? -v : v;
      }
      if (additional === 26) {
        if (cursor.i + 4 > bytes.length) throw new Error('CBOR truncated');
        const v = new DataView(bytes.buffer, bytes.byteOffset + cursor.i, 4).getFloat32(0, false);
        cursor.i += 4;
        return v;
      }
      if (additional === 27) {
        if (cursor.i + 8 > bytes.length) throw new Error('CBOR truncated');
        const v = new DataView(bytes.buffer, bytes.byteOffset + cursor.i, 8).getFloat64(0, false);
        cursor.i += 8;
        return v;
      }
      throw new Error('Unsupported CBOR simple value: ' + additional);
    }
    default:
      throw new Error('Invalid CBOR major type: ' + major);
  }
}
