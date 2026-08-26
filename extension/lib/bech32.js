/**
 * Eclipse Wallet — bech32 / bech32m (BIP-173) implementation.
 * Supports both bech32 (Cardano, Bitcoin) and bech32m (Midnight).
 */

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
export const BECH32_CONST = 1;
export const BECH32M_CONST = 0x2bc830a3;

function polymod(values) {
  let chk = 1;
  for (let i = 0; i < values.length; i++) {
    const b = values[i];
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ b;
    for (let j = 0; j < 5; j++) {
      if (((top >>> j) & 1) !== 0) chk ^= GENERATOR[j];
    }
  }
  return chk >>> 0;
}

function hrpExpand(hrp) {
  const ret = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

function createChecksum(hrp, data, spec) {
  const values = hrpExpand(hrp).concat(data);
  const p = [0, 0, 0, 0, 0, 0];
  const combined = values.concat(p);
  const mod = polymod(combined) ^ spec;
  const out = [];
  for (let i = 0; i < 6; i++) out.push((mod >>> (5 * (5 - i))) & 31);
  return out;
}

/**
 * Encode 5-bit words with hrp.
 * @param {string} hrp
 * @param {number[]|Uint8Array} data 5-bit words
 * @param {number} spec BECH32_CONST or BECH32M_CONST
 */
export function encode(hrp, data, spec = BECH32M_CONST) {
  if (typeof hrp !== 'string' || hrp.length < 1) throw new Error('Invalid HRP: ' + hrp);
  const lowered = hrp.toLowerCase();
  for (let i = 0; i < hrp.length; i++) {
    const c = hrp.charCodeAt(i);
    if (c < 33 || c > 126) throw new Error('Invalid HRP character');
    if (c >= 65 && c <= 90) throw new Error('HRP must be lowercase');
  }
  const checksum = createChecksum(lowered, data, spec);
  const combined = Array.from(data).concat(checksum);
  let out = lowered + '1';
  for (const d of combined) out += CHARSET[d];
  return out;
}

/**
 * Decode a bech32/bech32m string.
 * @returns {{hrp: string, data: Uint8Array}} data = 5-bit words (without checksum)
 */
export function decode(bechString, spec = BECH32M_CONST) {
  if (typeof bechString !== 'string') throw new Error('Not a string');
  const hasLower = bechString.toLowerCase() !== bechString;
  const hasUpper = bechString.toUpperCase() !== bechString;
  if (hasLower && hasUpper) throw new Error('Mixed-case bech32 string');
  bechString = bechString.toLowerCase();
  const pos = bechString.lastIndexOf('1');
  if (pos < 1 || pos + 7 > bechString.length) throw new Error('Invalid bech32 string (separator)');
  const hrp = bechString.slice(0, pos);
  for (let i = 0; i < hrp.length; i++) {
    const c = hrp.charCodeAt(i);
    if (c < 33 || c > 126) throw new Error('Invalid HRP character');
  }
  let data = [];
  for (let i = pos + 1; i < bechString.length; i++) {
    const idx = CHARSET.indexOf(bechString[i]);
    if (idx === -1) throw new Error('Invalid bech32 character: ' + bechString[i]);
    data.push(idx);
  }
  if (polymod(hrpExpand(hrp).concat(data)) !== spec) {
    throw new Error(spec === BECH32M_CONST ? 'Invalid bech32m checksum' : 'Invalid bech32 checksum');
  }
  data = data.slice(0, data.length - 6);
  return { hrp, data: Uint8Array.from(data) };
}

/**
 * Regroup a byte/word array from `from`-bit groups to `to`-bit groups.
 * @returns {number[]} output words
 */
export function convertBits(input, from, to, pad = true) {
  let acc = 0;
  let bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  for (let i = 0; i < input.length; i++) {
    const value = input[i];
    if (value < 0 || value >> from !== 0) throw new Error('Invalid range for convertBits');
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >>> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv) !== 0) {
    throw new Error('Invalid padding in convertBits');
  }
  return out;
}

/** Encode 8-bit bytes (e.g. an address) with bech32/bech32m. */
export function encodeBytes(hrp, bytes, spec = BECH32M_CONST) {
  return encode(hrp, convertBits(bytes, 8, 5, true), spec);
}

/** Decode a bech32/bech32m byte-encoded string back to 8-bit bytes. */
export function decodeBytes(bechString, spec = BECH32M_CONST) {
  const { hrp, data } = decode(bechString, spec);
  return { hrp, bytes: new Uint8Array(convertBits(data, 5, 8, false)) };
}
