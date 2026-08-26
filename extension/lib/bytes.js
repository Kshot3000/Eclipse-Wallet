/**
 * Eclipse Wallet — byte-level utilities.
 * Pure ESM, no dependencies.
 */

export function hexToBytes(hex) {
  if (typeof hex !== 'string') throw new Error('hex must be a string');
  let h = hex.trim();
  if (h.startsWith('0x') || h.startsWith('0X')) h = h.slice(2);
  if (h.length % 2 !== 0) throw new Error('Invalid hex length: ' + h.length);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(h.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte) || byte > 255) throw new Error('Invalid hex at offset ' + i * 2);
    out[i] = byte;
  }
  return out;
}

export function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

export function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function utf8ToBytes(str) {
  return new TextEncoder().encode(str);
}

export function bytesToUtf8(bytes) {
  return new TextDecoder('utf-8').decode(bytes);
}

/** Big-endian 16-bit. */
export function be16(n) {
  const b = new Uint8Array(2);
  b[0] = (n >>> 8) & 0xff;
  b[1] = n & 0xff;
  return b;
}

/** Big-endian 32-bit (unsigned 32-bit number). */
export function be32(n) {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}

/** Big-endian 64-bit from a Number or BigInt (0..2^64-1). */
export function be64(n) {
  let big = typeof n === 'bigint' ? n : BigInt(n);
  const b = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    b[i] = Number(big & 0xffn);
    big >>= 8n;
  }
  return b;
}

/** Little-endian 32-bit (Bitcoin wire format). */
export function le32(n) {
  const b = new Uint8Array(4);
  b[0] = n & 0xff;
  b[1] = (n >>> 8) & 0xff;
  b[2] = (n >>> 16) & 0xff;
  b[3] = (n >>> 24) & 0xff;
  return b;
}

/** Little-endian 64-bit from a Number or BigInt (0..2^64-1). */
export function le64(n) {
  let big = typeof n === 'bigint' ? n : BigInt(n);
  const b = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    b[i] = Number(big & 0xffn);
    big >>= 8n;
  }
  return b;
}

export function be32ToNum(bytes, offset = 0) {
  return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

export function be64ToBig(bytes, offset = 0) {
  let out = 0n;
  for (let i = 0; i < 8; i++) out = (out << 8n) | BigInt(bytes[offset + i]);
  return out;
}

/** Bitcoin compact-size varint (1, 3, 5 or 9 bytes). */
export function bitcoinVarInt(n) {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) {
    const b = new Uint8Array(3);
    b[0] = 0xfd;
    b[1] = (n >>> 8) & 0xff;
    b[2] = n & 0xff;
    return b;
  }
  const b = new Uint8Array(5);
  b[0] = 0xfe;
  b[1] = (n >>> 24) & 0xff;
  b[2] = (n >>> 16) & 0xff;
  b[3] = (n >>> 8) & 0xff;
  b[4] = n & 0xff;
  return b;
}

/** Reverse a copy of a byte array. */
export function reverseBytes(bytes) {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[bytes.length - 1 - i];
  return out;
}
