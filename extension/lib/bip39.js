/**
 * Eclipse Wallet — BIP39 mnemonic ↔ seed.
 * PBKDF2-HMAC-SHA512, 2048 iterations, "mnemonic" + passphrase.
 */
import { pbkdf2 } from '../vendor/hashes/pbkdf2.js';
import { sha256 } from '../vendor/hashes/sha2.js';
import { sha512 } from '../vendor/hashes/sha512.js';
import { utf8ToBytes } from './bytes.js';
import { WORDLIST, WORD_SET } from './bip39-wordlist.js';

export function randomBytes(n) {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

/** Generate a mnemonic from random entropy. strength = 128 (12w), 192 (18w) or 256 (24w). */
export function generateMnemonic(strength = 256) {
  if (![128, 192, 256].includes(strength)) throw new Error('Invalid strength');
  return entropyToMnemonic(randomBytes(strength / 8));
}

/** Convert entropy bytes to a mnemonic (checksum included). */
export function entropyToMnemonic(entropy) {
  if (!(entropy instanceof Uint8Array)) throw new Error('entropy must be Uint8Array');
  if (entropy.length < 16 || entropy.length > 64 || entropy.length % 8 !== 0) {
    throw new Error('entropy length must be 16..64 bytes, multiple of 8');
  }
  const hash = sha256(entropy);
  const csBits = entropy.length * 8 / 32;
  // Build the bit string: entropy bits + first csBits of the checksum.
  let bits = '';
  for (let i = 0; i < entropy.length; i++) bits += entropy[i].toString(2).padStart(8, '0');
  for (let i = 0; i < csBits; i++) {
    const bit = (hash[i >> 3] >> (7 - (i & 7))) & 1;
    bits += String(bit);
  }
  const words = [];
  for (let i = 0; i < bits.length; i += 11) {
    words.push(WORDLIST[parseInt(bits.slice(i, i + 11), 2)]);
  }
  return words.join(' ');
}

/** Convert a valid mnemonic back to entropy bytes. */
export function mnemonicToEntropy(mnemonic) {
  const words = normalizeMnemonic(mnemonic);
  if (words.length % 3 !== 0 || words.length < 12) throw new Error('Invalid mnemonic length');
  let bits = '';
  for (const w of words) {
    const idx = WORDLIST.indexOf(w);
    if (idx === -1) throw new Error('Word not in BIP39 wordlist: ' + w);
    bits += idx.toString(2).padStart(11, '0');
  }
  const csBits = bits.length / 33;
  const entBits = bits.slice(0, bits.length - csBits);
  const entropy = new Uint8Array(Math.floor(entBits.length / 8));
  for (let i = 0; i < entropy.length; i++) {
    entropy[i] = parseInt(entBits.slice(i * 8, i * 8 + 8), 2);
  }
  return entropy;
}

/** Validate checksum + wordlist membership. */
export function validateMnemonic(mnemonic) {
  try {
    const entropy = mnemonicToEntropy(mnemonic);
    const hash = sha256(entropy);
    const csBits = entropy.length * 8 / 32;
    const bits = bitsOf(entropy) + '';
    // Recompute expected mnemonic and compare — simplest robust check.
    return entropyToMnemonic(entropy) === normalizeMnemonic(mnemonic).join(' ');
  } catch {
    return false;
  }
}

function bitsOf(entropy) {
  let bits = '';
  for (let i = 0; i < entropy.length; i++) bits += entropy[i].toString(2).padStart(8, '0');
  const hash = sha256(entropy);
  const csBits = entropy.length * 8 / 32;
  for (let i = 0; i < csBits; i++) bits += String((hash[i >> 3] >> (7 - (i & 7))) & 1);
  return bits;
}

/** Normalize user-typed seed input into an array of lowercase words. */
export function normalizeMnemonic(input) {
  if (typeof input === 'string') {
    return input.toLowerCase().split(/[\s,]+/).filter((w) => w.length > 0);
  }
  if (Array.isArray(input)) {
    return input.map((w) => String(w).toLowerCase()).filter((w) => w.length > 0);
  }
  throw new Error('Invalid mnemonic input');
}

export function mnemonicToSeed(mnemonic, passphrase = '') {
  const norm = normalizeMnemonic(mnemonic).join(' ');
  if (!validateMnemonic(norm)) throw new Error('Invalid mnemonic (checksum failed)');
  return pbkdf2(
    sha512,
    utf8ToBytes(norm.normalize('NFKD')),
    utf8ToBytes('mnemonic'.normalize('NFKD') + String(passphrase).normalize('NFKD')),
    { c: 2048, dkLen: 64 }
  );
}
