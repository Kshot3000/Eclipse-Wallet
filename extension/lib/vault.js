/**
 * Eclipse Wallet — encrypted vault.
 * Seed material is encrypted with AES-256-GCM; the key is derived from the
 * user's password with scrypt (N=2^14, r=8, p=1). Never stored in plaintext.
 */
import { scrypt } from '../vendor/hashes/scrypt.js';
import { utf8ToBytes } from './bytes.js';
import { randomBytes } from './bip39.js';

const AAD = new TextEncoder().encode('eclipse-vault-v1');
export const KDF_PARAMS = { N: 1 << 14, r: 8, p: 1, dkLen: 32 };
const FORMAT = 1;

function getSubtle() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) throw new Error('WebCrypto is not available');
  return c.subtle;
}

/** Derive an AES-GCM key from password + salt (blocks ~1s; show progress in UI). */
export async function deriveAesKey(password, salt) {
  const keyBytes = scrypt(utf8ToBytes(password), salt, KDF_PARAMS);
  return getSubtle().importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/**
 * Encrypt a plaintext payload (e.g. the 64-byte seed).
 * @returns {{v:number, kdf:object, salt:Uint8Array, iv:Uint8Array, ct:Uint8Array}}
 */
export async function vaultEncrypt(plaintext, password) {
  if (!(plaintext instanceof Uint8Array)) throw new Error('plaintext must be Uint8Array');
  if (typeof password !== 'string' || password.length < 1) throw new Error('Password required');
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveAesKey(password, salt);
  const ct = await getSubtle().encrypt({ name: 'AES-GCM', iv, additionalData: AAD }, key, plaintext);
  return {
    v: FORMAT,
    kdf: { ...KDF_PARAMS },
    salt,
    iv,
    ct: new Uint8Array(ct),
  };
}

/** Decrypt a vault blob. Throws on wrong password / tampering. */
export async function vaultDecrypt(blob, password) {
  if (!blob || blob.v !== FORMAT) throw new Error('Unsupported vault format');
  const key = await deriveAesKey(password, blob.salt);
  let pt;
  try {
    pt = await getSubtle().decrypt(
      { name: 'AES-GCM', iv: blob.iv, additionalData: AAD },
      key,
      blob.ct
    );
  } catch {
    throw new Error('Wrong password');
  }
  return new Uint8Array(pt);
}

/** Convert a vault blob to/from JSON-safe (base64) storage format. */
export function vaultToStorage(blob) {
  const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
  const raw = blob.iv && typeof blob.iv !== 'string' ? blob : blob;
  return {
    v: raw.v,
    kdf: raw.kdf,
    salt: b64(raw.salt),
    iv: b64(raw.iv),
    ct: b64(raw.ct),
  };
}

export function vaultFromStorage(stored) {
  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  return {
    v: stored.v,
    kdf: stored.kdf,
    salt: fromB64(stored.salt),
    iv: fromB64(stored.iv),
    ct: fromB64(stored.ct),
  };
}
