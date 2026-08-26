/**
 * Eclipse Wallet — Cardano chain.
 * - Keys: SLIP-0010 ed25519, BIP44 path m/44'/1815'/0'/0'/0
 * - Addresses (CIP-19): base (type 0) + enterprise (type 6) + stake (type 14), bech32
 *   - header = (type << 4) | networkTag, networkTag 0 = testnet, 1 = mainnet
 *   - stake credential hash = blake2b-224 (28 bytes) of the public key
 *   - stake/reward addresses use the HRP `stake` on every network
 *   - address = header + body only; bech32's own 6-char checksum is the only checksum
 * - Data: Koios (keyless, CORS-enabled community API)
 * - Transactions: Babbage/Conway CBOR, vkey witness, min-fee = 155381 + 44*size
 *   - signee = [body, empty witness set (a0), empty vld]
 *   - txid = blake2b-256(canonical CBOR of body)
 */
import { sha256 } from '../../vendor/hashes/sha2.js';
import { blake2b } from '../../vendor/hashes/blake2b.js';
import * as ed25519 from '../../vendor/ed25519.js';
import { deriveEd25519Path } from '../slip10.js';
import { encodeBytes, decodeBytes, BECH32_CONST } from '../bech32.js';
import { cborEncode, cborEncodeCanonical, cborDecode } from '../cbor.js';
import { concatBytes, hexToBytes, bytesToHex, utf8ToBytes } from '../bytes.js';

const KOIOS_BASE = 'https://api.koios.rest/api/v1';
const DEFAULT_FEE_A = 155381; // minFeeB (constant)
const DEFAULT_FEE_B = 44; // minFeeA (per byte)
export const MIN_UTXO_LOVELACE = 1000000n; // 1 ADA minimum for plain outputs

async function koios(endpoint, body, extraHeaders = {}) {
  const res = await fetch(KOIOS_BASE + endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Koios ${endpoint} failed (${res.status}): ${text.slice(0, 300)}`);
  }
  return res.json();
}

/** Stake credential hash: first 28 bytes of blake2b(pubkey) (blake2b-224). */
export function credentialFromPubKey(pubKey) {
  return blake2b(pubKey, { dkLen: 28 });
}

/**
 * Build a Cardano address byte string: header + body (CIP-19).
 * Real Cardano addresses carry no separate hash — bech32's 6-character
 * checksum (added by the encoder) is the only checksum.
 */
function buildAddressBytes(addrType, networkId, body) {
  const header = ((addrType & 0x0f) << 4) | (networkId & 0x0f);
  const bodyBytes = body instanceof Uint8Array ? body : new Uint8Array(0);
  const out = new Uint8Array(1 + bodyBytes.length);
  out[0] = header;
  out.set(bodyBytes, 1);
  return out;
}

function toHexBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (typeof value === 'string' && /^[0-9a-fA-F]+$/.test(value) && value.length % 2 === 0) return hexToBytes(value);
  throw new Error('Expected bytes or hex string');
}

/**
 * Accept a bech32 Cardano address string or raw address bytes and return
 * the full address bytes (header + body) used in outputs.
 */
function outputAddressBytes(address) {
  if (address instanceof Uint8Array) return address;
  const s = String(address).trim();
  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) return hexToBytes(s);
  const { hrp, bytes } = decodeBytes(s, BECH32_CONST);
  if (hrp !== 'addr' && hrp !== 'addr_test') throw new Error('Invalid Cardano address');
  return bytes;
}

export const CARDANO = {
  id: 'cardano',
  name: 'Cardano',
  symbol: 'ADA',
  decimals: 6,
  color: '#0033AD',
  // CIP-19 networkTag: 0 = testnet, 1 = mainnet.
  networks: {
    mainnet: { id: 'mainnet', hrp: 'addr', networkId: 1, label: 'Mainnet' },
    preview: { id: 'preview', hrp: 'addr_test', networkId: 0, label: 'Preview' },
    preprod: { id: 'preprod', hrp: 'addr_test', networkId: 0, label: 'Preprod' },
  },
  defaultNetwork: 'mainnet',

  /** Derive the account-0 key used for payment + stake (base addresses). */
  deriveKeys(seed) {
    const { privKey, pubKey } = deriveEd25519Path(seed, "m/44'/1815'/0'/0'/0");
    const credential = credentialFromPubKey(pubKey);
    return { privKey, pubKey, credential };
  },

  baseAddress(keys, network) {
    const body = concatBytes(keys.credential, keys.credential);
    return encodeBytes(network.hrp, buildAddressBytes(0, network.networkId, body), BECH32_CONST);
  },

  /** Enterprise address (type 6): payment key hash, no delegation. */
  enterpriseAddress(keys, network) {
    return encodeBytes(network.hrp, buildAddressBytes(6, network.networkId, keys.credential), BECH32_CONST);
  },

  /**
   * Stake (reward) address (type 14). Per CIP-19 the HRP is `stake`
   * on both mainnet and testnet.
   */
  stakeAddress(keys, network) {
    return encodeBytes('stake', buildAddressBytes(14, network.networkId, keys.credential), BECH32_CONST);
  },

  /** Decode an address string into {type, networkId, body} or throw. */
  decodeAddress(address) {
    let decoded;
    try {
      decoded = decodeBytes(String(address), BECH32_CONST);
    } catch (e) {
      throw new Error('Invalid Cardano address');
    }
    const { hrp, bytes } = decoded;
    if (hrp !== 'addr' && hrp !== 'addr_test' && hrp !== 'stake') throw new Error('Invalid Cardano address HRP');
    if (bytes.length < 29) throw new Error('Cardano address too short');
    const header = bytes[0];
    const type = (header >> 4) & 0x0f;
    const networkId = header & 0x0f;
    // CIP-19: networkTag 0 = testnet, 1 = mainnet. Stake addresses use the
    // HRP `stake` on every network, so no tag check applies to them.
    if (hrp === 'addr' && networkId !== 1) throw new Error('Network mismatch');
    if (hrp === 'addr_test' && networkId !== 0) throw new Error('Network mismatch');
    // Address = header + body; bech32's own checksum is the only checksum.
    return { type, networkId, body: bytes.slice(1) };
  },

  validateAddress(address) {
    try { this.decodeAddress(address); return true; } catch { return false; }
  },

  networkFromAddress(address) {
    try {
      const { networkId } = this.decodeAddress(address);
      return networkId === 1 ? 'mainnet' : 'preview';
    } catch {
      return null;
    }
  },

  async getUTXOs(address) {
    const result = await koios('/address_info', { _addresses: [address] });
    const info = Array.isArray(result) ? result[0] : result;
    if (!info || !info.address) throw new Error('Address not found on network');
    const utxos = (info.utxo_set || []).map((u) => ({
      txHash: u.tx_hash,
      index: u.tx_index,
      lovelace: BigInt(u.value),
      assetList: u.asset_list || null,
    }));
    return { address: info.address, lovelace: BigInt(info.balance || 0), utxos };
  },

  async getTip() {
    const result = await koios('/tip', {});
    return Array.isArray(result) ? result[0] : result;
  },

  async getFeeParams() {
    try {
      const result = await koios('/epoch_params', {});
      const p = Array.isArray(result) ? result[0] : result;
      return {
        feeA: Number(p.min_fee_a) || DEFAULT_FEE_B,
        feeB: Number(p.min_fee_b) || DEFAULT_FEE_A,
        minUtxo: BigInt(p.min_utxo_value || 0),
        maxTxSize: Number(p.max_tx_size) || 16384,
      };
    } catch {
      return { feeA: DEFAULT_FEE_B, feeB: DEFAULT_FEE_A, minUtxo: MIN_UTXO_LOVELACE, maxTxSize: 16384 };
    }
  },

  /**
   * Select UTXOs to fund an amount + fee. Greedy by size.
   */
  selectInputs(utxos, amountLovelace, feeEstimateLovelace, minUtxo = MIN_UTXO_LOVELACE) {
    const sorted = [...utxos].sort((a, b) => (b.lovelace > a.lovelace ? 1 : -1));
    const selected = [];
    let total = 0n;
    for (const u of sorted) {
      selected.push(u);
      total += u.lovelace;
      if (total >= amountLovelace + feeEstimateLovelace) break;
    }
    if (total < amountLovelace) throw new Error('Insufficient ADA balance');
    return { selected, total };
  },

  /**
   * Build an unsigned transaction body (Babbage/Conway) with converged min-fee.
   * @returns {{body: Map, inputs: object[], fee: bigint, change: bigint, ttl: bigint, size: number}}
   */
  buildSendTx({ utxos, toAddress, amountLovelace, changeAddress, ttl, feeParams }) {
    if (amountLovelace <= 0n) throw new Error('Amount must be positive');
    const toBytes = outputAddressBytes(toAddress);
    const changeBytes = changeAddress ? outputAddressBytes(changeAddress) : null;
    const feeA = feeParams?.feeA ?? DEFAULT_FEE_B;
    const feeB = feeParams?.feeB ?? DEFAULT_FEE_A;
    const minUtxo = feeParams?.minUtxo && feeParams.minUtxo > 0n ? feeParams.minUtxo : MIN_UTXO_LOVELACE;

    const estFee = BigInt(feeB) + BigInt(400) * BigInt(feeA);
    const { selected, total } = this.selectInputs(utxos, amountLovelace, estFee, minUtxo);

    // Converge: build body -> measure size -> fee = feeB + size*feeA -> repeat.
    let fee = estFee;
    let change = 0n;
    let body;
    let size;
    for (let i = 0; i < 8; i++) {
      change = total - amountLovelace - fee;
      if (change > 0n && change < minUtxo) change = 0n; // dust goes to recipient
      const outputs = new Map();
      outputs.set(0, [amountLovelace, toBytes]);
      if (change > 0n && changeBytes) outputs.set(1, [change, changeBytes]);
      body = new Map();
      body.set(0, selected.map((u) => [hexToBytes(u.txHash), u.index]));
      body.set(1, outputs);
      body.set(2, fee);
      // TTL is optional in the Cardano tx body; omit it when not provided.
      if (ttl != null) body.set(3, ttl);
      // Size estimate of the FINAL tx: the body plus the vkey witness set
      // signTx() will attach (one [type, 32-byte vkey, 64-byte signature]
      // triple). Fee must cover the size actually submitted, or the network
      // rejects the tx for under-minimum-fee.
      const witnessEstimate = new Map([[0, [[0, new Uint8Array(32), new Uint8Array(64)]]]]);
      size = cborEncodeCanonical([body, witnessEstimate, new Map()]).length;
      const newFee = BigInt(feeB) + BigInt(size) * BigInt(feeA);
      if (newFee === fee) break;
      fee = newFee;
    }
    if (total < amountLovelace + fee) throw new Error('Insufficient ADA balance (including fee)');
    return { body, inputs: selected, fee, change, ttl, size };
  },

  /**
   * Sign a built body with the account key (vkey witness) and produce the
   * full transaction CBOR.
   * The signee is the tx with an EMPTY witness set (CBOR a0), per the
   * Shelley/Alonzo/Conway spec and cardano-serialization-lib behavior.
   */
  signTx({ body, privKey, pubKey }) {
    const signee = cborEncodeCanonical([body, new Map(), new Map()]);
    const signature = ed25519.sign(signee, privKey);
    const vkeyWitness = [0, pubKey, signature];
    // Witness set: CBOR map with integer key 0 (vkey_witness) mapping to an
    // array of [type, vkey, signature] triples. A Map (not a plain object)
    // keeps the key a CBOR uint — a text key would be an invalid witness set.
    const witnesses = new Map([[0, [vkeyWitness]]]);
    const tx = [body, witnesses, new Map()];
    return cborEncodeCanonical(tx);
  },

  /** Transaction hash (txid): blake2b-256 of canonical CBOR of the body. */
  txHash(body) {
    return bytesToHex(blake2b(cborEncodeCanonical(body), { dkLen: 32 }));
  },

  /** Submit raw CBOR tx. Returns the txid (hex). */
  async submit(txBytes) {
    const res = await fetch(KOIOS_BASE + '/submittx', {
      method: 'POST',
      headers: { 'Content-Type': 'application/cbor' },
      body: txBytes,
    });
    if (res.status === 202) {
      return (await res.text()).trim();
    }
    const text = await res.text().catch(() => '');
    throw new Error(`Cardano submission failed (${res.status}): ${text.slice(0, 400)}`);
  },

  async getTxStatus(txid) {
    const result = await koios('/tx_status', { _tx_ids: [txid] });
    const row = Array.isArray(result) ? result[0] : result;
    if (!row) throw new Error('Unknown transaction');
    return row;
  },
};

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function formatAda(lovelace) {
  const units = typeof lovelace === 'bigint' ? lovelace : BigInt(lovelace);
  const neg = units < 0n;
  const abs = neg ? -units : units;
  const whole = abs / 1000000n;
  const frac = (abs % 1000000n).toString().padStart(6, '0').replace(/0+$/, '');
  return (neg ? '-' : '') + whole.toString() + (frac ? '.' + frac : '') + ' ADA';
}
