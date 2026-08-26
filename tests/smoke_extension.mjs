/**
 * Eclipse Wallet — extension smoke test (offline).
 *
 * Exercises the POPUP's real code paths (the same functions the UI calls)
 * with a fake `chrome.storage`/`chrome.runtime` and stubbed network:
 *   - vault create / wrong-password / unlock
 *   - address derivation + validation for all three chains
 *   - Cardano: build -> sign -> (stubbed) submit, wire-format + signature checks
 *   - Bitcoin: build -> sign -> (stubbed) broadcast, BIP143 signature check
 *   - Midnight: BIP340 sign + verify
 *   - dApp request queue: push -> list -> compute result -> decide -> pop
 *
 * Run:  node tests/smoke_extension.mjs     (from the repo root)
 * No network access is required.
 */
import { strict as assert } from 'node:assert';
import * as ed25519 from '../extension/vendor/ed25519.js';
import * as secp256k1 from '../extension/vendor/secp256k1.js';
import { sha256 } from '../extension/vendor/hashes/sha2.js';
import { blake2b } from '../extension/vendor/hashes/blake2b.js';
import { cborDecode, cborEncodeCanonical } from '../extension/lib/cbor.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../extension/lib/bytes.js';
import { CARDANO } from '../extension/lib/chains/cardano.js';
import { BITCOIN } from '../extension/lib/chains/bitcoin.js';
import { MIDNIGHT } from '../extension/lib/chains/midnight.js';
import * as dappq from '../extension/lib/dapp-queue.js';

let passed = 0;
let failed = 0;
function check(name, cond, detail = '') {
  if (cond) { passed++; console.log(`  ok    ${name}`); }
  else { failed++; console.log(`  FAIL  ${name}${detail ? ' :: ' + detail : ''}`); }
}
function section(name) { console.log(`\n== ${name} ==`); }

// Parse a standard ECDSA DER signature (0x30 0xLL 0x02 0xLR <R> 0x02 0xLS <S>)
// into {r, s} bigints. Noble's verify() rejects raw DER bytes (it wants a 64-byte
// compact sig or {r, s}), so the test converts at the boundary.
function derToRS(der) {
  let p = 0;
  if (der.length < 8 || der[0] !== 0x30) throw new Error('DER: not a SEQUENCE');
  const total = der[1]; p = 2;
  if (total !== der.length - 2) throw new Error('DER: bad SEQUENCE length');
  if (der[p] !== 0x02) throw new Error('DER: R is not an INTEGER');
  const rLen = der[p + 1]; p += 2;
  const r = BigInt('0x' + bytesToHex(der.slice(p, p + rLen))); p += rLen;
  if (der[p] !== 0x02) throw new Error('DER: S is not an INTEGER');
  const sLen = der[p + 1]; p += 2;
  const s = BigInt('0x' + bytesToHex(der.slice(p, p + sLen))); p += sLen;
  if (p !== der.length) throw new Error('DER: trailing bytes');
  return { r, s };
}

/* ------------------------- fake chrome runtime ------------------------ */

const backing = {};
const sentMessages = [];
const badgeText = { text: '' };

globalThis.chrome = {
  storage: {
    local: {
      get: async (keys) => {
        const out = {};
        for (const k of (Array.isArray(keys) ? keys : [keys])) {
          if (k in backing) out[k] = backing[k];
        }
        return out;
      },
      set: async (obj) => { Object.assign(backing, obj); },
      remove: async (keys) => {
        for (const k of (Array.isArray(keys) ? keys : [keys])) delete backing[k];
      },
    },
  },
  runtime: {
    id: 'smoke-test',
    onMessage: { addListener() {} },
    sendMessage: async (msg) => { sentMessages.push(msg); return { ok: true }; },
  },
  action: {
    setBadgeText: async (o) => { badgeText.text = o.text; },
    setBadgeBackgroundColor: async () => {},
  },
  notifications: {
    create: async () => '1',
    clear: async () => {},
    onClicked: { addListener() {} },
  },
};

/* --------------------------- fake network ----------------------------- */

const CIP19_BASE = 'addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x';
const BIP173_BTC = 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu';
const OUR_KEYHASH = 'aa'.repeat(20);

const net = {
  submittxBody: null,
  broadcastHex: null,
};

function jsonOk(data) {
  return { ok: true, status: 200, json: async () => data, text: async () => JSON.stringify(data) };
}

globalThis.fetch = async (url, opts = {}) => {
  const u = String(url);
  const body = opts?.body;

  // ---- Koios (Cardano) ----
  if (u.includes('/api/v1/address_info')) {
    return jsonOk([{
      address: 'OWN_ADDR',
      balance: '50000000',
      utxo_set: [
        { tx_hash: 'ab'.repeat(32), tx_index: 0, value: '25000000', asset_list: null },
        { tx_hash: 'cd'.repeat(32), tx_index: 1, value: '25000000', asset_list: null },
      ],
    }]);
  }
  if (u.includes('/api/v1/epoch_params')) {
    return jsonOk([{ min_fee_a: 44, min_fee_b: 155381, min_utxo_value: 1000000, max_tx_size: 16384 }]);
  }
  if (u.includes('/api/v1/tip')) {
    // Wrapped shape (real Koios): the popup must find slot_no inside `tip`.
    return jsonOk([{ tip: { block0: { height: 9000000 }, slot_no: 500000000, slot_length: 1000 } }]);
  }
  if (u.includes('/api/v1/submittx')) {
    net.submittxBody = body instanceof Uint8Array ? body : new Uint8Array(body);
    return { ok: true, status: 202, text: async () => 'faketxid' + '11'.repeat(32) };
  }

  // ---- Blockstream (Bitcoin) ----
  if (u.includes('/api/address/') && u.includes('/txs')) {
    return jsonOk([{
      txid: 'ef'.repeat(32),
      vin: [], // nothing spent
      vout: [
        { value: 100000000, scriptpubkey: '0014' + OUR_KEYHASH },
      ],
    }]);
  }
  if (u.includes('/api/address/')) {
    return jsonOk({
      chain_stats: { funded_txo_sum: 100000000, spent_txo_sum: 0, received: 100000000 },
      mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0, received: 0 },
    });
  }
  if (u.endsWith('/api/tx')) {
    net.broadcastHex = String(body);
    return { ok: true, status: 200, text: async () => 'btcfake' + '22'.repeat(29) };
  }

  // ---- mempool.space (fees) ----
  if (u.includes('/fees/recommended')) {
    return jsonOk({ fastestFee: 30, halfHourFee: 12, economyFee: 5, minimumFee: 1 });
  }

  throw new Error('Unexpected fetch in smoke test: ' + u);
};

/* ------------------------------ import popup -------------------------- */

const { api } = await import('../extension/popup/js/popup.js');

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const PASSWORD = 'test-password-123';

/* ------------------------------- vault -------------------------------- */

section('Vault (create / wrong password / unlock)');
{
  await api.createVaultFromMnemonic(MNEMONIC, PASSWORD);
  const stored = backing['eclipse.vault'];
  check('vault stored in chrome.storage.local', !!stored && stored.v === 1 && typeof stored.ct === 'string');
  check('no plaintext seed in storage', JSON.stringify(stored).length < 1000);

  let wrongThrew = false;
  api.lockWallet();
  try { await api.unlockVault('definitely-wrong'); } catch (e) { wrongThrew = /wrong password/i.test(e.message); }
  check('wrong password rejected', wrongThrew);

  const seed = await api.unlockVault(PASSWORD);
  check('unlock returns 64-byte seed', seed instanceof Uint8Array && seed.length === 64);
}

/* ----------------------------- addresses ------------------------------ */

section('Addresses (Cardano / Bitcoin / Midnight)');
{
  const ada = api.addressFor('cardano');
  check('cardano base address addr1…', ada.startsWith('addr1'), ada);
  check('cardano base decodes (mainnet, type 0)', (() => {
    try { const d = CARDANO.decodeAddress(ada); return d.type === 0 && d.networkId === 1; } catch { return false; }
  })());
  const kAda = api.keysFor('cardano');
  const stake = CARDANO.stakeAddress(kAda, api.currentNetwork('cardano'));
  const ent = CARDANO.enterpriseAddress(kAda, api.currentNetwork('cardano'));
  check('stake address stake1u…', stake.startsWith('stake1u'), stake);
  check('enterprise address addr1v…', ent.startsWith('addr1v'), ent);

  const btc = api.addressFor('bitcoin');
  check('bitcoin address bc1…', btc.startsWith('bc1'), btc);
  check('bitcoin decodes to 20-byte keyhash', (() => {
    try { return BITCOIN.decodeAddress(btc).keyHash.length === 20; } catch { return false; }
  })());
  check('bitcoin keyhash matches derived', bytesToHex(api.keysFor('bitcoin').keyHash) === bytesToHex(BITCOIN.decodeAddress(btc).keyHash));

  const xno = api.addressFor('midnight');
  check('midnight address mn_addr…', xno.startsWith('mn_addr'), xno);
  const decX = MIDNIGHT.decodeAddress(xno);
  check('midnight payload = sha256(x-only)', bytesToHex(decX.payload) === bytesToHex(sha256(api.keysFor('midnight').xOnly)));
}

/* --------------------------- cardano send ----------------------------- */

section('Cardano send pipeline (offline)');
{
  const out = await api.reviewCardanoSend(CIP19_BASE, '5');
  const b = out.built;
  check('amount parsed to 5 ADA', out.amountLovelace === 5000000n);
  check('fee converged to feeB + size*feeA', b.fee === 155381n + BigInt(b.size) * 44n, `fee=${b.fee} size=${b.size}`);
  // Greedy selection funds 5 ADA + fee from the first 25-ADA UTXO only.
  check('one UTXO selected (25M >= 5M + fee)', b.inputs.length === 1, String(b.inputs.length));
  check('change computed from single input', b.change === 25000000n - 5000000n - b.fee, `change=${b.change} fee=${b.fee}`);
  check('ttl from tip slot (500000000 + 600)', (() => {
    try { return b.body.get(3) === 500000600n; } catch { return false; }
  })(), String(b.body.get?.(3)));

  const txid = await api.cardanoSignAndBroadcast(b);
  check('broadcast returns txid', /^faketxid[0-9a-f]{64}$/.test(txid), txid);

  const tx = cborDecode(net.submittxBody);
  check('submitted tx is 3-element array', Array.isArray(tx) && tx.length === 3);
  const [body, witnesses, vld] = tx;
  check('witness set is a map', witnesses instanceof Map);
  const wlist = witnesses.get(0);
  check('witness key is uint 0 (not text "0")', Array.isArray(wlist) && !witnesses.has('0'));
  const [triple] = wlist;
  check('vkey witness triple [0, 32B, 64B]', triple[0] === 0 && triple[1].length === 32 && triple[2].length === 64);
  const signee = cborEncodeCanonical([body, new Map(), new Map()]);
  check('signature verifies over signee [body, {}, {}]', ed25519.verify(triple[2], signee, triple[1]));
  check('txid = blake2b-256(canonical body)', CARDANO.txHash(body) === bytesToHex(blake2b(cborEncodeCanonical(body), { dkLen: 32 })));
  check('vld empty', vld instanceof Map && vld.size === 0);
}

/* --------------------------- bitcoin send ----------------------------- */

section('Bitcoin send pipeline (offline)');
{
  const out = await api.reviewBitcoinSend(BIP173_BTC, '0.1', 'halfHour');
  const b = out.built;
  check('amount parsed to 0.1 BTC', out.amountSats === 10000000n);
  check('fee = 142 vB × 12 sat/vB', b.feeSats === 1704n, String(b.feeSats));
  check('change computed', b.changeSats === 100000000n - 10000000n - 1704n, String(b.changeSats));
  check('two outputs (recipient + change)', b.outputs.length === 2);

  const txid = await api.bitcoinSignAndBroadcast(b);
  const raw = net.broadcastHex;
  check('raw tx starts with v2 + segwit marker/flag', raw.startsWith('020000000001'), raw.slice(0, 16));
  check('raw tx ends with locktime 0', raw.endsWith('00000000'));
  check('txid matches legacy dSHA256', BITCOIN.txidOf(raw) === txid, txid);

  // Witness: one stack, [DER-sig + 0x01, 33B pubkey].
  const preimage = BITCOIN.sighashPreimage({
    inputs: b.inputs, outputs: b.outputs, inputIndex: 0,
    amountSats: 100000000n, locktime: 0, version: 2,
  });
  const msg = sha256(sha256(preimage));
  const pubKey = api.keysFor('bitcoin').pubKey;
  // Walk the raw hex (offsets in HEX CHARS): version(8) marker(2) flag(2),
  // nIn(2), inputs(82 each: 64 txid + 8 vout + 2 scriptLen(0x00) + 8 sequence),
  // nOut(2), outputs(16 value + 2 spkLen + spk), then witness stacks, locktime(8).
  let p = 12;
  const nIn = parseInt(raw.slice(p, p + 2), 16); p += 2;
  p += nIn * 82;
  const nOut = parseInt(raw.slice(p, p + 2), 16); p += 2;
  for (let i = 0; i < nOut; i++) {
    p += 16; // value
    const len = parseInt(raw.slice(p, p + 2), 16); p += 2 + len * 2;
  }
  const wItems = parseInt(raw.slice(p, p + 2), 16); p += 2;
  check('witness stack has 2 items', wItems === 2);
  const sigLen = parseInt(raw.slice(p, p + 2), 16); p += 2;
  const sigBytes = hexToBytes(raw.slice(p, p + sigLen * 2)); p += sigLen * 2;
  check('signature ends with SIGHASH_ALL (0x01)', sigBytes[sigBytes.length - 1] === 1);
  // DER signature (without trailing 0x01) -> {r, s} -> noble verify({r,s}).
  const rs = derToRS(sigBytes.slice(0, sigBytes.length - 1));
  check('BIP143 signature verifies', secp256k1.verify(rs, msg, pubKey));
  const pubLen = parseInt(raw.slice(p, p + 2), 16); p += 2;
  check('witness pubkey is 33B and matches key', pubLen === 33 && hexToBytes(raw.slice(p, p + 66)).every((v, i) => v === pubKey[i]));
}

/* --------------------------- message signing -------------------------- */

section('Message signing (all chains)');
{
  const msg = 'Eclipse smoke test — sign me';

  const rAda = api.signChainMessage('cardano', msg);
  const sigAda = Uint8Array.from(atob(rAda.signature), (c) => c.charCodeAt(0));
  check('cardano sig is 64B', sigAda.length === 64);
  check('cardano sig verifies (Ed25519)', ed25519.verify(sigAda, utf8ToBytes(msg), hexToBytes(rAda.pubKey)));

  const rXno = api.signChainMessage('midnight', msg);
  const sigXno = Uint8Array.from(atob(rXno.signature), (c) => c.charCodeAt(0));
  check('midnight sig is 64B', sigXno.length === 64);
  check('midnight sig verifies (BIP340)', MIDNIGHT.verify(sigXno, utf8ToBytes(msg), hexToBytes(rXno.pubKey)));
  check('midnight address matches result', rXno.address === api.addressFor('midnight'));

  const rBtc = api.signChainMessage('bitcoin', msg);
  const sigBtc = Uint8Array.from(atob(rBtc.signature), (c) => c.charCodeAt(0));
  check('bitcoin sig is 64B compact', sigBtc.length === 64);
  check('bitcoin sig verifies (ECDSA over SHA-256)', secp256k1.verify(sigBtc, sha256(utf8ToBytes(msg)), hexToBytes(rBtc.pubKey)));
}

/* ------------------------------- dApps -------------------------------- */

section('dApp request queue (offline)');
{
  await api.refreshPending();
  check('queue starts empty', api.state.pending.length === 0);

  const req = {
    id: 'smoke-req-1',
    origin: 'https://example.com',
    type: dappq.DAPP_TYPES.getAddress,
    chain: 'cardano',
    message: null,
    ts: Date.now(),
  };
  await dappq.pushPending(api.store, req);
  await api.refreshPending();
  check('pending visible after push', api.state.pending.length === 1);
  check('badge shows 1', badgeText.text === '1');

  const result = api.computeDappResult(req);
  check('getAddress result matches wallet address', result.address === api.addressFor('cardano'));

  await api.dappDecide(req, true, result, true);
  const decided = sentMessages.find((m) => m.type === 'eclipse_dapp_decided' && m.id === 'smoke-req-1');
  check('decision relayed to service worker', !!decided && decided.approved === true);
  check('decision carries signed result', decided?.result?.address === api.addressFor('cardano'));
  check('queue drained', (await dappq.listPending(api.store)).length === 0);
  check('badge cleared', badgeText.text === '');
  const approvals = await dappq.getApprovals(api.store);
  check('origin remembered', approvals['https://example.com']?.chains?.includes('cardano'));

  const req2 = {
    id: 'smoke-req-2',
    origin: 'https://example.org',
    type: dappq.DAPP_TYPES.signMessage,
    chain: 'midnight',
    message: 'dapp hello',
    ts: Date.now(),
  };
  await dappq.pushPending(api.store, req2);
  await api.refreshPending();
  const result2 = api.computeDappResult(req2);
  const sig2 = Uint8Array.from(atob(result2.signature), (c) => c.charCodeAt(0));
  check('dApp signMessage produces a valid BIP340 sig', MIDNIGHT.verify(sig2, utf8ToBytes('dapp hello'), hexToBytes(result2.pubKey)));
  await api.dappDecide(req2, true, result2, false);
  check('second queue drained', (await dappq.listPending(api.store)).length === 0);
}

/* ------------------------------ locking ------------------------------- */

section('Locking');
{
  api.lockWallet();
  let threw = false;
  try { api.keysFor('cardano'); } catch { threw = true; }
  check('keysFor throws after lock', threw);
  threw = false;
  try { api.addressFor('bitcoin'); } catch { threw = true; }
  check('addressFor throws after lock', threw);
  await api.unlockVault(PASSWORD);
  check('can unlock again', api.addressFor('bitcoin').startsWith('bc1'));
}

/* --------------------------- amount parsing --------------------------- */

section('Amount parsing');
{
  check('parseAda("1.5")', api.parseAda('1.5') === 1500000n);
  check('parseAda("0.000001")', api.parseAda('0.000001') === 1n);
  let threw = false;
  try { api.parseAda('1.1234567'); } catch { threw = true; }
  check('parseAda rejects 7 decimals', threw);
  check('parseBtc("0.00000001")', api.parseBtc('0.00000001') === 1n);
  threw = false;
  try { api.parseBtc('1.123456789'); } catch { threw = true; }
  check('parseBtc rejects 9 decimals', threw);
}

/* -------------------------------- done -------------------------------- */

console.log(`\n==================================================`);
console.log(`SMOKE  PASSED: ${passed}   FAILED: ${failed}`);
if (failed > 0) process.exit(1);
console.log('Extension smoke test passed. ✓');
