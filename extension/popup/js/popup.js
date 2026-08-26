/**
 * Eclipse Wallet — popup (extension page).
 *
 * Security model:
 *  - The encrypted vault (scrypt + AES-256-GCM) lives in chrome.storage.local.
 *  - The seed is decrypted into MEMORY ONLY and cleared on lock/close.
 *  - All key derivation and signing happens here, in the extension page.
 *    The background service worker and content scripts never see secrets.
 *
 * The module is written so it can also be imported in Node (smoke tests):
 * nothing touches `document` or `chrome` at import time, and the UI entry
 * point (`init`) runs only when a DOM is present.
 */
import {
  generateMnemonic, validateMnemonic, mnemonicToSeed, normalizeMnemonic,
} from '../../lib/bip39.js';
import { vaultEncrypt, vaultDecrypt, vaultToStorage, vaultFromStorage } from '../../lib/vault.js';
import { CARDANO, formatAda } from '../../lib/chains/cardano.js';
import { BITCOIN, formatBtc } from '../../lib/chains/bitcoin.js';
import { MIDNIGHT, formatXno } from '../../lib/chains/midnight.js';
import * as nocturne from '../../lib/nocturne.js';
import { utf8ToBytes, bytesToHex } from '../../lib/bytes.js';
import * as ed25519 from '../../vendor/ed25519.js';
import * as secp256k1 from '../../vendor/secp256k1.js';
import { sha256 } from '../../vendor/hashes/sha2.js';
import * as dappq from '../../lib/dapp-queue.js';

/* ------------------------------ constants ------------------------------ */

const VAULT_KEY = 'eclipse.vault';
const NETWORKS_KEY = 'eclipse.networks';
const DEFAULT_NETWORKS = { cardano: 'mainnet', midnight: 'mainnet', bitcoin: 'mainnet' };

const CHAIN = { cardano: CARDANO, bitcoin: BITCOIN, midnight: MIDNIGHT };
const CHAIN_META = {
  cardano: { symbol: 'ADA', color: 'var(--ada)', icon: '◈' },
  bitcoin: { symbol: 'BTC', color: 'var(--btc)', icon: '₿' },
  midnight: { symbol: 'NIGHT', color: 'var(--xno)', icon: '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2.8"/><rect x="10.65" y="6.65" width="2.7" height="2.7" fill="currentColor"/><rect x="10.65" y="10.65" width="2.7" height="2.7" fill="currentColor"/><rect x="10.65" y="14.65" width="2.7" height="2.7" fill="currentColor"/></svg>' },
};

/* ------------------------------ storage ------------------------------ */

const store = {
  get: (k) => chrome.storage.local.get(k),
  set: (o) => chrome.storage.local.set(o),
  remove: (k) => chrome.storage.local.remove(k),
};

/* ------------------------------- state -------------------------------- */

// In-memory ONLY. Never serialized, never written to storage.
let seedBytes = null;
const keysCache = new Map();

const state = {
  view: 'boot',          // boot | onboarding | create | createpw | import | unlock
                          // | wallet | send | signmsg | dapps | settings | txdone
  chain: 'cardano',      // active chain in wallet view
  networks: { ...DEFAULT_NETWORKS },
  f: {},                 // form field values (data-f bindings)
  formError: null,       // last form error, rendered by the active view
  busy: false,           // heavy async operation in flight
  mnemonic: null,        // current mnemonic (create flow); cleared after encryption
  balances: {},          // chain -> {loading} | {lovelace,utxos} | {sats,received} | {error}
  send: null,            // send-flow state (see review* functions)
  signChain: 'cardano',  // sign-message chain
  signResult: null,      // last signature result
  pending: [],           // dApp requests awaiting a decision
  approvals: {},         // origin -> {chains, ts}
  txDone: null,          // {chain, txid} for the success screen
  nc: null,              // Nocturne UI state (null until the tab is opened)
  ncLoadError: false,    // sealed store failed to open — offer reset
  modal: null,           // {kind:'password', title, body, okLabel, onOk} | {kind:'confirm', ...}
  modalError: null,
};

/* ------------------------------- utils ------------------------------- */

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function b64(bytes) {
  let s = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(s);
}

/** Let the browser paint a "working…" state before a blocking crypto call. */
async function paint() {
  if (typeof requestAnimationFrame === 'function') {
    await new Promise((r) => requestAnimationFrame(() => r(null)));
  }
  await new Promise((r) => setTimeout(r, 40));
}

function toast(msg, kind = 'ok') {
  if (typeof document === 'undefined') return;
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3600);
}

function updateBadge() {
  try {
    if (typeof chrome === 'undefined' || !chrome.action || !chrome.action.setBadgeText) return;
    const n = state.pending.length;
    chrome.action.setBadgeText({ text: n > 0 ? String(n) : '' });
    if (chrome.action.setBadgeBackgroundColor) {
      chrome.action.setBadgeBackgroundColor({ color: '#7c5cff' });
    }
  } catch { /* badge is cosmetic */ }
}

function errBox(msg = state.formError) {
  return msg ? `<div class="notice err">${esc(msg)}</div>` : '';
}

let logoSeq = 0;
function logoMark(size = 26) {
  logoSeq += 1;
  const id = `egl-${logoSeq}`;
  // Blue (Cardano) -> Orange (Bitcoin) eclipse on black (Midnight).
  return `<svg width="${size}" height="${size}" viewBox="0 0 48 48" fill="none" aria-hidden="true" style="flex:0 0 auto">
    <circle cx="24" cy="24" r="19.5" fill="none" stroke="url(#${id})" stroke-width="1.2" opacity="0.45"/>
    <circle cx="24" cy="24" r="13.5" fill="#05060a" stroke="#f7931a" stroke-width="2.6"/>
    <path d="M33 17.5a13.5 13.5 0 010 13" stroke="#fff" stroke-width="1.2" opacity="0.35" fill="none"/>
    <defs><linearGradient id="${id}" x1="0" y1="0" x2="48" y2="48">
      <stop stop-color="#3d6fe0"/><stop offset="1" stop-color="#f7931a"/>
    </linearGradient></defs>
  </svg>`;
}

/* --------------------------- vault + keys ---------------------------- */

async function createVaultFromMnemonic(mnemonic, password) {
  const words = normalizeMnemonic(mnemonic);
  if (!validateMnemonic(words.join(' '))) throw new Error('Invalid recovery phrase (checksum failed)');
  if (typeof password !== 'string' || password.length < 8) throw new Error('Password must be at least 8 characters');
  const seed = mnemonicToSeed(words.join(' '));
  const blob = await vaultEncrypt(seed, password);
  await store.set({ [VAULT_KEY]: vaultToStorage(blob) });
  seedBytes = seed;
  keysCache.clear();
  state.hasVault = true;
  return seed;
}

async function importWallet(password, password2) {
  if (typeof password !== 'string' || password.length < 8) throw new Error('Password must be at least 8 characters');
  if (password !== password2) throw new Error('Passwords do not match');
  const mnemonic = (state.f.mnemonic || '').trim();
  if (!mnemonic) throw new Error('Enter your recovery phrase');
  return createVaultFromMnemonic(mnemonic, password);
}

async function unlockVault(password) {
  const o = await store.get([VAULT_KEY]);
  const stored = o[VAULT_KEY];
  if (!stored) throw new Error('No wallet found on this device');
  const seed = await vaultDecrypt(vaultFromStorage(stored), String(password || ''));
  seedBytes = seed;
  keysCache.clear();
  state.hasVault = true;
  return seed;
}

function lockWallet() {
  seedBytes = null;
  keysCache.clear();
  state.balances = {};
  // Nocturne: drop the derived key + decrypted messenger state from memory;
  // the sealed store in storage is re-opened (re-derived) on next unlock.
  if (typeof ncKey !== 'undefined') { ncKey = null; ncStateObj = null; ncStopTicker(); }
}

function requireUnlocked() {
  if (!seedBytes) throw new Error('Wallet is locked — unlock first');
  return seedBytes;
}

function keysFor(chain) {
  requireUnlocked();
  if (!keysCache.has(chain)) {
    if (chain === 'cardano') keysCache.set(chain, CARDANO.deriveKeys(seedBytes));
    else if (chain === 'bitcoin') keysCache.set(chain, BITCOIN.deriveKeys(seedBytes));
    else if (chain === 'midnight') keysCache.set(chain, MIDNIGHT.deriveKeys(seedBytes));
    else throw new Error('Unknown chain: ' + chain);
  }
  return keysCache.get(chain);
}

function currentNetwork(chain) {
  const lib = CHAIN[chain];
  const id = state.networks[chain] || lib.defaultNetwork;
  return lib.networks[id] || lib.networks[lib.defaultNetwork];
}

/** Primary (send/receive) address for a chain under the selected network. */
function addressFor(chain) {
  const net = currentNetwork(chain);
  const k = keysFor(chain);
  if (chain === 'cardano') return CARDANO.baseAddress(k, net);
  if (chain === 'bitcoin') return BITCOIN.address(k, net);
  return MIDNIGHT.address(k.xOnly, net.networkId);
}

function explorerTxLink(chain, txid) {
  const net = currentNetwork(chain);
  if (chain === 'cardano') {
    const host = net.id === 'mainnet' ? 'cardanoscan.io' : `${net.id}.cardanoscan.io`;
    return `https://${host}/tx/${txid}`;
  }
  if (chain === 'bitcoin') {
    const host = net.id === 'mainnet' ? 'mempool.space' : 'mempool.space/testnet';
    return `https://${host}/tx/${txid}`;
  }
  return MIDNIGHT.explorerUrl(net.id, txid);
}

/* ------------------------------ balances ----------------------------- */

async function loadBalance(chain) {
  if (!seedBytes) return;
  state.balances[chain] = { loading: true };
  if (typeof render === 'function') render();
  try {
    if (chain === 'cardano') {
      const info = await CARDANO.getUTXOs(addressFor('cardano'));
      state.balances[chain] = {
        lovelace: info.lovelace, utxos: info.utxos.length, address: info.address,
      };
    } else if (chain === 'bitcoin') {
      const net = currentNetwork('bitcoin');
      const info = await BITCOIN.getBalance(addressFor('bitcoin'), net.id);
      state.balances[chain] = {
        sats: info.funded - info.spent, received: info.received,
      };
    } else {
      state.balances[chain] = { none: true };
    }
  } catch (e) {
    state.balances[chain] = { error: e.message };
  }
  if (typeof render === 'function') render();
}

/* --------------------------- amount parsing -------------------------- */

function parseAda(str) {
  const s = String(str).trim();
  if (!/^\d{1,15}(\.\d{1,6})?$/.test(s)) throw new Error('Enter a valid ADA amount (up to 6 decimals)');
  const [w, f = ''] = s.split('.');
  return BigInt(w) * 1000000n + BigInt(f.padEnd(6, '0'));
}

function parseBtc(str) {
  const s = String(str).trim();
  if (!/^\d{1,12}(\.\d{1,8})?$/.test(s)) throw new Error('Enter a valid BTC amount (up to 8 decimals)');
  const [w, f = ''] = s.split('.');
  return BigInt(w) * 100000000n + BigInt(f.padEnd(8, '0'));
}

function lovelaceToInput(lovelace) {
  if (lovelace <= 0n) return '0';
  const w = lovelace / 1000000n;
  const f = (lovelace % 1000000n).toString().padStart(6, '0').replace(/0+$/, '');
  return w.toString() + (f ? '.' + f : '');
}

function satsToInput(sats) {
  if (sats <= 0n) return '0';
  const w = sats / 100000000n;
  const f = (sats % 100000000n).toString().padStart(8, '0').replace(/0+$/, '');
  return w.toString() + (f ? '.' + f : '');
}

function maxAmountFor(chain) {
  const b = state.balances[chain];
  if (!b || b.loading) return null;
  if (chain === 'cardano' && typeof b.lovelace === 'bigint') {
    const feeEst = 155381n + 300n * 44n; // typical 1-in/2-out tx
    const m = b.lovelace - feeEst;
    return lovelaceToInput(m > 0n ? m : 0n);
  }
  if (chain === 'bitcoin' && typeof b.sats === 'bigint') {
    const feeEst = 145n * 1n; // 1-in/2-out ~145 vB at 1 sat/vB
    const m = b.sats - feeEst;
    return satsToInput(m > 0n ? m : 0n);
  }
  return null;
}

/* --------------------------- cardano send ---------------------------- */

function extractSlot(tip) {
  if (tip == null) return null;
  const cands = [
    tip.slot_no, tip.slot_number, tip.slot,
    tip.tip && tip.tip.slot_no,
    tip.block0 && tip.block0.slot_no,
  ];
  for (const c of cands) {
    if (c == null) continue;
    try { return BigInt(String(c).replace(/[^\d]/g, '')); } catch { /* next */ }
  }
  return null;
}

async function reviewCardanoSend(toAddress, amountStr) {
  const net = currentNetwork('cardano');
  const own = addressFor('cardano');
  const amount = parseAda(amountStr);

  const dec = CARDANO.decodeAddress(String(toAddress).trim());
  if (dec.type === 14) throw new Error('You can\'t send ADA to a stake (reward) address');
  if (dec.type === 3) throw new Error('Pointer addresses are not supported as recipients');
  if (dec.networkId !== net.networkId) {
    const where = dec.networkId === 1 ? 'Mainnet' : 'a testnet';
    throw new Error(`Recipient is on ${where}, but Eclipse is set to ${net.label}. Switch the network in Settings.`);
  }

  const [utxosInfo, feeParams, tip] = await Promise.all([
    CARDANO.getUTXOs(own),
    CARDANO.getFeeParams(),
    CARDANO.getTip().catch(() => null),
  ]);
  // TTL is optional per the Cardano spec; prefer a fresh slot, fall back to
  // an unsigned (no-TTL) body if the tip endpoint is unavailable.
  const slot = extractSlot(tip);
  const ttl = slot != null ? slot + 600n : null; // ~20 min of slots

  const built = CARDANO.buildSendTx({
    utxos: utxosInfo.utxos,
    toAddress: String(toAddress).trim(),
    amountLovelace: amount,
    changeAddress: own,
    ttl,
    feeParams,
  });
  return { chain: 'cardano', built, toAddress: String(toAddress).trim(), own, amountLovelace: amount };
}

async function cardanoSignAndBroadcast(built) {
  const k = keysFor('cardano');
  const tx = CARDANO.signTx({ body: built.body, privKey: k.privKey, pubKey: k.pubKey });
  const txid = await CARDANO.submit(tx);
  return String(txid).trim();
}

/* --------------------------- bitcoin send ---------------------------- */

async function reviewBitcoinSend(toAddress, amountStr, feeTier) {
  const net = currentNetwork('bitcoin');
  const own = addressFor('bitcoin');
  const amount = parseBtc(amountStr);

  const dec = BITCOIN.decodeAddress(String(toAddress).trim());
  const recipientMainnet = dec.networkId === 0;
  const onMainnet = net.id === 'mainnet';
  if (recipientMainnet !== onMainnet) {
    const where = recipientMainnet ? 'Mainnet' : 'Testnet';
    throw new Error(`Recipient is on ${where}, but Eclipse is set to ${net.label}. Switch the network in Settings.`);
  }

  const [utxos, fees] = await Promise.all([
    BITCOIN.getUtxos(own, net.id),
    BITCOIN.getFees(net.id).catch(() => ({ fastest: 25, halfHour: 10, economy: 4 })),
  ]);
  const tier = ['fastest', 'halfHour', 'economy'].includes(feeTier) ? feeTier : 'halfHour';
  const feeRate = Math.max(1, Math.ceil(Number(fees[tier]) || 1));

  const k = keysFor('bitcoin');
  const built = BITCOIN.buildSend({
    utxos,
    toKeyHash: dec.keyHash,
    amountSats: amount,
    feeRate,
    changeKeyHash: k.keyHash,
  });
  return { chain: 'bitcoin', built, toAddress: String(toAddress).trim(), own, fees, feeRate, tier, amountSats: amount };
}

async function bitcoinSignAndBroadcast(built) {
  const k = keysFor('bitcoin');
  const rawHex = BITCOIN.signAndSerialize({
    inputs: built.inputs, outputs: built.outputs,
    privKey: k.privKey, pubKey: k.pubKey,
  });
  const txid = BITCOIN.txidOf(rawHex);
  const net = currentNetwork('bitcoin');
  await BITCOIN.broadcast(rawHex, net.id);
  return txid;
}

/* --------------------------- midnight send ---------------------------- */

/**
 * NIGHT send (v1) — review step: build the canonical transfer record.
 * Unsigned here; the NightExternal private key is only touched at confirm.
 */
async function reviewMidnightSend(toAddress, amountStr, memo) {
  const net = currentNetwork('midnight');
  const addrStr = String(toAddress).trim();
  if (!MIDNIGHT.validateAddress(addrStr)) throw new Error('Not a valid Midnight address (mn_addr… or mn_addr_…)');
  const dec = MIDNIGHT.decodeAddress(addrStr);
  if (dec.networkId !== net.networkId) {
    const where = dec.networkId ? dec.networkId : 'Mainnet';
    throw new Error(`Recipient is on ${where}, but Eclipse is set to ${net.label}. Switch the network in Settings.`);
  }
  const amount = parseAda(amountStr); // NIGHT shares Cardano's 6-decimal unit
  if (amount <= 0n) throw new Error('Enter an amount greater than zero');
  const k = keysFor('midnight');
  const built = MIDNIGHT.buildTransfer({
    from: k.xOnly,
    to: dec.payload,
    amount,
    memo,
    network: net.id,
    ts: Math.floor(Date.now() / 1000),
  });
  return { chain: 'midnight', built, toAddress: String(toAddress).trim(), amountMicro: amount };
}

/**
 * NIGHT send (v1) — confirm step: sign with the NightExternal key and
 * submit to Midnight's public RPC (author_submitExtrinsic). Honest outcomes:
 *   - status 'broadcast': the node accepted the payload and returned a hash
 *   - status 'signed':    the node rejected it (or was unreachable) — the
 *                         fully signed payload + signature are retained
 */
async function midnightSignAndBroadcast(built, networkId = 'mainnet') {
  const k = keysFor('midnight');
  const sig = MIDNIGHT.signTransfer(built, k.privKey);
  if (!MIDNIGHT.verifyTransfer(built, sig, k.xOnly)) throw new Error('Signature failed self-verification');
  const signed = {
    v: 1,
    scheme: 'bip340-schnorr',
    pubkey: bytesToHex(k.xOnly),
    payload: bytesToHex(built.payload),
    hash: bytesToHex(built.hash),
    signature: bytesToHex(sig),
  };
  const res = await MIDNIGHT.broadcastSigned(signed.payload, networkId);
  return {
    status: res.ok ? 'broadcast' : 'signed',
    txid: res.ok ? res.txid : null,
    explorer: res.ok ? explorerTxLink('midnight', res.txid) : null,
    signed,
    nodeResponse: res.ok ? null : (res.offline ? 'offline' : String(res.error || 'rejected')),
  };
}

/* ------------------------- message signing --------------------------- */

/**
 * Sign a UTF-8 message with the chain's account key.
 *  - cardano:  Ed25519 (64B) over the raw message bytes
 *  - midnight: BIP340 Schnorr (64B) over the raw message bytes
 *  - bitcoin:  ECDSA secp256k1 (64B compact r||s) over SHA-256(message)
 */
function signChainMessage(chain, message) {
  const k = keysFor(chain);
  const msg = utf8ToBytes(String(message == null ? '' : message));
  if (chain === 'cardano') {
    const sig = ed25519.sign(msg, k.privKey);
    return {
      chain, scheme: 'ed25519',
      signature: b64(sig), pubKey: bytesToHex(k.pubKey),
      address: CARDANO.baseAddress(k, currentNetwork('cardano')),
    };
  }
  if (chain === 'midnight') {
    const sig = MIDNIGHT.sign(msg, k.privKey);
    return {
      chain, scheme: 'bip340-schnorr',
      signature: b64(sig), pubKey: bytesToHex(k.xOnly),
      address: MIDNIGHT.address(k.xOnly, currentNetwork('midnight').networkId),
    };
  }
  if (chain === 'bitcoin') {
    const sig = secp256k1.sign(sha256(msg), k.privKey).toCompactRawBytes();
    return {
      chain, scheme: 'ecdsa-secp256k1-sha256',
      signature: b64(sig), pubKey: bytesToHex(k.pubKey),
      address: BITCOIN.address(k, currentNetwork('bitcoin')),
    };
  }
  throw new Error('Unknown chain: ' + chain);
}

/* ============================== NOCTURNE ==============================
   Nocturne — the private messenger that lives inside Eclipse.
   Sealed DMs, a personal mailbox (you@nocturne.night) and quiet rails for
   NIGHT / ADA / BTC. The state is sealed (AES-256-GCM, key derived from
   the wallet seed) before it is ever written to chrome.storage.local.
   Requires the wallet to be unlocked. ADA/BTC sends reuse the wallet's
   real signing + broadcast pipelines. NIGHT sends build a canonical
   transfer record, sign it with your NightExternal key (BIP340) and
   submit it to Midnight's public RPC — the node's response is recorded
   honestly in the receipt (broadcast / signed), with the signed payload
   and signature kept sealed in the store.
   ============================== */

let ncKey = null; // AES-GCM CryptoKey derived from the seed — memory only
let ncStateObj = null; // decrypted messenger state — memory only
let ncSaveQueue = Promise.resolve();
let ncTicker = null;

const NC_ASSETS = {
  NIGHT: {
    symbol: 'NIGHT', name: 'Midnight', chain: 'midnight', sealed: false,
    color: 'var(--xno)', placeholder: 'mn_addr…',
    hint: 'Real send — BIP340-signed with your NightExternal key, then submitted to Midnight RPC.',
  },
  ADA: {
    symbol: 'ADA', name: 'Cardano', chain: 'cardano', sealed: false,
    color: 'var(--ada)', placeholder: 'addr1… / addr_test1…',
    hint: 'Real send — signed with your key and broadcast.',
  },
  BTC: {
    symbol: 'BTC', name: 'Bitcoin', chain: 'bitcoin', sealed: false,
    color: 'var(--btc)', placeholder: 'bc1… / tb1…',
    hint: 'Real send — signed with your key and broadcast.',
  },
};

function ncAsset(sym) { return NC_ASSETS[sym] || NC_ASSETS.NIGHT; }
function ncF(key) { return String(state.f['nc.' + key] || ''); }

function ncTime(ts) {
  if (!ts) return '';
  const diff = Date.now() - ts;
  if (diff < 60000) return 'now';
  if (diff < 3600000) return Math.floor(diff / 60000) + 'm';
  if (diff < 86400000) return Math.floor(diff / 3600000) + 'h';
  return new Date(ts).toLocaleDateString();
}

function ncConvo(id) {
  return ncStateObj ? (ncStateObj.convos.find((c) => c.id === id) || null) : null;
}

function ncDefaultUI() {
  return {
    tab: 'chats',
    convoId: null,
    mailTab: 'inbox',
    mailId: null,
    composing: false,
    newChatOpen: false,
    send: { asset: 'NIGHT', stage: 'form', toAddress: '', amountText: '', memo: '', built: null, feeRate: null, receipt: null },
  };
}

/** Load (or detect absence of) the sealed Nocturne state. */
async function ncEnsure() {
  const seed = requireUnlocked();
  if (!ncKey) ncKey = await nocturne.deriveDeviceKey(seed);
  const o = await store.get([nocturne.STORAGE_KEY]);
  const sealed = o[nocturne.STORAGE_KEY];
  if (!sealed) { ncStateObj = null; return null; }
  ncStateObj = await nocturne.openState(sealed, ncKey);
  nocturne.settle(ncStateObj);
  return ncStateObj;
}

/** Seal + persist the messenger state (queued, non-blocking). */
function ncSave() {
  if (!ncKey || !ncStateObj) return Promise.resolve();
  ncSaveQueue = ncSaveQueue.then(async () => {
    const blob = await nocturne.sealState(ncKey, ncStateObj);
    await store.set({ [nocturne.STORAGE_KEY]: blob });
  }).catch(() => { /* storage hiccup — in-memory copy stays authoritative */ });
  return ncSaveQueue;
}

/** Advance deterministic time state (ticks, typing, replies) + persist. */
function ncSettleTick() {
  if (!ncStateObj) return;
  const changed = nocturne.settle(ncStateObj);
  if (changed) ncSave();
}

function ncStartTicker() {
  // UI-only concern: in Node (tests) there is no DOM, and a live interval
  // would keep the process alive. Deterministic settling still happens on
  // every load and on ncSettleTick() calls.
  if (ncTicker || typeof setInterval === 'undefined' || typeof document === 'undefined') return;
  const t = setInterval(() => {
    ncSettleTick();
    if (state.view === 'nocturne' && dom()) render();
  }, 1000);
  if (typeof t.unref === 'function') t.unref();
  ncTicker = t;
}

function ncStopTicker() {
  if (ncTicker) { clearInterval(ncTicker); ncTicker = null; }
}

/* ------------------------------ dApps -------------------------------- */

async function refreshPending() {
  state.pending = await dappq.listPending(store);
  state.approvals = await dappq.getApprovals(store);
  updateBadge();
}

async function dappDecide(req, approved, result, remember) {
  try {
    if (approved && remember && req.chain) {
      await dappq.saveApproval(store, req.origin, req.chain);
    }
    await chrome.runtime.sendMessage({
      type: 'eclipse_dapp_decided',
      id: req.id,
      approved: !!approved,
      result: approved ? (result || null) : null,
      reason: approved ? undefined : 'Rejected by user',
    });
  } catch { /* worker may have already timed out — queue state is still cleaned */ }
  await dappq.popPending(store, req.id);
  await refreshPending();
  render(); // refresh the dApps list (no-op outside a DOM)
}

function computeDappResult(req) {
  if (req.type === dappq.DAPP_TYPES.getAddress) {
    if (!CHAIN[req.chain]) throw new Error('Unknown chain in dApp request');
    return { address: addressFor(req.chain), chain: req.chain, network: currentNetwork(req.chain).id };
  }
  if (req.type === dappq.DAPP_TYPES.signMessage) {
    if (!CHAIN[req.chain]) throw new Error('Unknown chain in dApp request');
    if (typeof req.message !== 'string' || !req.message.length) throw new Error('dApp sent an empty message');
    return signChainMessage(req.chain, req.message);
  }
  throw new Error('Unsupported dApp request type: ' + req.type);
}

/* ------------------------------ modal -------------------------------- */

const dom = () => (typeof document !== 'undefined' ? document : null);

function closeModal() {
  const doc = dom();
  if (doc) doc.getElementById('overlay')?.remove();
  state.modal = null;
  state.modalError = null;
}

function openModal(html) {
  const doc = dom();
  if (!doc) return;
  doc.getElementById('overlay')?.remove();
  const el = doc.createElement('div');
  el.className = 'overlay';
  el.id = 'overlay';
  el.innerHTML = html;
  doc.body.appendChild(el);
  const focusEl = el.querySelector('input[type="password"]') || el.querySelector('.btn.primary') || el.querySelector('.btn');
  if (focusEl) { try { focusEl.focus(); } catch { /* ignore */ } }
}

function modalHtml() {
  const m = state.modal;
  if (!m) return '';
  if (m.kind === 'password') {
    return `<div class="modal">
      <h2>${esc(m.title)}</h2>
      <p class="muted small mb">${esc(m.body || '')}</p>
      ${state.modalError ? `<div class="notice err">${esc(state.modalError)}</div>` : ''}
      <div class="field" style="margin-top:10px"><input type="password" data-m="password" placeholder="Password" autocomplete="current-password"></div>
      <div class="actions">
        <button class="btn" data-action="modal:cancel">Cancel</button>
        <button class="btn primary" data-action="modal:ok">${esc(m.okLabel || 'Confirm')}</button>
      </div>
    </div>`;
  }
  // confirm
  return `<div class="modal">
    <h2>${esc(m.title)}</h2>
    <p class="muted small mb">${esc(m.body || '')}</p>
    ${state.modalError ? `<div class="notice err">${esc(state.modalError)}</div>` : ''}
    <div class="actions">
      <button class="btn" data-action="modal:cancel">Cancel</button>
      <button class="btn ${m.danger ? 'danger' : 'primary'}" data-action="modal:ok">${esc(m.okLabel || 'OK')}</button>
    </div>
  </div>`;
}

function openPasswordModal(title, body, onOk, okLabel = 'Confirm') {
  state.modal = { kind: 'password', title, body, onOk, okLabel };
  state.modalError = null;
  const doc = dom();
  if (!doc) return;
  doc.getElementById('overlay')?.remove();
  openModal(modalHtml());
}

function openConfirmModal(title, body, onOk, okLabel = 'OK', danger = false) {
  state.modal = { kind: 'confirm', title, body, onOk, okLabel, danger };
  state.modalError = null;
  const doc = dom();
  if (!doc) return;
  doc.getElementById('overlay')?.remove();
  openModal(modalHtml());
}

async function handleModalAction(action, dataset) {
  const m = state.modal;
  if (!m) return;
  if (action === 'modal:cancel' || action === 'modal:close') { closeModal(); return; }
  if (action === 'modal:copy' && dataset.text) {
    try { await navigator.clipboard.writeText(dataset.text); toast('Copied'); } catch { toast('Copy failed', 'err'); }
    return;
  }
  if (action !== 'modal:ok') return;
  try {
    const doc = dom();
    const pw = m.kind === 'password' && doc ? doc.getElementById('overlay').querySelector('[data-m="password"]')?.value : undefined;
    state.modalError = null;
    const before = state.modal;
    if (m.kind === 'password') await Promise.resolve(m.onOk(pw));
    else await Promise.resolve(m.onOk());
    // If onOk opened a *new* modal (e.g. a password step replacing a confirm
    // step), keep it; otherwise the completed modal is closed.
    if (state.modal === before) closeModal();
  } catch (e) {
    state.modalError = e.message || String(e);
    const doc = dom();
    if (doc) {
      const ov = doc.getElementById('overlay');
      if (ov) ov.innerHTML = modalHtml();
    }
  }
}

/* --------------------------- QR (receive) ---------------------------- */

function openQrModal(addr) {
  let body = '<div class="notice err">QR generator is not available in this build.</div>';
  if (typeof qrcode === 'function') {
    try {
      const qr = qrcode(10, 'M'); // version 10 ≈ 152 bytes capacity — fits all three address kinds
      qr.addData(String(addr));
      qr.make();
      body = `<div class="qr-wrap">${qr.createImgTag(2, 8)}</div>`;
    } catch (e) {
      body = `<div class="notice err">Could not build QR: ${esc(e.message)}</div>`;
    }
  }
  openModal(`<div class="modal">
    <h2 class="center">Receive</h2>
    ${body}
    <div class="addr center mb" style="margin-top:10px">${esc(addr)}</div>
    <div class="actions">
      <button class="btn" data-action="modal:copy" data-text="${esc(addr)}">Copy address</button>
      <button class="btn primary" data-action="modal:close">Done</button>
    </div>
  </div>`);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(String(text));
    toast('Copied to clipboard');
  } catch {
    const doc = dom();
    if (!doc) return;
    const ta = doc.createElement('textarea');
    ta.value = String(text);
    doc.body.appendChild(ta);
    ta.select();
    try { doc.execCommand('copy'); toast('Copied'); } catch { toast('Copy failed', 'err'); }
    ta.remove();
  }
}

/* ============================== VIEWS ================================ */

function topbar() {
  const unlocked = !!seedBytes;
  return `<div class="topbar">
    <div class="brand">${logoMark(24)}<span>Eclipse</span></div>
    <div class="spacer"></div>
    <div class="status"><span class="dot ${unlocked ? '' : 'locked'}"></span>${unlocked ? 'Unlocked' : 'Locked'}</div>
    ${unlocked ? '<button class="btn icon" data-action="lock" title="Lock wallet" aria-label="Lock wallet">🔒</button>' : ''}
  </div>`;
}

function bottomNav() {
  const v = state.view;
  if (!['wallet', 'dapps', 'settings', 'nocturne'].includes(v)) return '';
  const item = (id, ico, label, active, n) => `
    <button data-action="nav:${id}" class="${active ? 'active' : ''}">
      <span class="ico ${n ? 'badge' : ''}" ${n ? `data-n="${n}"` : ''}>${ico}</span>${label}
    </button>`;
  return `<nav class="bottomnav">
    ${item('wallet', '◈', 'Wallet', v === 'wallet', 0)}
    ${item('nocturne', '☾', 'Nocturne', v === 'nocturne', 0)}
    ${item('dapps', '⬡', 'dApps', v === 'dapps', state.pending.length)}
    ${item('settings', '⚙', 'Settings', v === 'settings', 0)}
  </nav>`;
}

function viewOnboarding() {
  return `<div class="view">
    <div class="hero">
      ${logoMark(64)}
      <h1>Eclipse Wallet</h1>
      <div class="trio-line" aria-hidden="true"></div>
      <p>One self-custody wallet for <b class="c-cardano">Cardano</b>, <b class="c-mid">Midnight</b> and <b class="c-btc">Bitcoin</b>.
         Your keys are generated and used on this device only.</p>
      <div class="chips">
        <span class="chip" style="--c:${CHAIN_META.cardano.color}">◈ ADA</span>
        <span class="chip" style="--c:${CHAIN_META.midnight.color}">☾ NIGHT</span>
        <span class="chip" style="--c:${CHAIN_META.bitcoin.color}">₿ BTC</span>
      </div>
    </div>
    <div class="card flush">
      <div class="row">
        <div class="grow"><b>Create a new wallet</b><div class="muted small">Generate a fresh 24-word recovery phrase</div></div>
        <button class="btn primary" data-action="onboard:create">Start</button>
      </div>
      <div class="row">
        <div class="grow"><b>Import an existing wallet</b><div class="muted small">Enter a 12 / 18 / 24-word phrase</div></div>
        <button class="btn" data-action="onboard:import">Import</button>
      </div>
    </div>
    <p class="muted small center mt">Eclipse is open source. Nothing is sent anywhere without your explicit approval.</p>
  </div>`;
}

function viewCreate() {
  const words = String(state.mnemonic || '').split(/\s+/).filter(Boolean);
  const grid = words.map((w, i) => `<div class="word"><b>${i + 1}</b>${esc(w)}</div>`).join('');
  return `<div class="view">
    <h2>Your recovery phrase</h2>
    <p class="muted small mb">Write these ${words.length} words down, in order, on paper. Eclipse does <b>not</b> store this phrase — if you lose it, your funds are unrecoverable.</p>
    <div class="notice warn">Keep it offline. Never share it, screenshot it, or type it into a website or email.</div>
    <div class="word-grid">${grid}</div>
    <div class="mt"><button class="btn block" data-action="create:copy">Copy to clipboard</button></div>
    <div class="mt"><button class="btn primary block" data-action="create:ack">I've written it down</button></div>
    <div class="mt"><button class="btn ghost block" data-action="create:back">Back</button></div>
  </div>`;
}

function viewCreatePw() {
  return `<div class="view">
    <h2>Set a password</h2>
    <p class="muted small mb">This encrypts your keys on this device (scrypt + AES-256-GCM). You'll need it to unlock and to confirm signatures.</p>
    ${errBox()}
    <div class="field"><label>Password</label>
      <input type="password" data-f="password" placeholder="At least 8 characters" autocomplete="new-password" value="${esc(state.f.password || '')}"></div>
    <div class="field"><label>Confirm password</label>
      <input type="password" data-f="password2" placeholder="Repeat password" autocomplete="new-password" value="${esc(state.f.password2 || '')}"></div>
    <button class="btn primary block" data-action="createpw:go" ${state.busy ? 'disabled' : ''}>
      ${state.busy ? '<span class="spinner"></span> Encrypting (≈1 s)…' : 'Encrypt &amp; create wallet'}
    </button>
    <div class="mt"><button class="btn ghost block" data-action="createpw:back">Back</button></div>
  </div>`;
}

function viewImport() {
  return `<div class="view">
    <h2>Import a wallet</h2>
    <p class="muted small mb">Paste your recovery phrase and choose a password to protect it on this device.</p>
    ${errBox()}
    <div class="field"><label>Recovery phrase</label>
      <textarea data-f="mnemonic" placeholder="word1 word2 word3 … (12, 18 or 24 words)">${esc(state.f.mnemonic || '')}</textarea>
      <div class="hint">BIP39, English wordlist. Spaces or commas both work.</div>
    </div>
    <div class="field"><label>Password</label>
      <input type="password" data-f="password" placeholder="At least 8 characters" autocomplete="new-password" value="${esc(state.f.password || '')}"></div>
    <div class="field"><label>Confirm password</label>
      <input type="password" data-f="password2" placeholder="Repeat password" autocomplete="new-password" value="${esc(state.f.password2 || '')}"></div>
    <button class="btn primary block" data-action="import:go" ${state.busy ? 'disabled' : ''}>
      ${state.busy ? '<span class="spinner"></span> Encrypting (≈1 s)…' : 'Import &amp; encrypt'}
    </button>
    <div class="mt"><button class="btn ghost block" data-action="import:back">Back</button></div>
  </div>`;
}

function viewUnlock() {
  return `<div class="view">
    <div class="hero" style="padding-top:52px">
      ${logoMark(52)}
      <h2>Welcome back</h2>
      <p class="muted small">Unlock Eclipse on this device.</p>
    </div>
    ${errBox()}
    <div class="field"><label>Password</label>
      <input type="password" data-f="password" placeholder="Wallet password" autocomplete="current-password" value="${esc(state.f.password || '')}"></div>
    <button class="btn primary block" data-action="unlock:go" ${state.busy ? 'disabled' : ''}>
      ${state.busy ? '<span class="spinner"></span> Unlocking…' : 'Unlock'}
    </button>
    <div class="mt"><p class="muted small center">Keys stay encrypted at rest and live in memory only while unlocked.</p></div>
  </div>`;
}

function addressCard(chain) {
  const k = keysFor(chain);
  const net = currentNetwork(chain);
  const row = (label, addr) => `
    <div class="row">
      <div class="grow">
        <div class="muted small" style="margin-bottom:3px">${label}</div>
        <div class="addr">${esc(addr)}</div>
      </div>
      <button class="btn icon" data-action="copy" data-text="${esc(addr)}" title="Copy ${label}" aria-label="Copy ${label}">⧉</button>
      <button class="btn icon" data-action="qr" data-text="${esc(addr)}" title="Show QR code" aria-label="QR code for ${label}">▦</button>
    </div>`;
  if (chain === 'cardano') {
    return `<div class="card flush">
      ${row('Payment (base) address', CARDANO.baseAddress(k, net))}
      ${row('Stake (reward) address', CARDANO.stakeAddress(k, net))}
      ${row('Enterprise address', CARDANO.enterpriseAddress(k, net))}
    </div>`;
  }
  if (chain === 'bitcoin') {
    return `<div class="card flush">
      ${row('Bitcoin address (native SegWit)', BITCOIN.address(k, net))}
    </div>`;
  }
  return `<div class="card flush">
    ${row('Midnight unshielded address', MIDNIGHT.address(k.xOnly, net.networkId))}
  </div>`;
}

/* --------------------------- live USD prices ---------------------------
   Display-only: USD values shown next to balances (CoinGecko public API).
   Prices never influence signing, fees or broadcast — when the fetch fails
   (offline, rate-limited) the USD line is simply not rendered. */
const PRICE_TTL_MS = 60000;
const prices = { data: null, ts: 0, inFlight: null };

function fmtUsd(n) {
  if (n == null || !isFinite(Number(n))) return null;
  const v = Number(n);
  const opts = v < 1 ? { minimumFractionDigits: 2, maximumFractionDigits: 4 }
                     : { maximumFractionDigits: 2 };
  return '$' + v.toLocaleString('en-US', opts);
}

async function refreshPrices(force = false) {
  const fresh = prices.data != null && Date.now() - prices.ts < PRICE_TTL_MS;
  if (fresh && !force) return prices.data;
  if (prices.inFlight) return prices.inFlight;
  prices.inFlight = (async () => {
    try {
      const ctl = typeof AbortController !== 'undefined' ? new AbortController() : null;
      const t = ctl ? setTimeout(() => ctl.abort(), 8000) : null;
      const r = await fetch(
        'https://api.coingecko.com/api/v3/simple/price?ids=cardano,bitcoin,midnight-3&vs_currencies=usd',
        { headers: { accept: 'application/json' }, signal: ctl ? ctl.signal : undefined }
      );
      if (t) clearTimeout(t);
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const p = await r.json();
      prices.data = {
        cardano:  p.cardano && p.cardano.usd != null ? Number(p.cardano.usd) : null,
        bitcoin:  p.bitcoin && p.bitcoin.usd != null ? Number(p.bitcoin.usd) : null,
        midnight: p['midnight-3'] && p['midnight-3'].usd != null ? Number(p['midnight-3'].usd) : null,
      };
      prices.ts = Date.now();
      return prices.data;
    } catch {
      return prices.data; // keep previous values (or null) — UI degrades gracefully
    } finally {
      prices.inFlight = null;
    }
  })();
  return prices.inFlight;
}

function usdLine(chain) {
  const p = prices.data;
  if (!p) return '';
  const b = state.balances[chain];
  if (chain === 'cardano' && typeof b?.lovelace === 'bigint' && p.cardano != null) {
    const u = fmtUsd(Number(b.lovelace) / 1e6 * p.cardano);
    if (u) return `<div class="usd">≈ ${u}</div>`;
  }
  if (chain === 'bitcoin' && typeof b?.sats === 'bigint' && p.bitcoin != null) {
    const u = fmtUsd(Number(b.sats) / 1e8 * p.bitcoin);
    if (u) return `<div class="usd">≈ ${u}</div>`;
  }
  if (chain === 'midnight' && p.midnight != null) {
    return `<div class="usd">1 NIGHT ≈ ${fmtUsd(p.midnight)}</div>`;
  }
  return '';
}

function balanceHero(chain) {
  const b = state.balances[chain];
  const net = currentNetwork(chain);
  let amount = '—';
  let sub = '';
  if (chain === 'cardano') {
    if (b?.loading) sub = 'Loading balance…';
    else if (b?.error) { amount = '??'; sub = 'Balance unavailable'; }
    else if (b && typeof b.lovelace === 'bigint') { amount = formatAda(b.lovelace); sub = `${b.utxos} UTXO(s) · ${net.label}`; }
    else sub = `Tap refresh to load from Koios · ${net.label}`;
  } else if (chain === 'bitcoin') {
    if (b?.loading) sub = 'Loading balance…';
    else if (b?.error) { amount = '??'; sub = 'Balance unavailable'; }
    else if (b && typeof b.sats === 'bigint') { amount = formatBtc(b.sats); sub = `Received ${formatBtc(b.received)} · ${net.label}`; }
    else sub = `Tap refresh to load from Blockstream · ${net.label}`;
  } else {
    amount = CHAIN_META.midnight.symbol;
    sub = `${net.label} · v1 supports address + message signing (no public balance API)`;
  }
  const meta = CHAIN_META[chain];
  return `<div class="balance-hero" data-chain="${chain}">
    <div class="hero-glyph" aria-hidden="true">${meta.icon}</div>
    <div class="muted small" style="display:flex;align-items:center;gap:7px">
      <span style="width:9px;height:9px;border-radius:50%;background:${meta.color};display:inline-block"></span>
      ${CHAIN[chain].name} · ${meta.symbol}
    </div>
    <div class="amount" style="margin-top:6px">${b?.loading ? '<span class="spinner"></span> Loading…' : esc(amount)}</div>
    ${usdLine(chain)}
    <div class="sub">${esc(sub)}</div>
    <div style="margin-top:12px;display:flex;gap:8px">
      <button class="btn sm" data-action="refresh" ${state.balances[chain]?.loading ? 'disabled' : ''}>↻ Refresh</button>
    </div>
  </div>`;
}

function viewWallet() {
  const chain = state.chain;
  const net = currentNetwork(chain);
  const networkOptions = Object.values(CHAIN[chain].networks)
    .map((n) => `<option value="${esc(n.id)}" ${n.id === net.id ? 'selected' : ''}>${esc(n.label)}</option>`).join('');
  const canSend = chain === 'cardano' || chain === 'bitcoin';
  return `${topbar()}
  <div class="view">
    <div class="tabs">
      ${['cardano', 'midnight', 'bitcoin'].map((c) => `
        <button data-action="chain" data-chain="${c}" class="${c === chain ? 'active' : ''}">
          <span class="sym" aria-hidden="true">${CHAIN_META[c].icon}</span>${CHAIN_META[c].symbol}
        </button>`).join('')}
    </div>
    ${balanceHero(chain)}
    ${addressCard(chain)}
    <div class="card flush">
      <div class="row">
        <div class="grow"><div class="muted small">Network</div>
          <select data-f="net:${chain}" style="margin-top:4px;padding:7px 10px;font-size:12.5px" aria-label="Network">
            ${networkOptions}
          </select>
        </div>
      </div>
    </div>
    <div style="display:flex;gap:8px;margin-bottom:12px">
      ${canSend ? `<button class="btn ${chain === 'bitcoin' ? 'orange' : 'primary'}" style="flex:1" data-action="send">Send</button>` : '<button class="btn" style="flex:1" disabled title="Midnight v1: address + sign message only">Send</button>'}
      <button class="btn" style="flex:1" data-action="receive">Receive</button>
      <button class="btn" style="flex:1" data-action="signmsg">Sign msg</button>
    </div>
    ${chain === 'midnight' ? '<div class="notice info">Midnight v1 is address + message signing. On-chain Midnight transactions arrive in a later release.</div>' : ''}
  </div>
  ${bottomNav()}`;
}

function viewSend() {
  const s = state.send;
  if (!s) return viewWallet();
  const chain = s.chain;
  const sym = CHAIN_META[chain].symbol;
  if (s.stage === 'done' || state.view === 'txdone') {
    return viewTxDone();
  }
  let reviewHtml = '';
  if (s.stage === 'review' && s.built) {
    const rows = [];
    const kv = (k, v, mono = false) => rows.push(`<div class="row"><span class="k">${k}</span><span class="v ${mono ? 'mono' : ''}">${esc(v)}</span></div>`);
    if (chain === 'cardano') {
      kv('Recipient', s.toAddress, true);
      kv('Amount', formatAda(s.amountLovelace));
      kv('Network fee', formatAda(s.built.fee));
      kv('Total', formatAda(s.amountLovelace + s.built.fee));
      if (s.built.change > 0n) kv('Change back', formatAda(s.built.change));
      kv('Tx size (signed, est.)', s.built.size + ' B');
    } else {
      kv('Recipient', s.toAddress, true);
      kv('Amount', formatBtc(s.amountSats));
      kv('Fee', s.built.feeSats + ' sats (' + s.feeRate + ' sat/vB)');
      kv('Total', formatBtc(s.amountSats + s.built.feeSats));
      if (s.built.changeSats > 0n) kv('Change back', formatBtc(s.built.changeSats));
      kv('Inputs', String(s.built.inputs.length));
    }
    reviewHtml = `<div class="card flush kv"><div style="padding:4px 14px">${rows.join('')}</div></div>`;
  }

  const locked = s.stage === 'review';
  return `${topbar()}
  <div class="view">
    <h2 style="margin-bottom:10px">Send ${sym}</h2>
    ${errBox()}
    <div class="field"><label>Recipient address</label>
      <input data-f="to" placeholder="${chain === 'cardano' ? 'addr1… / addr_test1…' : 'bc1… / tb1…'}" value="${esc(state.f.to || '')}" ${locked ? 'disabled' : ''}></div>
    <div class="field"><label>Amount</label>
      <div class="suffix">
        <input data-f="amount" inputmode="decimal" placeholder="0.00" value="${esc(state.f.amount || '')}" ${locked ? 'disabled' : ''}>
        <button class="btn sm" data-action="max" ${locked ? 'disabled' : ''}>MAX</button>
      </div>
      <div class="hint">Balance: ${esc(balanceText(chain))}</div>
    </div>
    ${chain === 'bitcoin' ? `
    <div class="field"><label>Fee tier</label>
      <select data-f="tier">
        <option value="fastest" ${s?.tier === 'fastest' ? 'selected' : ''}>Fastest (${s?.fees ? s.fees.fastest : '…'} sat/vB)</option>
        <option value="halfHour" ${(s?.tier || 'halfHour') === 'halfHour' ? 'selected' : ''}>Standard (${s?.fees ? s.fees.halfHour : '…'} sat/vB)</option>
        <option value="economy" ${s?.tier === 'economy' ? 'selected' : ''}>Slow (${s?.fees ? s.fees.economy : '…'} sat/vB)</option>
      </select>
      <div class="hint">Live rates from mempool.space.</div>
    </div>` : ''}
    ${reviewHtml}
    ${s.stage === 'review'
      ? `<button class="btn ${chain === 'bitcoin' ? 'orange' : 'primary'} block" data-action="send:confirm">Confirm &amp; sign</button>
         <div class="mt"><button class="btn ghost block" data-action="send:edit">← Edit details</button></div>`
      : `<button class="btn ${chain === 'bitcoin' ? 'orange' : 'primary'} block" data-action="send:review" ${state.busy ? 'disabled' : ''}>${state.busy ? '<span class="spinner"></span> Building…' : 'Build &amp; review'}</button>`}
    <div class="mt"><button class="btn ghost block" data-action="send:back">Back to wallet</button></div>
  </div>
  ${bottomNav()}`;
}

function balanceText(chain) {
  const b = state.balances[chain];
  if (b?.loading) return 'loading…';
  if (b?.error) return 'unavailable';
  if (chain === 'cardano' && typeof b?.lovelace === 'bigint') return formatAda(b.lovelace);
  if (chain === 'bitcoin' && typeof b?.sats === 'bigint') return formatBtc(b.sats);
  return '—';
}

function viewSignMsg() {
  const chain = state.signChain;
  const r = state.signResult;
  const chainOptions = ['cardano', 'midnight', 'bitcoin'].map((c) =>
    `<option value="${c}" ${c === chain ? 'selected' : ''}>${CHAIN[c].name}</option>`).join('');
  return `${topbar()}
  <div class="view">
    <h2 style="margin-bottom:10px">Sign a message</h2>
    <p class="muted small mb">Proves control of your key without spending anything. Signing requires your password.</p>
    ${errBox()}
    <div class="field"><label>Chain</label><select data-f="signchain">${chainOptions}</select></div>
    <div class="field"><label>Message (UTF-8)</label>
      <textarea data-f="signmsgtext" rows="5" placeholder="Type the message to sign…">${esc(state.f.signmsgtext || '')}</textarea>
    </div>
    <button class="btn ${chain === 'bitcoin' ? 'orange' : 'primary'} block" data-action="sign:go" ${state.busy ? 'disabled' : ''}>${state.busy ? '<span class="spinner"></span> Signing…' : 'Sign message'}</button>
    <div class="mt"><button class="btn ghost block" data-action="sign:back">Back to wallet</button></div>
    ${r ? `<div class="card flush mt">
      <div class="row"><div class="grow"><div class="muted small">Scheme</div><div>${esc(r.scheme)}</div></div></div>
      <div class="row"><div class="grow"><div class="muted small">Signature (base64)</div><div class="addr">${esc(r.signature)}</div></div>
      <button class="btn icon" data-action="copy" data-text="${esc(r.signature)}">⧉</button></div>
      <div class="row"><div class="grow"><div class="muted small">Public key (hex)</div><div class="addr">${esc(r.pubKey)}</div></div>
      <button class="btn icon" data-action="copy" data-text="${esc(r.pubKey)}">⧉</button></div>
    </div>` : ''}
  </div>
  ${bottomNav()}`;
}

function dappReqHtml(req) {
  const isSign = req.type === dappq.DAPP_TYPES.signMessage;
  const typeLabel = isSign ? 'Sign message' : req.type === dappq.DAPP_TYPES.getAddress ? 'Request address' : 'Request';
  const originApproved = state.approvals[req.origin]?.chains?.includes(req.chain);
  const preview = req.message ? String(req.message).slice(0, 220) : (isSign ? '—' : 'Return your ' + (req.chain || '') + ' address');
  return `<div class="dapp-card">
    <div class="head">
      <span class="origin">${esc(req.origin)}</span>
      <span class="pill ${esc(req.chain || '')}">${esc(req.chain || 'any')}</span>
    </div>
    <div class="small muted">${esc(typeLabel)} · ${new Date(req.ts || Date.now()).toLocaleTimeString()}</div>
    ${req.message ? `<div class="msg">${esc(preview)}${String(req.message).length > 220 ? '…' : ''}</div>` : ''}
    ${originApproved ? '<div class="notice ok" style="margin:8px 0 0">This origin is remembered for ' + esc(req.chain || 'this chain') + '.</div>' : ''}
    <div class="actions">
      <label class="checkbox" style="flex:0 0 auto"><input type="checkbox" data-remember="${esc(req.id)}"> Remember</label>
      <button class="btn danger sm" data-action="dapp:reject" data-id="${esc(req.id)}">Reject</button>
      <button class="btn ok sm" data-action="dapp:approve" data-id="${esc(req.id)}">Approve</button>
    </div>
  </div>`;
}

function viewDapps() {
  const approvals = Object.entries(state.approvals || {});
  return `${topbar()}
  <div class="view">
    <h2 style="margin-bottom:4px">dApp requests</h2>
    <p class="muted small mb">Sites using <span class="mono">window.eclipse</span> appear here. Approving signs with your key — check the origin carefully.</p>
    ${state.pending.length === 0
      ? '<div class="empty"><div class="big">⬡</div>No pending requests.<br>Connect from a site with <span class="mono">window.eclipse.request(…)</span>.</div>'
      : state.pending.map(dappReqHtml).join('')}
    <h3>Remembered origins</h3>
    ${approvals.length === 0
      ? '<p class="muted small">None yet. Tick “Remember” when approving to speed up future requests.</p>'
      : approvals.map(([origin, entry]) => `
        <div class="card flush"><div class="row">
          <div class="grow"><div class="addr">${esc(origin)}</div>
          <div class="muted small">${esc((entry.chains || []).join(', ') || '—')}</div></div>
          <button class="btn icon" data-action="dapp:clear" data-origin="${esc(origin)}" title="Forget this origin">✕</button>
        </div></div>`).join('')}
  </div>
  ${bottomNav()}`;
}

function viewSettings() {
  const netSelect = (chain) => {
    const cur = state.networks[chain];
    const opts = Object.values(CHAIN[chain].networks)
      .map((n) => `<option value="${esc(n.id)}" ${n.id === cur ? 'selected' : ''}>${esc(n.label)}</option>`).join('');
    return `<div class="row">
      <div class="grow"><b style="font-size:13px">${CHAIN[chain].name}</b>
        <div class="muted small">${CHAIN[chain].symbol}</div></div>
      <select data-f="net:${chain}" style="width:150px;padding:7px 10px;font-size:12.5px">${opts}</select>
    </div>`;
  };
  return `${topbar()}
  <div class="view">
    <h2 style="margin-bottom:4px">Settings</h2>
    <p class="muted small mb">Networks are per-chain and stored locally.</p>
    <div class="card flush">
      ${netSelect('cardano')}
      ${netSelect('midnight')}
      ${netSelect('bitcoin')}
    </div>
    <h3>Security</h3>
    <div class="card flush">
      <div class="row"><div class="grow"><b style="font-size:13px">Lock wallet</b><div class="muted small">Clear keys from memory</div></div>
        <button class="btn sm" data-action="settings:lock">Lock</button></div>
      <div class="row"><div class="grow"><b style="font-size:13px">Wipe this device</b><div class="muted small">Deletes the encrypted vault. Your recovery phrase is the only backup.</div></div>
        <button class="btn sm danger" data-action="settings:wipe">Wipe</button></div>
    </div>
    <h3>About</h3>
    <div class="card flush">
      <div class="row"><div class="grow"><b style="font-size:13px">Eclipse Wallet</b><div class="muted small">v0.1.0 · MV3 · Chrome &amp; Brave</div></div></div>
      <div class="row"><div class="grow muted small" style="margin-bottom:6px">Chains: Cardano (Koios data), Midnight (address + BIP340 sign), Bitcoin (Blockstream data, P2WPKH).</div></div>
      <div class="row"><div class="grow muted small" style="margin-bottom:6px">Provider: <span class="mono">window.eclipse</span> — getAddress + signMessage with per-request approval.</div></div>
      <div class="row"><div class="grow muted small" style="margin-bottom:6px">BIP39 English wordlist only. No third-party tracking, no telemetry.</div></div>
      <div class="row"><div class="grow muted small">Built by <a class="link" href="https://x.com/kshot9000" target="_blank" rel="noopener">@kshot9000</a> · <a class="link" href="https://github.com/Kshot3000/eclipse-wallet" target="_blank" rel="noopener">github.com/Kshot3000/eclipse-wallet</a></div></div>
    </div>
  </div>
  ${bottomNav()}`;
}

function viewTxDone() {
  const t = state.txDone;
  if (!t) return viewWallet();
  const link = explorerTxLink(t.chain, t.txid);
  return `${topbar()}
  <div class="view">
    <div class="success">
      <div class="check">✓</div>
      <h2>Transaction broadcast</h2>
      <p class="muted small">${CHAIN[t.chain].name} · ${esc(t.txid)}</p>
      <div class="txid">${esc(t.txid)}</div>
      <button class="btn block" data-action="copy" data-text="${esc(t.txid)}">Copy transaction ID</button>
      <div class="mt"><a class="btn block" href="${esc(link)}" target="_blank" rel="noopener">View on explorer ↗</a></div>
      <div class="mt"><button class="btn primary block" data-action="txdone:done">Back to wallet</button></div>
    </div>
  </div>
  ${bottomNav()}`;
}

/* --------------------------- Nocturne views --------------------------- */

function ncHeader() {
  const p = ncStateObj.profile;
  return `<div class="nc-head">
    <div class="nc-ident">
      <div class="nc-orb">☾</div>
      <div class="grow">
        <div class="nc-handle">@${esc(p.handle)}</div>
        <div class="nc-mailbox mono" data-action="nc:copy-mailbox" title="Copy mailbox">${esc(p.mailbox)}</div>
      </div>
      <span class="nc-lock">🔒 AES-256-GCM</span>
    </div>
    <div class="nc-head-actions">
      <span class="nc-local">local only</span>
      <button class="btn sm ghost" data-action="nc:clear" title="Clear Nocturne data from this device">Clear</button>
    </div>
  </div>`;
}

function ncTabs() {
  const tabs = [['chats', 'Chats'], ['mail', 'Mail'], ['send', 'Send'], ['activity', 'Activity']];
  const unread = ncStateObj.mail.inbox.filter((m) => !m.read).length;
  return `<div class="nc-tabs">${tabs.map(([id, label]) =>
    `<button data-action="nc:sub" data-tab="${id}" class="${state.nc.tab === id ? 'active' : ''}">${label}${id === 'mail' && unread ? `<span class="nc-dot">${unread}</span>` : ''}</button>`).join('')}</div>`;
}

function ncOnboarding() {
  const handle = ncF('handle').trim().toLowerCase();
  const valid = nocturne.validHandle(handle);
  return `<div class="nc-onb">
    <div class="nc-orb big">☾</div>
    <h2>Nocturne</h2>
    <p class="muted small">The quiet side of Eclipse — private chats, your own mailbox, and NIGHT / ADA / BTC rails. Every record is sealed on this device before it is stored.</p>
    ${errBox()}
    <div class="field"><label>Your handle</label>
      <input data-f="nc.handle" maxlength="24" placeholder="kshot" value="${esc(ncF('handle'))}" autocomplete="off" spellcheck="false" style="font-family:var(--mono)">
      <div class="hint">${handle
        ? (valid ? `Your mailbox: <b class="mono">${esc(handle)}@${esc(nocturne.DOMAIN)}</b>` : '3–24 lowercase letters, numbers or underscores')
        : '3–24 lowercase letters, numbers or underscores'}</div>
    </div>
    <button class="btn primary moon block" data-action="nc:create" ${!valid || state.busy ? 'disabled' : ''}>
      ${state.busy ? '<span class="spinner"></span> Sealing…' : 'Step into the dark'}
    </button>
    ${state.ncLoadError ? `<div class="notice err mt">The sealed store on this device could not be opened. Starting fresh discards the local Nocturne records in this browser.</div>
    <div class="mt"><button class="btn danger block" data-action="nc:reset">Start fresh (reset Nocturne store)</button></div>` : ''}
    <div class="notice info mt">Residents here are demo contacts — Nocturne has no server by design. Your data never leaves this browser.</div>
  </div>`;
}

function ncChatList() {
  const convos = ncStateObj.convos.slice().sort((a, b) => (b.lastActive || 0) - (a.lastActive || 0));
  const rows = convos.map((c) => {
    const last = c.msgs[c.msgs.length - 1];
    return `<div class="nc-convo" data-action="nc:open-convo" data-id="${esc(c.id)}">
      <div class="nc-avar" style="--c:${c.color}">${esc((c.name || c.handle)[0].toUpperCase())}</div>
      <div class="grow">
        <div class="nc-convo-head"><b>${esc(c.name)}</b>${c.online ? '<span class="nc-online" title="online"></span>' : ''}<span class="muted small nc-convo-handle">@${esc(c.handle)}</span></div>
        <div class="muted small nc-preview">${last ? (last.from === 'me' ? 'You: ' : '') + esc(last.text).slice(0, 48) : 'Say something…'}</div>
      </div>
      <div class="nc-when">${ncTime(last ? last.ts : c.lastActive)}</div>
    </div>`;
  }).join('');
  return `<div class="nc-card">
    <div class="nc-newchat-row">
      <div class="grow"><b style="font-size:13px">Start a chat</b><div class="muted small">Anyone at <span class="mono">${esc(nocturne.DOMAIN)}</span></div></div>
      <button class="btn sm" data-action="nc:newchat-open">＋ New</button>
    </div>
    ${state.nc.newChatOpen ? `<div class="nc-newchat">
      ${errBox()}
      <div class="field" style="margin-bottom:8px"><input data-f="nc.newhandle" placeholder="handle" value="${esc(ncF('newhandle'))}" maxlength="24" autocomplete="off" spellcheck="false" style="font-family:var(--mono)"></div>
      <div class="actions">
        <button class="btn sm" data-action="nc:newchat-cancel">Cancel</button>
        <button class="btn sm primary moon" data-action="nc:newchat-go">Open chat</button>
      </div>
    </div>` : ''}
    ${rows}
  </div>`;
}

function ncThread() {
  const c = ncConvo(state.nc.convoId);
  if (!c) return ncChatList();
  const msgs = c.msgs.map((m) => `
    <div class="nc-msg ${m.from}">
      <div class="nc-bubble">${esc(m.text)}</div>
      <div class="nc-meta">${ncTime(m.ts)}${m.from === 'me' ? `<span class="nc-ticks ${m.status}">${m.status === 'sent' ? '✓' : '✓✓'}</span>` : ''}</div>
    </div>`).join('');
  return `<div class="nc-thread">
    <div class="nc-thread-head">
      <button class="btn icon" data-action="nc:back" title="Back to chats">←</button>
      <div class="nc-avar sm" style="--c:${c.color}">${esc((c.name || c.handle)[0].toUpperCase())}</div>
      <div class="grow"><b>${esc(c.name)}</b>
        <div class="muted small">${c.typing ? 'typing…' : (c.online ? 'online' : 'offline')} · @${esc(c.handle)}${c.system ? ' · resident' : ''}</div>
      </div>
    </div>
    <div class="nc-msgs" id="nc-msgs">
      ${msgs}
      ${c.typing ? '<div class="nc-msg them"><div class="nc-bubble typing"><span></span><span></span><span></span></div></div>' : ''}
    </div>
    <div class="nc-composer">
      <input data-f="nc.msg" placeholder="Whisper…" value="${esc(ncF('msg'))}" autocomplete="off" maxlength="500">
      <button class="btn sm primary moon" data-action="nc:msg-send" ${ncF('msg').trim() ? '' : 'disabled'}>Send</button>
    </div>
  </div>`;
}

function ncMailList() {
  const tab = state.nc.mailTab || 'inbox';
  const list = ncStateObj.mail[tab] || [];
  const rows = list.map((m) => `
    <div class="nc-mailrow ${m.read ? '' : 'unread'}" data-action="nc:mail-open" data-id="${esc(m.id)}">
      <div class="grow">
        <div class="nc-mailrow-head">${m.read ? '' : '<span class="nc-unread"></span>'}<b>${esc(m.name || m.from)}</b>${tab === 'sent' ? `<span class="muted small">→ ${esc(m.to)}</span>` : ''}</div>
        <div class="muted small">${esc(m.subject)}</div>
      </div>
      <div class="nc-when">${ncTime(m.ts)}</div>
    </div>`).join('');
  return `<div class="nc-card">
    <div class="nc-mailtabs">
      <button class="${tab === 'inbox' ? 'active' : ''}" data-action="nc:mailtab" data-tab="inbox">Inbox (${ncStateObj.mail.inbox.length})</button>
      <button class="${tab === 'sent' ? 'active' : ''}" data-action="nc:mailtab" data-tab="sent">Sent (${ncStateObj.mail.sent.length})</button>
      <button class="nc-compose-btn" data-action="nc:compose" title="Compose sealed mail">✎</button>
    </div>
    ${list.length === 0 ? '<div class="nc-empty">Nothing here yet.</div>' : rows}
  </div>`;
}

function ncMailRead() {
  const tab = state.nc.mailTab || 'inbox';
  const m = (ncStateObj.mail[tab] || []).find((x) => x.id === state.nc.mailId);
  if (!m) return ncMailList();
  return `<div class="nc-mailread">
    <div class="nc-thread-head">
      <button class="btn icon" data-action="nc:mailback" title="Back to ${tab}">←</button>
      <div class="grow"><b>${esc(m.subject)}</b>
        <div class="muted small">${tab === 'sent' ? 'To' : 'From'}: <span class="mono">${esc(tab === 'sent' ? m.to : m.from)}</span> · ${ncTime(m.ts)}</div>
      </div>
    </div>
    <div class="nc-mailbody">${esc(m.body).replace(/\n/g, '<br>')}</div>
  </div>`;
}

function ncCompose() {
  const to = ncF('mailto').trim();
  const m = /^(.*)@nocturne\.night$/i.exec(to);
  const toOk = !!m && nocturne.validHandle(m[1]);
  return `<div class="nc-mailread">
    <div class="nc-thread-head">
      <button class="btn icon" data-action="nc:compose-cancel" title="Cancel">←</button>
      <div class="grow"><b>Compose</b><div class="muted small">Sealed mail at <span class="mono">${esc(nocturne.DOMAIN)}</span></div></div>
    </div>
    ${errBox()}
    <div class="field"><label>To</label>
      <input data-f="nc.mailto" placeholder="resident@nocturne.night" value="${esc(ncF('mailto'))}" autocomplete="off" style="font-family:var(--mono)">
    </div>
    <div class="field"><label>Subject</label>
      <input data-f="nc.mailsubject" placeholder="A whisper" value="${esc(ncF('mailsubject'))}">
    </div>
    <div class="field"><label>Message</label>
      <textarea data-f="nc.mailbody" rows="6" placeholder="Write into the dark…">${esc(ncF('mailbody'))}</textarea>
    </div>
    <button class="btn primary moon block" data-action="nc:mail-send" ${!toOk || !ncF('mailsubject').trim() || !ncF('mailbody').trim() ? 'disabled' : ''}>Send sealed mail</button>
    <div class="hint mt">Mail to your own handle also lands in your Inbox.</div>
  </div>`;
}

function ncSendForm() {
  const s = state.nc.send;
  const a = ncAsset(s.asset);
  const assets = Object.values(NC_ASSETS).map((x) => `
    <div class="nc-asset ${s.asset === x.symbol ? 'active' : ''}" data-action="nc:asset" data-asset="${x.symbol}">
      <span class="nc-asset-dot" style="background:${x.color}"></span>
      <div class="grow"><b>${x.symbol}</b><div class="muted small">${x.name}</div></div>
      <span class="nc-asset-pill ${x.sealed ? 'sealed' : 'live'}">${x.sealed ? 'sealed v1' : 'live'}</span>
    </div>`).join('');
  return `<div class="nc-card">
    ${assets}
    ${errBox()}
    <div class="field"><label>Recipient ${a.symbol} address</label>
      <input data-f="nc.sendaddr" placeholder="${a.placeholder}" value="${esc(ncF('sendaddr'))}" spellcheck="false" style="font-family:var(--mono)">
    </div>
    <div class="field"><label>Amount</label>
      <div class="suffix"><input data-f="nc.sendamt" inputmode="decimal" placeholder="0.0" value="${esc(ncF('sendamt'))}"><span class="suffix-unit">${a.symbol}</span></div>
    </div>
    <div class="field"><label>Memo <span class="muted">(optional — travels with the record)</span></label>
      <input data-f="nc.sendmemo" maxlength="140" placeholder="e.g. for the archive" value="${esc(ncF('sendmemo'))}">
    </div>
    <div class="notice ${a.sealed ? 'info' : 'ok'}">${a.hint}</div>
    <button class="btn primary moon block" data-action="nc:review" ${state.busy ? 'disabled' : ''}>
      ${state.busy ? '<span class="spinner"></span> Building…' : (a.sealed ? 'Seal &amp; review' : 'Build &amp; review')}
    </button>
    <div class="mt"><button class="btn ghost block" data-action="nc:send-back">Back</button></div>
  </div>`;
}

function ncSendReview() {
  const s = state.nc.send;
  const a = ncAsset(s.asset);
  const rows = [];
  const kv = (k, v, mono) => rows.push(`<div class="row"><span class="k">${k}</span><span class="v ${mono ? 'mono' : ''}">${esc(v)}</span></div>`);
  kv('Asset', a.symbol + ' · ' + a.name);
  kv('Recipient', s.toAddress, true);
  if (a.chain === 'midnight') {
    kv('Amount', formatXno(s.amountMicro));
    kv('Network', currentNetwork('midnight').label);
    kv('Signature', 'BIP340 Schnorr · NightExternal key');
  } else if (a.chain === 'cardano') {
    kv('Amount', formatAda(s.amountLovelace));
    kv('Network fee', formatAda(s.built.fee));
    kv('Total', formatAda(s.amountLovelace + s.built.fee));
    if (s.built.change > 0n) kv('Change back', formatAda(s.built.change));
  } else {
    kv('Amount', formatBtc(s.amountSats));
    kv('Fee', s.built.feeSats + ' sats (' + s.feeRate + ' sat/vB)');
    kv('Total', formatBtc(s.amountSats + s.built.feeSats));
  }
  if (s.memo) kv('Memo', s.memo);
  return `<div class="nc-card">
    <div class="card flush kv"><div style="padding:4px 14px">${rows.join('')}</div></div>
    <div class="actions mt">
      <button class="btn sm" data-action="nc:sendqr" data-text="${esc(s.toAddress)}">▦ Recipient QR</button>
    </div>
    <button class="btn primary moon block" data-action="nc:confirm" style="margin-top:12px">${a.sealed ? 'Seal this transfer' : 'Sign &amp; broadcast'}</button>
    <div class="mt"><button class="btn ghost block" data-action="nc:back-edit">← Edit details</button></div>
  </div>`;
}

function ncReceipt() {
  const t = state.nc.send.receipt;
  if (!t) return ncSendForm();
  const live = t.status === 'broadcast';
  const legacySealed = t.status === 'sealed'; // v1 receipts from before signing landed
  const note = live
    ? `<div class="mt"><a class="btn block" href="${esc(t.explorer)}" target="_blank" rel="noopener">View on explorer ↗</a></div>`
    : `<div class="notice info mt">${
        t.nodeResponse === 'offline'
          ? 'Midnight RPC was unreachable — the transfer is fully signed and kept on this device.<br>'
          : t.nodeResponse
            ? '<b>' + esc(String(t.nodeResponse).slice(0, 160)) + '</b><br>'
            : ''
      }${legacySealed
        ? 'The v1 record is sealed in your store.'
        : 'Signed with your NightExternal key (BIP340). Midnight nodes do not accept v1 transfer records yet — the fully signed payload and signature are kept in this receipt.'}</div>`;
  return `<div class="nc-receipt ${live ? 'live' : 'sealed'}">
    <div class="nc-receipt-mark">${live ? '✓' : '☾'}</div>
    <h3>${live ? 'Transaction broadcast' : (legacySealed ? 'Sealed for the dark' : 'Signed for the dark')}</h3>
    <p class="muted small">${esc(t.asset)} · to <span class="mono">${esc(t.to)}</span> · ${ncTime(t.ts)}</p>
    <div class="card flush kv mt">
      <div class="row"><span class="k">Amount</span><span class="v">${esc(t.amountText)}</span></div>
      ${t.memo ? `<div class="row"><span class="k">Memo</span><span class="v">${esc(t.memo)}</span></div>` : ''}
      ${t.txid ? `<div class="row"><span class="k">Tx</span><span class="v mono">${esc(t.txid)}</span></div>` : ''}
      ${t.signed && t.signed.signature ? `<div class="row"><span class="k">Signature</span><span class="v mono">${esc(t.signed.scheme)} · ${esc(t.signed.signature.slice(0, 24))}…</span></div>` : ''}
      <div class="row"><span class="k">Reference</span><span class="v mono">${esc(t.id)}</span></div>
    </div>
    ${note}
    <div class="mt"><button class="btn block" data-action="nc:copy-txid" data-text="${esc(t.txid || t.id)}">Copy reference</button></div>
    <div class="mt"><button class="btn primary moon block" data-action="nc:to-activity">View activity</button></div>
  </div>`;
}

function ncSendView() {
  const s = state.nc.send;
  if (s.stage === 'review' && s.built) return ncSendReview();
  if (s.stage === 'done') return ncReceipt();
  return ncSendForm();
}

function ncActivity() {
  const txs = ncStateObj.txs;
  if (!txs.length) {
    return `<div class="nc-card"><div class="nc-empty">No transfers yet.<br>Send NIGHT, ADA or BTC from the Send tab.</div></div>`;
  }
  const rows = txs.map((t) => `
    <div class="nc-tx ${t.status === 'broadcast' ? 'live' : 'sealed'}">
      <div class="grow">
        <div class="nc-tx-head"><b>${esc(t.asset)}</b><span class="nc-tx-pill ${t.status === 'broadcast' ? 'live' : 'sealed'}">${t.status === 'broadcast' ? 'Broadcast' : (t.status === 'sealed' ? 'Sealed' : 'Signed')}</span></div>
        <div class="muted small">${esc(t.amountText)} · to <span class="mono">${esc(t.to)}</span></div>
      </div>
      <div class="nc-tx-side">
        <div class="nc-when">${ncTime(t.ts)}</div>
        ${t.explorer ? `<a class="btn sm" href="${esc(t.explorer)}" target="_blank" rel="noopener" title="View on explorer">↗</a>` : ''}
      </div>
    </div>`).join('');
  return `<div class="nc-card">${rows}</div>`;
}

function viewNocturne() {
  let body;
  if (!ncStateObj) body = ncOnboarding();
  else if (state.nc.tab === 'chats') body = state.nc.convoId ? ncThread() : ncChatList();
  else if (state.nc.tab === 'mail') body = state.nc.composing ? ncCompose() : (state.nc.mailId ? ncMailRead() : ncMailList());
  else if (state.nc.tab === 'send') body = ncSendView();
  else body = ncActivity();
  return `${topbar()}
  <div class="view nc-view">
    ${ncStateObj ? ncHeader() + ncTabs() : ''}
    ${body}
  </div>
  ${bottomNav()}`;
}

function viewBoot() {
  return `<div class="view"><div class="empty"><span class="spinner"></span><div style="margin-top:12px">Starting Eclipse…</div></div></div>`;
}

/* ------------------------------ render ------------------------------- */

let lastRenderedView = null;

function render() {
  const doc = dom();
  if (!doc) return;
  const root = doc.getElementById('app');
  if (!root) return;
  let html;
  switch (state.view) {
    case 'boot': html = viewBoot(); break;
    case 'onboarding': html = viewOnboarding(); break;
    case 'create': html = viewCreate(); break;
    case 'createpw': html = viewCreatePw(); break;
    case 'import': html = viewImport(); break;
    case 'unlock': html = viewUnlock(); break;
    case 'wallet': html = viewWallet(); break;
    case 'nocturne': html = viewNocturne(); break;
    case 'send': html = viewSend(); break;
    case 'signmsg': html = viewSignMsg(); break;
    case 'dapps': html = viewDapps(); break;
    case 'settings': html = viewSettings(); break;
    case 'txdone': html = viewTxDone(); break;
    default: html = viewBoot();
  }
  root.innerHTML = html;
  // Animate only when the view actually changes (not on every state re-render).
  const vEl = root.querySelector('.view');
  if (vEl) vEl.classList.toggle('anim', state.view !== lastRenderedView);
  lastRenderedView = state.view;
  // Keep Nocturne threads scrolled to the newest message.
  if (state.view === 'nocturne') {
    const m = root.querySelector('#nc-msgs');
    if (m) m.scrollTop = m.scrollHeight;
  }
  // Re-focus the first password field on auth screens.
  if (['unlock', 'createpw', 'import'].includes(state.view)) {
    const pw = root.querySelector('input[type="password"]');
    if (pw) { try { pw.focus(); } catch { /* ignore */ } }
  }
}

function go(view) {
  state.view = view;
  state.formError = null;
  render();
}

/* ------------------------------ actions ------------------------------ */

async function actOnboard(kind) {
  state.f = { password: '', password2: '', mnemonic: '' };
  if (kind === 'create') {
    state.mnemonic = generateMnemonic(256);
    go('create');
  } else {
    go('import');
  }
}

async function actCreateCopy() {
  await copyText(state.mnemonic || '');
}

async function actCreatePwGo() {
  const pw = state.f.password || '';
  if (pw.length < 8) { state.formError = 'Password must be at least 8 characters'; render(); return; }
  if (pw !== state.f.password2) { state.formError = 'Passwords do not match'; render(); return; }
  state.busy = true; state.formError = null; render();
  try {
    await paint();
    await createVaultFromMnemonic(state.mnemonic, pw);
    state.mnemonic = null;
    state.f = { password: '', password2: '', to: '', amount: '', tier: 'halfHour' };
    go('wallet');
    toast('Wallet created — keys are encrypted on this device');
    loadBalance('cardano');
    loadBalance('bitcoin');
    loadBalance('midnight');
  } catch (e) {
    state.formError = e.message;
    render();
  } finally {
    state.busy = false;
    render();
  }
}

async function actImportGo() {
  state.busy = true; state.formError = null; render();
  try {
    await paint();
    await importWallet(state.f.password || '', state.f.password2 || '');
    state.mnemonic = null;
    state.f = { password: '', password2: '', to: '', amount: '', tier: 'halfHour' };
    go('wallet');
    toast('Wallet imported');
    loadBalance('cardano');
    loadBalance('bitcoin');
    loadBalance('midnight');
  } catch (e) {
    state.formError = e.message;
    render();
  } finally {
    state.busy = false;
    render();
  }
}

async function actUnlockGo() {
  state.busy = true; state.formError = null; render();
  try {
    await paint();
    await unlockVault(state.f.password || '');
    state.f.password = '';
    go('wallet');
    toast('Unlocked');
    loadBalance(state.chain);
    refreshPrices().then((d) => { if (d) render(); });
  } catch (e) {
    state.formError = e.message || 'Wrong password';
    render();
  } finally {
    state.busy = false;
    render();
  }
}

async function actLock() {
  lockWallet();
  state.f.password = '';
  go('unlock');
}

async function actChain(chain) {
  state.chain = chain;
  state.f.to = ''; state.f.amount = '';
  state.send = null;
  state.formError = null;
  render();
  loadBalance(chain);
  refreshPrices().then((d) => { if (d) render(); });
}

async function actRefresh() {
  loadBalance(state.chain);
  refreshPrices(true).then((d) => { if (d) render(); });
}

async function actReceive() {
  openQrModal(addressFor(state.chain));
}

async function actCopy(dataset) {
  await copyText(dataset.text || '');
}

async function actSend() {
  const chain = state.chain;
  if (chain === 'midnight') { toast('Midnight v1: sending is not available yet', 'err'); return; }
  state.f.to = ''; state.f.amount = ''; state.f.tier = 'halfHour';
  state.send = { chain, stage: 'form' };
  state.formError = null;
  go('send');
}

async function actMax() {
  const m = maxAmountFor(state.chain);
  if (m == null) { toast('Load the balance first (Refresh)', 'err'); return; }
  state.f.amount = m;
  render();
}

async function actSendReview() {
  const s = state.send;
  if (!s) return;
  state.formError = null; state.busy = true; render();
  try {
    await paint();
    if (s.chain === 'cardano') {
      const out = await reviewCardanoSend(state.f.to, state.f.amount);
      Object.assign(s, out, { stage: 'review' });
      s.amountLovelace = parseAda(state.f.amount);
    } else {
      const out = await reviewBitcoinSend(state.f.to, state.f.amount, state.f.tier);
      Object.assign(s, out, { stage: 'review' });
      s.amountSats = parseBtc(state.f.amount);
    }
  } catch (e) {
    state.formError = e.message;
  } finally {
    state.busy = false;
    render();
  }
}

async function actSendConfirm(dataset) {
  const s = state.send;
  if (!s || s.stage !== 'review') return;
  const title = `Sign ${CHAIN[s.chain].name} transaction`;
  const body = s.chain === 'cardano'
    ? `Send ${formatAda(s.amountLovelace)} for ${formatAda(s.built.fee)} fee. Enter your password to sign.`
    : `Send ${formatBtc(s.amountSats)} for ${s.built.feeSats} sats fee. Enter your password to sign.`;
  openPasswordModal(title, body, async (pw) => {
    if (!pw) throw new Error('Password required');
    state.busy = true;
    try {
      await paint();
      let txid;
      if (s.chain === 'cardano') txid = await cardanoSignAndBroadcast(s.built);
      else txid = await bitcoinSignAndBroadcast(s.built);
      state.txDone = { chain: s.chain, txid };
      state.send = { chain: s.chain, stage: 'done' };
      go('txdone');
      toast('Broadcast OK');
    } finally {
      state.busy = false;
      render();
    }
  }, 'Sign & broadcast');
}

async function actTxDone() {
  state.txDone = null;
  state.send = null;
  go('wallet');
  loadBalance(state.chain);
}

async function actSignMsgGo() {
  const chain = state.signChain;
  const msg = state.f.signmsgtext || '';
  if (!msg.trim()) { state.formError = 'Enter a message to sign'; render(); return; }
  state.formError = null;
  openPasswordModal(
    `Sign ${CHAIN[chain].name} message`,
    `${CHAIN[chain].name} key will sign ${msg.length} characters. Enter your password.`,
    async (pw) => {
      if (!pw) throw new Error('Password required');
      state.busy = true;
      try {
        await paint();
        state.signResult = signChainMessage(chain, msg);
        render();
        toast('Signed');
      } finally {
        state.busy = false;
        render();
      }
    },
    'Sign'
  );
}

async function actDappApprove(dataset) {
  const req = state.pending.find((r) => r.id === dataset.id);
  if (!req) { toast('Request no longer pending', 'err'); return; }
  if (!seedBytes) {
    openPasswordModal(
      'Unlock to approve',
      'This dApp request needs your keys. Enter your password to unlock, then approve again.',
      async (pw) => { if (!pw) throw new Error('Password required'); await unlockVault(pw || ''); toast('Unlocked — approve the request now'); },
      'Unlock'
    );
    return;
  }
  const remember = !!(dom()?.querySelector?.(`input[data-remember="${dataset.id}"]`)?.checked);
  try {
    const result = computeDappResult(req);
    await dappDecide(req, true, result, remember);
    toast('Approved');
    if (state.view !== 'dapps') render();
  } catch (e) {
    toast(e.message, 'err');
  }
}

async function actDappReject(dataset) {
  const req = state.pending.find((r) => r.id === dataset.id);
  if (!req) { toast('Request no longer pending', 'err'); return; }
  await dappDecide(req, false, null, false);
  toast('Rejected');
  if (state.view !== 'dapps') render();
}

async function actDappClear(dataset) {
  await dappq.clearApproval(store, dataset.origin);
  state.approvals = await dappq.getApprovals(store);
  if (state.view === 'dapps') render();
  toast('Origin forgotten');
}

async function actSettingsNetwork(chain) {
  const id = state.f['net:' + chain];
  if (!id || !CHAIN[chain].networks[id]) return;
  state.networks[chain] = id;
  await store.set({ [NETWORKS_KEY]: state.networks });
  state.balances = {};
  toast(`${CHAIN[chain].name} network: ${CHAIN[chain].networks[id].label}`);
  if (state.view === 'wallet') { render(); loadBalance(state.chain); }
}

async function actWipe() {
  openConfirmModal(
    'Wipe Eclipse from this device?',
    'This deletes the encrypted vault and your Nocturne messenger data. Anyone with your recovery phrase can still restore the wallet — no one without it. This cannot be undone.',
    async () => {
      openPasswordModal('Confirm wipe', 'Enter your password to permanently delete the vault on this device.',
        async (pw) => {
          if (!pw) throw new Error('Password required');
          try { await vaultDecrypt(vaultFromStorage((await store.get([VAULT_KEY]))[VAULT_KEY]), pw); } catch { throw new Error('Wrong password'); }
          await store.remove([VAULT_KEY, 'eclipse.dapp.pending', 'eclipse.dapp.approvals', nocturne.STORAGE_KEY]);
          lockWallet();
          state.pending = [];
          state.approvals = {};
          updateBadge();
          go('onboarding');
          toast('Eclipse wiped from this device');
        }, 'Wipe device',
      );
    }, 'Continue', true
  );
}

/* --------------------------- Nocturne actions ------------------------- */

async function actNcOpen() {
  if (!seedBytes) { go('unlock'); return; }
  if (!state.nc) state.nc = ncDefaultUI();
  state.view = 'nocturne';
  if (!ncStateObj) {
    state.busy = true;
    state.formError = null;
    state.ncLoadError = false;
    render();
    try {
      await ncEnsure();
    } catch (e) {
      ncStateObj = null;
      state.ncLoadError = true;
      state.formError = 'The sealed messenger store could not be opened (wrong seed or tampered data). You can start fresh below.';
    } finally {
      state.busy = false;
    }
  }
  render();
  ncStartTicker();
}

async function actNcReset() {
  openPasswordModal(
    'Reset Nocturne on this device?',
    'Deletes the sealed messenger store (chats, mail, activity) from this browser. Enter your wallet password to confirm.',
    async (pw) => {
      if (!pw) throw new Error('Password required');
      await vaultDecrypt(vaultFromStorage((await store.get([VAULT_KEY]))[VAULT_KEY]), pw);
      await store.remove([nocturne.STORAGE_KEY]);
      ncStateObj = null;
      ncKey = null;
      state.nc = ncDefaultUI();
      state.ncLoadError = false;
      state.formError = null;
      toast('Nocturne store reset');
    }, 'Reset'
  );
}

async function actNcClear() {
  openConfirmModal(
    'Clear Nocturne from this device?',
    'Deletes the sealed messenger store: chats, mail, activity. This cannot be undone.',
    async () => {
      openPasswordModal(
        'Confirm clear',
        'Enter your wallet password to delete the Nocturne store on this device.',
        async (pw) => {
          if (!pw) throw new Error('Password required');
          await vaultDecrypt(vaultFromStorage((await store.get([VAULT_KEY]))[VAULT_KEY]), pw);
          await store.remove([nocturne.STORAGE_KEY]);
          ncStateObj = null;
          ncKey = null;
          state.nc = ncDefaultUI();
          state.formError = null;
          toast('Nocturne cleared from this device');
        }, 'Clear'
      );
    }, 'Continue', true
  );
}

async function actNcCreate() {
  if (!state.nc) state.nc = ncDefaultUI();
  const handle = ncF('handle').trim();
  if (!nocturne.validHandle(handle)) {
    state.formError = 'Handle: 3–24 lowercase letters, numbers or underscores';
    render(); return;
  }
  state.busy = true; state.formError = null; render();
  try {
    const seed = requireUnlocked();
    if (!ncKey) ncKey = await nocturne.deriveDeviceKey(seed);
    ncStateObj = nocturne.newState(handle.toLowerCase());
    state.nc = { ...ncDefaultUI(), tab: state.nc.tab };
    state.f['nc.handle'] = '';
    await ncSave();
    toast('Welcome to the dark, @' + handle.toLowerCase());
  } catch (e) {
    state.formError = e.message || String(e);
  } finally {
    state.busy = false;
    render();
    ncStartTicker();
  }
}

async function actNcSub(dataset) {
  if (!state.nc) return;
  state.nc.tab = dataset.tab;
  state.nc.convoId = null;
  state.nc.mailId = null;
  state.nc.composing = false;
  state.nc.newChatOpen = false;
  if (state.nc.send) {
    state.nc.send.stage = 'form';
    state.nc.send.built = null;
    state.nc.send.receipt = null;
  }
  state.formError = null;
  render();
}

async function actNcOpenConvo(dataset) {
  if (!ncConvo(dataset.id)) return;
  state.nc.convoId = dataset.id;
  state.formError = null;
  render();
}

async function actNcBack() {
  state.nc.convoId = null;
  state.f['nc.msg'] = '';
  render();
}

async function actNcNewChatOpen() {
  state.nc.newChatOpen = true;
  state.formError = null;
  render();
}

async function actNcNewChatCancel() {
  state.nc.newChatOpen = false;
  state.f['nc.newhandle'] = '';
  state.formError = null;
  render();
}

async function actNcNewChatGo() {
  const h = ncF('newhandle').trim().replace(/^@/, '');
  state.formError = null;
  try {
    const c = nocturne.addConvo(ncStateObj, h);
    state.nc.convoId = c.id;
    state.nc.newChatOpen = false;
    state.f['nc.newhandle'] = '';
    await ncSave();
  } catch (e) {
    state.formError = e.message || String(e);
  }
  render();
}

async function actNcMsgSend() {
  const text = ncF('msg').trim();
  const c = state.nc && ncConvo(state.nc.convoId);
  if (!text || !c) return;
  const now = Date.now();
  c.msgs.push({ id: nocturne.uid(), from: 'me', text, ts: now, status: 'sent' });
  c.lastActive = now;
  nocturne.scheduleReply(c, now);
  state.f['nc.msg'] = '';
  await ncSave();
  ncSettleTick();
  if (state.view === 'nocturne') render();
}

async function actNcMailtab(dataset) {
  state.nc.mailTab = dataset.tab;
  state.nc.mailId = null;
  render();
}

async function actNcMailOpen(dataset) {
  const tab = state.nc.mailTab === 'sent' ? 'sent' : 'inbox';
  const m = (ncStateObj.mail[tab] || []).find((x) => x.id === dataset.id);
  if (!m) return;
  if (tab === 'inbox' && !m.read) {
    m.read = true;
    await ncSave();
  }
  state.nc.mailId = dataset.id;
  render();
}

async function actNcMailBack() {
  state.nc.mailId = null;
  render();
}

async function actNcCompose() {
  state.nc.composing = true;
  state.nc.mailId = null;
  state.formError = null;
  render();
}

async function actNcComposeCancel() {
  state.nc.composing = false;
  ['nc.mailto', 'nc.mailsubject', 'nc.mailbody'].forEach((k) => { state.f[k] = ''; });
  state.formError = null;
  render();
}

async function actNcMailSend() {
  const to = ncF('mailto').trim();
  const subject = ncF('mailsubject').trim();
  const body = ncF('mailbody').trim();
  const m = /^(.*)@nocturne\.night$/i.exec(to);
  if (!m || !nocturne.validHandle(m[1])) {
    state.formError = 'Address must be handle@nocturne.night';
    render(); return;
  }
  if (!subject || !body) {
    state.formError = 'Subject and message are required';
    render(); return;
  }
  state.formError = null;
  const now = Date.now();
  const entry = { id: nocturne.uid('m'), to, name: m[1].toLowerCase(), subject, body, ts: now, read: true };
  ncStateObj.mail.sent.unshift(entry);
  if (m[1].toLowerCase() === ncStateObj.profile.handle) {
    ncStateObj.mail.inbox.unshift({ ...entry, read: false });
  }
  state.nc.composing = false;
  state.nc.mailTab = 'sent';
  state.nc.mailId = null;
  ['nc.mailto', 'nc.mailsubject', 'nc.mailbody'].forEach((k) => { state.f[k] = ''; });
  await ncSave();
  toast('Sealed mail sent');
  render();
}

async function actNcAsset(dataset) {
  if (!state.nc || !NC_ASSETS[dataset.asset]) return;
  state.nc.send.asset = dataset.asset;
  state.nc.send.stage = 'form';
  state.nc.send.built = null;
  state.formError = null;
  render();
}

async function actNcSendBack() {
  state.nc.send = { ...state.nc.send, stage: 'form', built: null, receipt: null };
  state.formError = null;
  render();
}

async function actNcReview() {
  const s = state.nc.send;
  const a = ncAsset(s.asset);
  const addr = ncF('sendaddr').trim();
  const amt = ncF('sendamt').trim();
  state.formError = null;
  if (!addr) { state.formError = 'Enter a recipient address'; render(); return; }
  if (!amt) { state.formError = 'Enter an amount'; render(); return; }
  state.busy = true; render();
  try {
    await paint();
    if (a.chain === 'midnight') {
      const memo = ncF('sendmemo').trim();
      const out = await reviewMidnightSend(addr, amt, memo);
      Object.assign(s, out, { amountText: formatXno(out.amountMicro), stage: 'review' });
    } else if (a.chain === 'cardano') {
      const out = await reviewCardanoSend(addr, amt);
      Object.assign(s, out, { amountText: formatAda(out.amountLovelace), stage: 'review' });
    } else {
      const out = await reviewBitcoinSend(addr, amt, 'halfHour');
      Object.assign(s, out, { amountText: formatBtc(out.amountSats), stage: 'review' });
    }
    s.memo = ncF('sendmemo').trim();
  } catch (e) {
    state.formError = e.message || String(e);
  } finally {
    state.busy = false;
    render();
  }
}

async function actNcBackEdit() {
  state.nc.send.stage = 'form';
  state.nc.send.built = null;
  state.formError = null;
  render();
}

async function actNcSendQr(dataset) {
  openQrModal(dataset.text);
}

async function actNcConfirm() {
  const s = state.nc.send;
  if (s.stage !== 'review') return;
  const a = ncAsset(s.asset);
  const title = a.sealed ? 'Seal NIGHT transfer' : `Sign ${a.name} transaction`;
  const body = a.sealed
    ? `Seal ${s.amountText} to ${s.toAddress}. Enter your password to seal this record.`
    : `Send ${s.amountText}. Enter your password to sign and broadcast.`;
  openPasswordModal(title, body, async (pw) => {
    if (!pw) throw new Error('Password required');
    state.busy = true;
    try {
      await paint();
      const now = Date.now();
      let t;
      let toastMsg = 'Broadcast OK';
      if (a.chain === 'midnight') {
        const r = await midnightSignAndBroadcast(s.built, currentNetwork('midnight').id);
        t = {
          id: nocturne.uid('tx'), asset: 'NIGHT', to: s.toAddress, amountText: s.amountText, memo: s.memo, ts: now,
          status: r.status, txid: r.txid, explorer: r.explorer, signed: r.signed, nodeResponse: r.nodeResponse,
        };
        toastMsg = r.status === 'broadcast' ? 'Broadcast OK' : 'Signed — receipt sealed for the dark';
      } else if (a.chain === 'cardano') {
        const txid = await cardanoSignAndBroadcast(s.built);
        t = { id: nocturne.uid('tx'), asset: 'ADA', to: s.toAddress, amountText: s.amountText, memo: s.memo, ts: now, status: 'broadcast', txid, explorer: explorerTxLink('cardano', txid) };
      } else {
        const txid = await bitcoinSignAndBroadcast(s.built);
        t = { id: nocturne.uid('tx'), asset: 'BTC', to: s.toAddress, amountText: s.amountText, memo: s.memo, ts: now, status: 'broadcast', txid, explorer: explorerTxLink('bitcoin', txid) };
      }
      ncStateObj.txs.unshift(t);
      s.receipt = t;
      s.stage = 'done';
      ['nc.sendaddr', 'nc.sendamt', 'nc.sendmemo'].forEach((k) => { state.f[k] = ''; });
      await ncSave();
      if (a.chain === 'cardano' || a.chain === 'bitcoin') loadBalance(a.chain);
      toast(toastMsg);
    } finally {
      state.busy = false;
      render();
    }
  }, a.sealed ? 'Seal' : 'Sign & broadcast');
}

async function actNcToActivity() {
  state.nc.tab = 'activity';
  state.nc.send = { ...ncDefaultUI().send };
  render();
}

async function actNcCopyMailbox() {
  if (ncStateObj) await copyText(ncStateObj.profile.mailbox);
}

async function actNcCopyTxid(dataset) {
  await copyText(dataset.text || '');
}

/* --------------------------- event wiring ---------------------------- */

/**
 * Enter-to-confirm (Phantom-style): pressing Enter in a text/password field
 * fires the primary action — the modal OK button when a modal is open,
 * otherwise the first primary button in the current view.
 * Textareas (mnemonic paste, messages) are excluded.
 */
function onAppKeydown(e) {
  if (e.key !== 'Enter' || e.isComposing) return;
  const t = e.target;
  if (!t || t.tagName === 'TEXTAREA' || (t.tagName !== 'INPUT' && t.tagName !== 'SELECT')) return;
  if (t.type === 'checkbox' || t.type === 'radio') return;
  const overlay = document.getElementById('overlay');
  const target =
    (overlay && overlay.querySelector('[data-action="modal:ok"]')) ||
    document.querySelector('#app .btn.primary:not([disabled])');
  if (!target) return;
  e.preventDefault();
  target.click();
}

function onAppClick(e) {
  const el = e.target && e.target.closest ? e.target.closest('[data-action]') : null;
  if (!el) return;
  const action = el.dataset.action;
  const dataset = el.dataset;
  Promise.resolve(dispatch(action, dataset, el)).catch((err) => {
    state.formError = err.message || String(err);
    if (['createpw', 'import', 'unlock', 'send', 'signmsg', 'nocturne'].includes(state.view)) render();
    toast(err.message || String(err), 'err');
  });
}

function onAppChange(e) {
  const el = e.target && e.target.closest ? e.target.closest('[data-f]') : null;
  if (!el) return;
  const key = el.dataset.f;
  state.f[key] = el.value;
  if (key === 'tier' && state.send) {
    // Fee tier changed on the form stage: preview the new rate.
    const s = state.send;
    if (s.fees) s.tier = el.value;
    if (state.view === 'send' && s.stage === 'form') render();
  }
  if (key.startsWith('net:')) {
    const chain = key.slice(4);
    actSettingsNetwork(chain).catch((err) => toast(err.message, 'err'));
  }
  if (key === 'signchain') {
    state.signChain = el.value;
    state.signResult = null;
    render();
  }
}

async function dispatch(action, dataset, el) {
  switch (action) {
    case 'nav:wallet': go('wallet'); loadBalance(state.chain); return;
    case 'nav:dapps': {
      go('dapps');
      await refreshPending();
      render();
      return;
    }
    case 'nav:settings': go('settings'); return;
    case 'lock': return actLock();
    case 'onboard:create':
    case 'onboard:import': return actOnboard(action.split(':')[1]);
    case 'create:copy': return actCreateCopy();
    case 'create:ack': go('createpw'); return;
    case 'create:back': go('onboarding'); return;
    case 'createpw:go': return actCreatePwGo();
    case 'createpw:back': go('create'); return;
    case 'import:go': return actImportGo();
    case 'import:back': go('onboarding'); return;
    case 'unlock:go': return actUnlockGo();
    case 'chain': return actChain(dataset.chain);
    case 'refresh': return actRefresh();
    case 'receive': return actReceive();
    case 'copy': return actCopy(dataset);
    case 'qr': return openQrModal(dataset.text);
    case 'send': return actSend();
    case 'max': return actMax();
    case 'send:back': go('wallet'); return;
    case 'send:edit': if (state.send) { state.send.stage = 'form'; state.formError = null; render(); } return;
    case 'send:review': return actSendReview();
    case 'send:confirm': return actSendConfirm(dataset);
    case 'txdone:done': return actTxDone();
    case 'signmsg': state.signChain = state.chain; state.f.signmsgtext = state.f.signmsgtext || ''; go('signmsg'); return;
    case 'sign:back': go('wallet'); return;
    case 'sign:go': return actSignMsgGo();
    case 'dapp:approve': return actDappApprove(dataset);
    case 'dapp:reject': return actDappReject(dataset);
    case 'dapp:clear': return actDappClear(dataset);
    case 'settings:lock': return actLock();
    case 'settings:wipe': return actWipe();
    case 'nav:nocturne': return actNcOpen();
    case 'nc:reset': return actNcReset();
    case 'nc:clear': return actNcClear();
    case 'nc:create': return actNcCreate();
    case 'nc:sub': return actNcSub(dataset);
    case 'nc:open-convo': return actNcOpenConvo(dataset);
    case 'nc:back': return actNcBack();
    case 'nc:newchat-open': return actNcNewChatOpen();
    case 'nc:newchat-cancel': return actNcNewChatCancel();
    case 'nc:newchat-go': return actNcNewChatGo();
    case 'nc:msg-send': return actNcMsgSend();
    case 'nc:mailtab': return actNcMailtab(dataset);
    case 'nc:mail-open': return actNcMailOpen(dataset);
    case 'nc:mailback': return actNcMailBack();
    case 'nc:compose': return actNcCompose();
    case 'nc:compose-cancel': return actNcComposeCancel();
    case 'nc:mail-send': return actNcMailSend();
    case 'nc:asset': return actNcAsset(dataset);
    case 'nc:review': return actNcReview();
    case 'nc:back-edit': return actNcBackEdit();
    case 'nc:sendqr': return actNcSendQr(dataset);
    case 'nc:confirm': return actNcConfirm();
    case 'nc:to-activity': return actNcToActivity();
    case 'nc:copy-mailbox': return actNcCopyMailbox();
    case 'nc:copy-txid': return actNcCopyTxid(dataset);
    default:
      throw new Error('Unknown action: ' + action);
  }
}

function onOverlayClick(e) {
  const ov = e.target && e.target.closest ? e.target.closest('#overlay') : null;
  if (!ov) return;
  if (e.target === ov) { closeModal(); return; }
  const el = e.target && e.target.closest ? e.target.closest('[data-action]') : null;
  if (!el) return;
  Promise.resolve(handleModalAction(el.dataset.action, el.dataset)).catch((err) => {
    state.modalError = err.message || String(err);
    const doc = dom();
    if (doc) { const o = doc.getElementById('overlay'); if (o) o.innerHTML = modalHtml(); }
  });
}

function onAppInput(e) {
  const el = e.target && e.target.closest ? e.target.closest('[data-f]') : null;
  if (!el) return;
  state.f[el.dataset.f] = el.value;
}

/* ----------------------------- dApp bridge --------------------------- */

function onRuntimeMessage(msg) {
  if (!msg || typeof msg !== 'object') return;
  if (msg.type === 'eclipse_dapp_new' && msg.req) {
    refreshPending()
      .then(() => {
        toast('New dApp request — open dApps to approve', 'ok');
        updateBadge();
        if (state.view === 'dapps') render();
      })
      .catch(() => { /* ignore */ });
    return { ok: true };
  }
  if (msg.type === 'eclipse_dapp_hello') {
    refreshPending().catch(() => { /* ignore */ });
    return { ok: true };
  }
}

/* -------------------------------- init ------------------------------- */

async function init() {
  const doc = dom();
  if (!doc) return; // Node / test environment

  doc.addEventListener('click', onAppClick);
  doc.addEventListener('change', onAppChange);
  doc.addEventListener('input', onAppInput);
  doc.addEventListener('click', onOverlayClick);
  doc.addEventListener('keydown', onAppKeydown);

  // Restore settings + dApp state.
  try {
    const o = await store.get([VAULT_KEY, NETWORKS_KEY]);
    state.hasVault = !!o[VAULT_KEY];
    if (o[NETWORKS_KEY] && typeof o[NETWORKS_KEY] === 'object') {
      state.networks = { ...DEFAULT_NETWORKS, ...o[NETWORKS_KEY] };
    }
  } catch { /* storage unavailable — proceed with defaults */ }

  await refreshPending();

  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      const res = onRuntimeMessage(msg);
      if (res !== undefined && typeof sendResponse === 'function') sendResponse(res);
    });
  }
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ type: 'eclipse_dapp_hello' }, () => { /* wake worker */ });
    }
  } catch { /* worker may be asleep */ }

  state.view = state.hasVault ? 'unlock' : 'onboarding';
  render();
}

// Run in browsers only; harmless no-op under Node.
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { init().catch((e) => toast(e.message, 'err')); });
  } else {
    init().catch((e) => { if (typeof console !== 'undefined') console.error(e); });
  }
}

/* ====================== exports (for smoke tests) ===================== */

export const api = {
  state,
  store,
  createVaultFromMnemonic,
  importWallet,
  unlockVault,
  lockWallet,
  keysFor,
  addressFor,
  currentNetwork,
  signChainMessage,
  reviewCardanoSend,
  reviewBitcoinSend,
  cardanoSignAndBroadcast,
  bitcoinSignAndBroadcast,
  reviewMidnightSend,
  midnightSignAndBroadcast,
  computeDappResult,
  refreshPending,
  dappDecide,
  parseAda,
  parseBtc,
  maxAmountFor,
  refreshPrices,
  priceState: () => prices,
  balanceHero,
  fmtUsd,
  setNetworks(n) { state.networks = { ...state.networks, ...n }; },

  /* Nocturne (sealed private messenger) */
  nocturne,
  ncEnsure,
  ncSave,
  ncSettleTick,
  ncState: () => ncStateObj,
  actNcOpen,
  actNcCreate,
  actNcSub,
  actNcOpenConvo,
  actNcNewChatGo,
  actNcMsgSend,
  actNcMailSend,
  actNcReview,
  actNcConfirm,
};
