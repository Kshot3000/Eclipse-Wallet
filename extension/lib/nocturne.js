/**
 * Eclipse Wallet — Nocturne core (private messenger on Midnight).
 *
 * Nocturne is the in-wallet private messenger: encrypted DMs, a sealed
 * personal mailbox (you@nocturne.night) and "quiet rails" for NIGHT/ADA/BTC.
 * It is the Eclipse-wallet edition of the standalone Nocturne site
 * (https://kshot3000.github.io/nocturne/) — same idea, stronger backing:
 * ADA and BTC sends settle through the wallet's real chain pipelines.
 *
 * Security model:
 *  - A 256-bit AES-GCM device key is derived deterministically from the
 *    wallet seed (SHA-256(seed || "nocturne/v1")). No new secret to manage —
 *    the vault password already protects the seed.
 *  - All messenger state (chats, mail, activity) is sealed (AES-256-GCM)
 *    before it is written to chrome.storage.local.
 *  - Nothing here is a network path: messages and mail are local, sealed
 *    records. "Residents" are seeded demo contacts (labelled as such in the
 *    UI), exactly like the standalone Nocturne site.
 *
 * The module is pure (no DOM, no chrome) and Node-compatible so the test
 * suites can exercise it offline.
 */
import { concatBytes, utf8ToBytes } from './bytes.js';
import { sha256 } from '../vendor/hashes/sha2.js';

/** chrome.storage.local key for the sealed Nocturne blob. */
export const STORAGE_KEY = 'eclipse.nocturne.v1';

/** Mailbox domain — same as the standalone Nocturne site. */
export const DOMAIN = 'nocturne.night';

/* ------------------------- seeded residents -------------------------- */
/* Carried over from the Nocturne site (kshot3000.github.io/nocturne).
   They are demo contacts with canned replies — labelled as demo in the UI. */

export const RESIDENTS = [
  {
    id: 'nocturne',
    handle: 'nocturne',
    name: 'Nocturne Concierge',
    system: true,
    online: true,
    color: '#c9d4ea',
    welcome:
      'Welcome to the quiet side of Cardano, {handle}. I am the concierge — ask me about your mailbox, sending NIGHT/ADA/BTC, or how the encryption works.',
    replies: [
      'Noted. Everything you store here is sealed with AES-256-GCM before it touches this browser\u2019s storage.',
      'Tip: open the Send tab to move NIGHT, ADA or BTC. The QR in the review step is real and scannable.',
      'Your mailbox is {handle}@nocturne.night. Mail you send lands in the Sent folder.',
      'Remember: Nocturne has no server. When this storage clears, the dark takes it back.',
      'Ask me again if you like \u2014 I never sleep, which is the point of the name.',
      'Midnight tip: programmable privacy \u2014 everything stays shielded, and only what\u2019s necessary gets disclosed, when it\u2019s necessary.'
    ]
  },
  {
    id: 'moon_whisper',
    handle: 'moon_whisper',
    name: 'Moon Whisper',
    online: true,
    color: '#c9d4ea',
    welcome:
      'You found the quiet channel, {handle}. Moonlight travels fast; gossip doesn\u2019t. What\u2019s on your mind?',
    replies: [
      'The moon doesn\u2019t send receipts. But I can see you read that.',
      'I was just watching Midnight\u2019s ledger breathe \u2014 public state up top, private state under the blanket. It hums in B-flat, if you squint.',
      'Keep your keys like a lullaby \u2014 only you should know the words.',
      'I once forwarded a secret to a satellite. It bounced. Poetic, no?',
      'The dark isn\u2019t empty, {handle}. It\u2019s just listening.',
      'Send me your NIGHT and I\u2019ll pretend it was always mine. (Demo \u2014 nothing actually moves.)'
    ]
  },
  {
    id: 'ada_dev',
    handle: 'ada_dev',
    name: 'Ada Dev',
    online: true,
    color: '#98a1b8',
    welcome:
      '{handle}! I ship Cardano stuff by day and lurk Midnight channels by night. P2P, Plutus, or just moon talk?',
    replies: [
      'Ha \u2014 \u201cprivacy by default, drama by exception.\u201d I could tattoo that.',
      'If Nocturne ever gets a relay, I\u2019m volunteering as the human load-balancer.',
      'My ADA address is in my bio. My secrets are in Nocturne. That\u2019s the whole philosophy.',
      'In Eclipse your ADA sends are real \u2014 the quiet rails settle through the actual chain pipeline.',
      'Ship it. Then whisper about it. Then let the blocks settle.',
      '0x42, but make it midnight.'
    ]
  },
  {
    id: 'btc_ghost',
    handle: 'btc_ghost',
    name: 'BTC Ghost',
    online: false,
    color: '#98a1b8',
    welcome:
      '*static* \u2026you… talk to a ghost, {handle}? …fine. I lurk here. BTC forever. Midnight sometimes.',
    replies: [
      'Not much to say. Satoshis don\u2019t whisper. They settle.',
      'I heard Midnight discloses only what\u2019s necessary, when it\u2019s necessary. In 2010 we called that \u201ca cold wallet in a bunker.\u201d',
      'My last message was 2016. I keep it as an artifact.',
      'Eclipse broadcasts real BTC \u2014 BIP143, verified. Even ghosts respect a well-signed witness stack.',
      '…',
      '*ghost appears to have left the dark*'
    ]
  }
];

/** Generic replies for chats the user starts with new handles. */
export const GENERIC_REPLIES = [
  'Heard you over the quiet line. (This is a demo resident \u2014 no one is really there, which is rather the point.)',
  'Signal received. I will pretend to be someone important. (Demo mode.)',
  'Even ghosts need a \u201ctyping…\u201d indicator. (Demo mode.)'
];

/** Welcome mail seeded into a new mailbox. */
export const WELCOME_MAIL = [
  {
    from: 'welcome@nocturne.night',
    name: 'Nocturne',
    subject: 'Welcome to the quiet side of Cardano',
    body:
      'Your private mailbox {handle}@nocturne.night is live.\n\n' +
      'This inbox lives only in this browser, sealed with AES-256-GCM ' +
      '(WebCrypto, right on your machine) before anything is written to storage, ' +
      'and there is no server holding a copy.\n\n' +
      'What you can do here:\n' +
      '\u2022 Chat with residents in the Chats tab\n' +
      '\u2022 Write mail to anyone at @nocturne.night (Sent keeps your copies)\n' +
      '\u2022 Send Midnight (NIGHT), Cardano (ADA) or Bitcoin (BTC) from the Send tab\n\n' +
      'ADA and BTC sends settle through Eclipse\u2019s real chain pipelines. ' +
      'NIGHT sends are sealed now and broadcast when Midnight mainnet support lands.\n\n' +
      'Cardano by day. Nocturne by night.\n' +
      '\u2014 The Nocturne Concierge'
  },
  {
    from: 'midnight@nocturne.night',
    name: 'Midnight Desk',
    subject: 'Programmable privacy',
    body:
      'Midnight is the fourth-generation blockchain of the Cardano ecosystem, ' +
      'built to bring rational privacy to blockchain: zero-knowledge proofs shield ' +
      'sensitive data, and programmable privacy decides exactly what gets ' +
      'disclosed \u2014 and when. NIGHT continuously generates DUST, the resource ' +
      'that powers transactions, so costs stay predictable.\n\n' +
      'Nocturne is what a conversation feels like at \u201cprivate\u201d: messages sealed ' +
      'end-to-end, a mailbox with no landlord, and money rails that don\u2019t announce ' +
      'themselves.\n\n' +
      'Nothing in this mailbox has ever left your device. That is not a feature ' +
      'we added \u2014 it is a feature we refused to remove.'
  },
  {
    from: 'treasury@nocturne.night',
    name: 'Nocturne Treasury',
    subject: 'Your keys, your coins',
    body:
      'A note before you send anything:\n\n' +
      'The Send tab validates recipient addresses per-chain (NIGHT, ADA, BTC) and ' +
      'renders a real, scannable QR of the recipient.\n\n' +
      '\u2022 ADA and BTC: signed with your key and broadcast \u2014 real transactions, ' +
      'real explorer links.\n' +
      '\u2022 NIGHT: sealed and recorded now; broadcasting arrives with Midnight ' +
      'mainnet support (v1 is address + message signing).\n\n' +
      'Keep the lights low.'
  }
];

/* ------------------------------ helpers ------------------------------ */

function getSubtle() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) throw new Error('WebCrypto is not available');
  return c.subtle;
}

function bytesToB64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return globalThis.btoa(bin);
}

function b64ToBytes(b64) {
  const bin = globalThis.atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function uid(prefix = 'n') {
  return prefix + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

/** Handle rules: 3–24 lowercase letters, numbers or underscores. */
export function validHandle(handle) {
  return /^[a-z0-9_]{3,24}$/.test(String(handle || '').trim().toLowerCase());
}

/* ------------------------------ crypto ------------------------------- */

/**
 * Derive the Nocturne device key (AES-256-GCM) from the wallet seed.
 * Deterministic: the same seed always yields the same key; a different
 * seed cannot open the sealed state.
 */
export function deriveDeviceKey(seed) {
  if (!(seed instanceof Uint8Array) || seed.length < 16) {
    throw new Error('Nocturne needs an unlocked wallet seed');
  }
  const raw = sha256(concatBytes(seed, utf8ToBytes('nocturne/v1')));
  return getSubtle().importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** Seal arbitrary JSON-able state with the device key. */
export async function sealState(key, obj) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = await getSubtle().encrypt(
    { name: 'AES-GCM', iv }, key, utf8ToBytes(JSON.stringify(obj))
  );
  return { v: 1, mode: 'aes-256-gcm', iv: bytesToB64(iv), ct: bytesToB64(new Uint8Array(ct)) };
}

/** Open a sealed state. Throws on wrong key or tampering. */
export async function openState(sealed, key) {
  if (!sealed || sealed.mode !== 'aes-256-gcm') throw new Error('Unsupported Nocturne store');
  const pt = await getSubtle().decrypt(
    { name: 'AES-GCM', iv: b64ToBytes(sealed.iv) }, key, b64ToBytes(sealed.ct)
  );
  return JSON.parse(new TextDecoder().decode(pt));
}

/* --------------------------- state shaping --------------------------- */

/** Fresh Nocturne state for a new identity (seeded residents + welcome mail). */
export function newState(handle, now = Date.now()) {
  if (!validHandle(handle)) throw new Error('Invalid Nocturne handle');
  const h = String(handle).trim().toLowerCase();
  return {
    v: 1,
    profile: { handle: h, mailbox: h + '@' + DOMAIN, createdAt: now },
    convos: RESIDENTS.map((c, i) => ({
      id: c.id,
      handle: c.handle,
      name: c.name,
      color: c.color,
      system: !!c.system,
      online: !!c.online,
      userMade: false,
      silent: false,
      replies: (c.replies || []).slice(),
      _ri: 0,
      msgs: c.welcome
        ? [{ id: uid(), from: 'them', text: c.welcome.replace('{handle}', h), ts: now - 1000 * 60 * 12 * (RESIDENTS.length - i), status: 'read' }]
        : [],
      lastActive: now - 1000 * 60 * 12 * (RESIDENTS.length - i)
    })),
    mail: {
      inbox: WELCOME_MAIL.map((m, i) => ({
        id: uid(),
        from: m.from,
        name: m.name,
        subject: m.subject,
        body: m.body.replace(/\{handle\}/g, h),
        ts: now - 1000 * 60 * 9 * (WELCOME_MAIL.length - i),
        read: false
      })),
      sent: []
    },
    txs: []
  };
}

/**
 * Next canned reply for a convo (advances the internal pointer).
 * User-made convos go silent after their first reply — like the standalone
 * Nocturne site, a new handle answers once and then just listens.
 */
export function pickReply(convo, generic = GENERIC_REPLIES) {
  const lines = convo.replies && convo.replies.length ? convo.replies : generic;
  const line = lines[(convo._ri || 0) % lines.length];
  convo._ri = (convo._ri || 0) + 1;
  if (convo.userMade && convo._ri >= 1) convo.silent = true;
  return line;
}

/**
 * Schedule the next reply for a convo (advances the canned-reply pointer
 * now, so the rotation is deterministic even if the popup closes before
 * the reply lands). User-made convos that already replied once are silent.
 * Returns true if a reply was scheduled.
 */
export function scheduleReply(convo, now = Date.now(), delayMs) {
  if (convo.silent) return false;
  if (convo.incoming) return false; // one reply in flight per convo
  const text = pickReply(convo);
  const d = typeof delayMs === 'number' ? Math.max(400, delayMs) : 2100 + Math.round(Math.random() * 1600);
  const typingAt = now + 900;
  convo.incoming = { text, typingAt, at: Math.max(now + d, typingAt + 400) };
  return true;
}

/**
 * Deterministic "settle": advance time-based state (delivered ticks, typing
 * indicator, scheduled replies) up to `now`. Pure with respect to `now`, so
 * it is safe to call on every load and render — including after the popup
 * was closed and timers never ran. Returns true if anything changed.
 */
export function settle(state, now = Date.now()) {
  let changed = false;
  for (const c of state.convos) {
    const gotReplyAfter = (ts) => c.msgs.some((m) => m.from === 'them' && m.ts > ts);
    for (const m of c.msgs) {
      if (m.from === 'me' && m.status === 'sent' && now - m.ts > 600) {
        m.status = gotReplyAfter(m.ts) ? 'read' : 'delivered';
        changed = true;
      }
    }
    const inc = c.incoming;
    if (!inc) {
      if (c.typing) { c.typing = false; changed = true; }
      continue;
    }
    if (now >= inc.at) {
      c.msgs.push({ id: uid(), from: 'them', text: inc.text, ts: inc.at, status: 'read' });
      for (const m of c.msgs) {
        if (m.from === 'me' && m.status !== 'read') { m.status = 'read'; changed = true; }
      }
      c.incoming = null;
      c.typing = false;
      c.lastActive = inc.at;
      changed = true;
    } else {
      const typing = now >= inc.typingAt;
      if (c.typing !== typing) { c.typing = typing; changed = true; }
    }
  }
  return changed;
}

/** Create a user-initiated convo for a handle (idempotent per handle). */
export function addConvo(state, handle, now = Date.now()) {
  const h = String(handle || '').trim().toLowerCase().replace(/^@/, '');
  if (!validHandle(h)) throw new Error('Handle: 3\u201324 letters, numbers or underscores');
  let c = state.convos.find((x) => x.handle === h);
  if (!c) {
    const palette = ['#c9d4ea', '#98a1b8', '#c9d4ea', '#c9d4ea'];
    c = {
      id: uid('c'),
      handle: h,
      name: h,
      color: palette[Math.floor(Math.random() * palette.length)],
      system: false,
      online: Math.random() > 0.4,
      userMade: true,
      silent: false,
      replies: GENERIC_REPLIES.slice(),
      _ri: 0,
      msgs: [],
      lastActive: now
    };
    state.convos.push(c);
  }
  return c;
}
